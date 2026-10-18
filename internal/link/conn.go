package link

import (
	"context"
	"errors"
	"io"
	"sync"
)

// Priority order (docs/protocol.md § Priority): lower value is sent first.
const (
	PrioCore      = 0 // heartbeats, alerts, acks
	PrioSteps     = 1 // plan steps and step results
	PrioEvidence  = 2 // evidence attached to alerts
	PrioData      = 3 // transactions and flows
	PrioTelemetry = 4
	PrioBulk      = 5 // pcap slices, files, binaries
)

// ErrClosed is returned by operations on a closed Conn.
var ErrClosed = errors.New("link: conn closed")

// Handler processes one received message. Returning an error closes the
// connection with that error.
type Handler func(ctx context.Context, c *Conn, m *Message) error

// Conn is a framed, priority-ordered protocol connection over a
// ReadWriteCloser (the TLS session). One sender goroutine drains the
// priority queues; one receiver loop dispatches to handlers.
type Conn struct {
	rwc  io.ReadWriteCloser
	peer string // peer address for logging
	queues  [6][]*Message
	mu      sync.Mutex
	cond    *sync.Cond
	closing bool

	handlerMu sync.RWMutex
	handlers  map[byte]Handler

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	done   chan struct{}
	doneMu sync.Once
}

// NewConn wraps rwc. The background sender and receiver start immediately.
func NewConn(rwc io.ReadWriteCloser, peer string) *Conn {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Conn{
		rwc:      rwc,
		peer:     peer,
		handlers: map[byte]Handler{},
		ctx:      ctx,
		cancel:   cancel,
		done:     make(chan struct{}),
	}
	c.cond = sync.NewCond(&c.mu)
	c.wg.Add(2)
	go c.sendLoop()
	go c.recvLoop()
	return c
}

// On registers the handler for a message type.
func (c *Conn) On(typ byte, h Handler) {
	c.handlerMu.Lock()
	c.handlers[typ] = h
	c.handlerMu.Unlock()
}

// Enqueue queues a message for sending at the given priority.
func (c *Conn) Enqueue(prio int, m *Message) error {
	if prio < PrioCore || prio > PrioBulk {
		return errors.New("link: bad priority")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing {
		return ErrClosed
	}
	c.queues[prio] = append(c.queues[prio], m)
	c.cond.Signal()
	return nil
}

func (c *Conn) sendLoop() {
	defer c.wg.Done()
	for {
		c.mu.Lock()
		var m *Message
		for p := PrioCore; p <= PrioBulk && m == nil; p++ {
			if q := c.queues[p]; len(q) > 0 {
				m = q[0]
				c.queues[p] = q[1:]
			}
		}
		if m == nil {
			if c.closing {
				c.mu.Unlock()
				return
			}
			c.cond.Wait()
			c.mu.Unlock()
			continue
		}
		c.mu.Unlock()
		if err := NewWriter(c.rwc).Write(m); err != nil {
			c.die()
			return
		}
	}
}

func (c *Conn) recvLoop() {
	defer c.wg.Done()
	rd := NewReader(c.rwc)
	for {
		m, err := rd.Read()
		if err != nil {
			c.die()
			return
		}
		c.handlerMu.RLock()
		h := c.handlers[m.Type]
		c.handlerMu.RUnlock()
		if h == nil {
			continue // unknown type: drop
		}
		if err := h(c.ctx, c, m); err != nil {
			c.die()
			return
		}
	}
}

// Close shuts the connection down.
func (c *Conn) Close() error {
	c.die()
	err := c.rwc.Close()
	c.waitGone()
	return err
}

func (c *Conn) die() {
	c.doneMu.Do(func() { close(c.done) })
	c.cancel()
	c.mu.Lock()
	c.closing = true
	c.cond.Broadcast()
	c.mu.Unlock()
}

// waitGone waits for both loops to exit.
func (c *Conn) waitGone() { c.wg.Wait() }

// Done is closed when the connection dies (cleanly or not).
func (c *Conn) Done() <-chan struct{} { return c.done }

// Peer is the peer address, for logs.
func (c *Conn) Peer() string { return c.peer }
