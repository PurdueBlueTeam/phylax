package link

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

var (
	// ErrQueueFull is returned by TrySend when the priority's queue is at its bound.
	ErrQueueFull = errors.New("link: send queue full")
	// ErrClosed is returned once the session has ended.
	ErrClosed = errors.New("link: session closed")
	// ErrOverload ends a session whose handler fell too far behind.
	ErrOverload = errors.New("link: inbound handler queue overflow")
	// ErrUnexpected ends a session on a message type not valid for its role.
	ErrUnexpected = errors.New("link: unexpected message type for role")
)

// QueueLimit bounds one priority's send queue.
type QueueLimit struct {
	Msgs  int
	Bytes int
}

// Options configure a Session.
type Options struct {
	Role Role
	// Handler receives every inbound message except ack (consumed by the
	// session). It runs off the read loop on two goroutines: one for Control and
	// Heartbeat messages, one for the rest, so a slow handler cannot delay
	// control. It must be safe to call from both and should return promptly
	// once ctx is cancelled. A non-nil error ends the session.
	Handler func(ctx context.Context, m Message) error
	// AckFunc, if set, makes the session answer every received heartbeat with
	// an ack carrying its value (the controller's highest contiguous stored
	// sequence for this host). This doubles as the controller-to-agent keepalive.
	AckFunc func() uint64
	// Queues overrides per-priority send bounds.
	Queues [NumPriorities]QueueLimit
	// ReadIdle is the longest a whole frame may take to arrive (default 20 s;
	// negative disables). Agents heartbeat every 5 s, so a quiet link is dead.
	ReadIdle time.Duration
	// WriteTimeout bounds each frame write (default 10 s).
	WriteTimeout time.Duration
	// BulkRate limits PrioBulk throughput in bytes/second (0 = unlimited).
	BulkRate int
	// InboundQueue bounds each handler queue (default 256).
	InboundQueue int
}

func (o *Options) defaults() {
	def := [NumPriorities]QueueLimit{
		{1024, 4 << 20}, {256, 8 << 20}, {64, 8 << 20}, {64, 8 << 20}, {64, 8 << 20}, {8, 4 << 20},
	}
	for i := range o.Queues {
		if o.Queues[i].Msgs <= 0 {
			o.Queues[i].Msgs = def[i].Msgs
		}
		if o.Queues[i].Bytes <= 0 {
			o.Queues[i].Bytes = def[i].Bytes
		}
	}
	if o.ReadIdle == 0 {
		o.ReadIdle = 20 * time.Second
	}
	if o.WriteTimeout <= 0 {
		o.WriteTimeout = 10 * time.Second
	}
	if o.InboundQueue <= 0 {
		o.InboundQueue = 256
	}
}

type item struct {
	t        Type
	body     []byte
	compress bool
}

// Session runs the message protocol over one established connection.
type Session struct {
	conn net.Conn
	o    Options

	mu      sync.Mutex
	q       [NumPriorities][]item
	qbytes  [NumPriorities]int
	space   chan struct{} // closed and replaced whenever room appears
	wake    chan struct{} // writer wakeup, capacity 1
	acked   uint64
	ackSeen bool
	ackCh   chan struct{} // closed and replaced on every ack

	done    chan struct{}
	errOnce sync.Once
	err     error

	bucket tokenBucket
}

// NewSession wraps conn. Call Run to start it.
func NewSession(conn net.Conn, o Options) *Session {
	o.defaults()
	s := &Session{conn: conn, o: o,
		space: make(chan struct{}), wake: make(chan struct{}, 1), ackCh: make(chan struct{}),
		done: make(chan struct{})}
	s.bucket = newTokenBucket(o.BulkRate)
	return s
}

// Done is closed when the session ends; Err then reports why.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err returns the reason the session ended (nil while running).
func (s *Session) Err() error {
	select {
	case <-s.done:
		return s.err
	default:
		return nil
	}
}

func (s *Session) fail(err error) {
	s.errOnce.Do(func() {
		s.err = err
		close(s.done)
		s.conn.Close()
	})
}

// Close ends the session.
func (s *Session) Close() { s.fail(ErrClosed) }

// Acked returns the highest event sequence the peer has acknowledged and
// whether any ack has arrived yet.
func (s *Session) Acked() (seq uint64, seen bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acked, s.ackSeen
}

// AckChanged returns a channel that is closed on the next ack received.
func (s *Session) AckChanged() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ackCh
}

// WaitFirstAck blocks until the peer's first ack arrives (it tells the agent
// where to resume) and returns its sequence.
func (s *Session) WaitFirstAck(ctx context.Context) (uint64, error) {
	for {
		s.mu.Lock()
		seq, seen, ch := s.acked, s.ackSeen, s.ackCh
		s.mu.Unlock()
		if seen {
			return seq, nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-s.done:
			return 0, s.err
		}
	}
}

func (s *Session) onAck(seq uint64) {
	s.mu.Lock()
	if !s.ackSeen || seq > s.acked {
		s.acked = seq
	}
	s.ackSeen = true
	close(s.ackCh)
	s.ackCh = make(chan struct{})
	s.mu.Unlock()
}

func (s *Session) fits(p Priority, n int) bool {
	l := s.o.Queues[p]
	return len(s.q[p]) == 0 || (len(s.q[p]) < l.Msgs && s.qbytes[p]+n <= l.Bytes)
}

func (s *Session) enqueueLocked(p Priority, it item) {
	if it.t == TypeHeartbeat { // a newer heartbeat supersedes any queued one
		kept := s.q[p][:0]
		for _, o := range s.q[p] {
			if o.t == TypeHeartbeat {
				s.qbytes[p] -= len(o.body)
				continue
			}
			kept = append(kept, o)
		}
		s.q[p] = kept
	}
	s.q[p] = append(s.q[p], it)
	s.qbytes[p] += len(it.body)
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Session) prepare(p Priority, m Message) (item, error) {
	if p >= NumPriorities {
		return item{}, fmt.Errorf("link: bad priority %d", p)
	}
	t, body, err := Marshal(m)
	if err != nil {
		return item{}, err
	}
	if len(body) >= MaxFrame {
		return item{}, ErrFrameTooLarge
	}
	return item{t: t, body: body, compress: compressible(t)}, nil
}

// TrySend queues m at priority p, or returns ErrQueueFull without blocking.
func (s *Session) TrySend(p Priority, m Message) error {
	it, err := s.prepare(p, m)
	if err != nil {
		return err
	}
	select {
	case <-s.done:
		return ErrClosed
	default:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.fits(p, len(it.body)) {
		return ErrQueueFull
	}
	s.enqueueLocked(p, it)
	return nil
}

// Send queues m at priority p, blocking (backpressure) while that priority's
// queue is full, until ctx ends or the session closes.
func (s *Session) Send(ctx context.Context, p Priority, m Message) error {
	it, err := s.prepare(p, m)
	if err != nil {
		return err
	}
	for {
		s.mu.Lock()
		if s.fits(p, len(it.body)) {
			s.enqueueLocked(p, it)
			s.mu.Unlock()
			return nil
		}
		ch := s.space
		s.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		case <-s.done:
			return ErrClosed
		}
	}
}

// pop returns the next item in strict priority order. It reports a wait time
// when only rate-limited bulk is pending.
func (s *Session) pop() (it item, ok bool, wait time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for p := Priority(0); p < NumPriorities; p++ {
		if len(s.q[p]) == 0 {
			continue
		}
		head := s.q[p][0]
		if p == PrioBulk {
			if w := s.bucket.reserve(len(head.body) + 5); w > 0 {
				return item{}, false, w
			}
		}
		s.q[p][0] = item{}
		s.q[p] = s.q[p][1:]
		if len(s.q[p]) == 0 {
			s.q[p] = nil
		}
		s.qbytes[p] -= len(head.body)
		close(s.space)
		s.space = make(chan struct{})
		return head, true, 0
	}
	return item{}, false, 0
}

func (s *Session) writeLoop() {
	fw := NewFrameWriter(s.conn)
	var timer *time.Timer
	for {
		it, ok, wait := s.pop()
		if ok {
			s.conn.SetWriteDeadline(time.Now().Add(s.o.WriteTimeout))
			if err := fw.WriteFrame(it.t, it.body, it.compress); err != nil {
				s.fail(fmt.Errorf("link: write: %w", err))
				return
			}
			continue
		}
		var tc <-chan time.Time
		if wait > 0 {
			if timer == nil {
				timer = time.NewTimer(wait)
			} else {
				timer.Reset(wait)
			}
			tc = timer.C
		}
		select {
		case <-s.wake:
		case <-tc:
		case <-s.done:
			return
		}
		if timer != nil && !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

func (s *Session) readLoop(ctx context.Context, urgent, normal chan<- Message) {
	fr := NewFrameReader(s.conn)
	defer fr.Close()
	allowed := inbound[s.o.Role]
	for {
		if s.o.ReadIdle > 0 {
			s.conn.SetReadDeadline(time.Now().Add(s.o.ReadIdle))
		}
		t, body, err := fr.ReadFrame()
		if err != nil {
			s.fail(fmt.Errorf("link: read: %w", err))
			return
		}
		if !allowed[t] {
			if newMessage(t) == nil {
				s.fail(fmt.Errorf("%w: 0x%02x", ErrUnknownType, byte(t)))
			} else {
				s.fail(fmt.Errorf("%w: %s", ErrUnexpected, t))
			}
			return
		}
		m, err := Unmarshal(t, body)
		if err != nil {
			s.fail(err)
			return
		}
		switch v := m.(type) {
		case *Ack:
			s.onAck(v.Seq)
			continue
		case *Heartbeat:
			if s.o.AckFunc != nil {
				s.TrySend(PrioCritical, &Ack{Seq: s.o.AckFunc()}) // full queue: a newer ack follows
			}
		}
		q := normal
		if t == TypeControl || t == TypeHeartbeat {
			q = urgent
		}
		select {
		case q <- m:
		default:
			s.fail(ErrOverload)
			return
		}
	}
}

func (s *Session) work(ctx context.Context, in <-chan Message) {
	for {
		select {
		case m := <-in:
			if s.o.Handler == nil {
				continue
			}
			if err := s.o.Handler(ctx, m); err != nil {
				s.fail(fmt.Errorf("link: handler: %w", err))
				return
			}
		case <-s.done:
			return
		}
	}
}

// Run drives the session until it ends, the context is cancelled or the
// connection fails. It always closes the connection and returns the cause.
func (s *Session) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	urgent := make(chan Message, s.o.InboundQueue)
	normal := make(chan Message, s.o.InboundQueue)
	var wg sync.WaitGroup
	// Handler goroutines are not waited for: a stuck handler must not keep the
	// session (and its connection slot) alive. They see ctx cancelled and exit
	// as soon as the handler returns.
	for _, ch := range []chan Message{urgent, normal} {
		go s.work(ctx, ch)
	}
	wg.Add(2)
	go func() { defer wg.Done(); s.writeLoop() }()
	go func() { defer wg.Done(); s.readLoop(ctx, urgent, normal) }()
	select {
	case <-ctx.Done():
		s.fail(ctx.Err())
	case <-s.done:
	}
	cancel()
	wg.Wait()
	return s.err
}

// tokenBucket is a simple byte-rate limiter; rate 0 disables it.
type tokenBucket struct {
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newTokenBucket(rate int) tokenBucket {
	b := float64(2 * ChunkSize)
	if float64(rate) > b {
		b = float64(rate)
	}
	return tokenBucket{rate: float64(rate), burst: b, tokens: b, last: time.Now()}
}

// reserve takes n tokens if available, else returns how long to wait.
// Callers hold the session lock.
func (b *tokenBucket) reserve(n int) time.Duration {
	if b.rate <= 0 {
		return 0
	}
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
	need := float64(n)
	if need > b.burst {
		need = b.burst
	}
	if b.tokens >= need {
		b.tokens -= need
		return 0
	}
	return time.Duration((need - b.tokens) / b.rate * float64(time.Second))
}
