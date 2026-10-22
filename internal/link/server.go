package link

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Handler serves one authenticated connection. The server closes the
// connection when the handler returns. ctx is cancelled at server shutdown.
type Handler func(ctx context.Context, c *Conn)

// ServerOptions configure a Server.
type ServerOptions struct {
	Identity *Identity
	// Check authorises the peer key inside the TLS handshake for every
	// phylax/* connection. Required.
	Check PeerCheck
	// Handlers maps an ALPN id to its handler. Bootstrap serves connections
	// that negotiated no phylax protocol (ALPN "" or http/1.1).
	Handlers  map[string]Handler
	Bootstrap Handler
	// MaxHandshakes caps connections concurrently in the TLS handshake
	// (default 128); beyond it new connections are closed immediately.
	MaxHandshakes int
	// MaxConns caps all live connections (default 4096).
	MaxConns int
	// HandshakeTimeout bounds each handshake (default 5 s).
	HandshakeTimeout time.Duration
	Logger           *slog.Logger
}

// Server accepts connections and dispatches them by ALPN. The accept loop does
// no TLS work: each connection gets its own goroutine that performs the
// handshake under a deadline.
type Server struct {
	o   ServerOptions
	tls *tls.Config
	log *slog.Logger

	pending chan struct{}
	live    chan struct{}
}

func NewServer(o ServerOptions) (*Server, error) {
	if o.Identity == nil || o.Check == nil {
		return nil, errors.New("link: server needs an identity and a peer check")
	}
	if o.MaxHandshakes <= 0 {
		o.MaxHandshakes = 128
	}
	if o.MaxConns <= 0 {
		o.MaxConns = 4096
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = 5 * time.Second
	}
	lg := o.Logger
	if lg == nil {
		lg = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Server{o: o, tls: serverTLS(o.Identity, o.Check), log: lg,
		pending: make(chan struct{}, o.MaxHandshakes), live: make(chan struct{}, o.MaxConns)}, nil
}

// Serve accepts on ln until ctx is cancelled or ln fails. It closes ln and all
// live connections, and waits for handlers, before returning.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	var mu sync.Mutex
	conns := map[net.Conn]struct{}{}
	go func() {
		<-ctx.Done()
		ln.Close()
		mu.Lock()
		for c := range conns {
			c.Close()
		}
		mu.Unlock()
	}()
	defer func() { cancel(); wg.Wait() }()

	for {
		raw, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		select {
		case s.live <- struct{}{}:
		default:
			raw.Close()
			s.log.Warn("link: connection cap reached", "remote", raw.RemoteAddr())
			continue
		}
		select {
		case s.pending <- struct{}{}:
		default:
			<-s.live
			raw.Close()
			s.log.Warn("link: pending-handshake cap reached", "remote", raw.RemoteAddr())
			continue
		}
		mu.Lock()
		conns[raw] = struct{}{}
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				mu.Lock()
				delete(conns, raw)
				mu.Unlock()
				raw.Close()
				<-s.live
			}()
			s.handle(ctx, raw)
		}()
	}
}

func (s *Server) handle(ctx context.Context, raw net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("link: handler panic", "panic", r, "remote", raw.RemoteAddr())
		}
	}()
	if tc, ok := raw.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(15 * time.Second)
	}
	hctx, cancel := context.WithTimeout(ctx, s.o.HandshakeTimeout)
	tc := tls.Server(raw, s.tls)
	err := tc.HandshakeContext(hctx)
	cancel()
	<-s.pending // handshake phase over, success or not
	if err != nil {
		s.log.Debug("link: handshake failed", "remote", raw.RemoteAddr(), "err", err)
		return
	}
	c, err := newConn(tc)
	if err != nil {
		return
	}
	h := s.o.Handlers[c.ALPN]
	if c.ALPN == "" || c.ALPN == "http/1.1" {
		h = s.o.Bootstrap
	}
	if h == nil {
		s.log.Debug("link: no handler", "alpn", c.ALPN)
		return
	}
	h(ctx, c)
}
