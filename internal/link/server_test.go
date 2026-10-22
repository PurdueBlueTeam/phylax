package link

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestALPNDispatch(t *testing.T) {
	got := make(chan string, 8)
	mk := func(name string) Handler {
		return func(ctx context.Context, c *Conn) {
			if name != c.ALPN && !(name == "boot" && c.ALPN == "") {
				got <- "mismatch:" + name + ":" + c.ALPN
			}
			got <- name
			io.Copy(io.Discard, c)
		}
	}
	e := startServer(t, ServerOptions{
		Handlers:  map[string]Handler{ALPNAgent: mk(ALPNAgent), ALPNRelay: mk(ALPNRelay)},
		Bootstrap: mk("boot"),
	})
	for _, a := range []string{ALPNAgent, ALPNRelay} {
		c, err := e.dial(t, a)
		if err != nil {
			t.Fatal(err)
		}
		if c.Conn.ConnectionState().Version != tls.VersionTLS13 {
			t.Fatal("not TLS 1.3")
		}
		if g := <-got; g != a {
			t.Fatalf("alpn %s dispatched to %s", a, g)
		}
		c.Close()
	}
	// Splice has no handler registered: connection is closed, not served.
	c, err := e.dial(t, ALPNSplice)
	if err == nil {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("unhandled ALPN got a live connection")
		}
		c.Close()
	}
	// Bootstrap client: TLS 1.2, no client cert, no phylax ALPN.
	bc, err := tls.Dial("tcp", e.addr, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer bc.Close()
	if g := <-got; g != "boot" {
		t.Fatalf("bootstrap dispatched to %s", g)
	}
}

func TestPhylaxALPNRefusesTLS12(t *testing.T) {
	e := startServer(t, ServerOptions{Handlers: map[string]Handler{ALPNAgent: func(context.Context, *Conn) {}}})
	_, err := tls.Dial("tcp", e.addr, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12,
		NextProtos: []string{ALPNAgent}, Certificates: []tls.Certificate{e.cliID.Cert}})
	if err == nil {
		t.Fatal("phylax/agent negotiated below TLS 1.3")
	}
}

func TestWrongServerPinRejectedByClient(t *testing.T) {
	var served atomic.Int32
	e := startServer(t, ServerOptions{Handlers: map[string]Handler{ALPNAgent: func(context.Context, *Conn) { served.Add(1) }}})
	wrong, _ := GenerateIdentity("wrong")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := Dial(ctx, e.addr, DialOptions{Identity: e.cliID, ServerPin: wrong.Pin, ALPN: ALPNAgent})
	if err == nil {
		t.Fatal("dial succeeded against the wrong pinned key")
	}
	time.Sleep(100 * time.Millisecond)
	if served.Load() != 0 {
		t.Fatal("handler ran for a client that rejected the server")
	}
}

func TestWrongClientPinRejectedBeforeApplicationData(t *testing.T) {
	var served atomic.Int32
	e := startServer(t, ServerOptions{Handlers: map[string]Handler{ALPNAgent: func(ctx context.Context, c *Conn) {
		served.Add(1)
	}}})
	stranger, _ := GenerateIdentity("stranger")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// In TLS 1.3 the client may finish its handshake before the server has
	// checked the client certificate, so the client can write; the server must
	// never hand that data to a handler, and the client must see a failure.
	c, err := Dial(ctx, e.addr, DialOptions{Identity: stranger, ServerPin: e.srvID.Pin, ALPN: ALPNAgent})
	if err == nil {
		c.Write([]byte("secret application data"))
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, rerr := c.Read(make([]byte, 16))
		if rerr == nil {
			t.Fatal("unauthorised client was served")
		}
		c.Close()
	}
	time.Sleep(100 * time.Millisecond)
	if served.Load() != 0 {
		t.Fatal("handler ran for an unauthorised client")
	}
}

func TestIdleConnectionsDoNotBlockHandshakes(t *testing.T) {
	served := make(chan struct{}, 4)
	e := startServer(t, ServerOptions{
		HandshakeTimeout: 400 * time.Millisecond,
		MaxHandshakes:    8,
		Handlers:         map[string]Handler{ALPNAgent: func(ctx context.Context, c *Conn) { served <- struct{}{} }},
	})
	var idle []net.Conn
	for i := 0; i < 6; i++ { // slowloris: connect, send nothing / a partial hello
		c, err := net.Dial("tcp", e.addr)
		if err != nil {
			t.Fatal(err)
		}
		if i%2 == 1 {
			c.Write([]byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01}) // truncated TLS record
		}
		idle = append(idle, c)
	}
	defer func() {
		for _, c := range idle {
			c.Close()
		}
	}()
	start := time.Now()
	c, err := e.dial(t, ALPNAgent)
	if err != nil {
		t.Fatalf("real client blocked behind idle connections: %v", err)
	}
	defer c.Close()
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("handler not reached")
	}
	if time.Since(start) > 300*time.Millisecond {
		t.Fatalf("handshake took %v behind idle connections", time.Since(start))
	}
	// The idle connections are cut once the handshake deadline passes.
	for _, ic := range idle {
		ic.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := ic.Read(make([]byte, 1)); err == nil || isTimeout(err) {
			t.Fatalf("idle connection not closed by handshake deadline: %v", err)
		}
	}
}

func TestPendingHandshakeCapIsBounded(t *testing.T) {
	e := startServer(t, ServerOptions{
		HandshakeTimeout: 600 * time.Millisecond,
		MaxHandshakes:    2,
		Handlers:         map[string]Handler{ALPNAgent: func(ctx context.Context, c *Conn) { io.Copy(io.Discard, c) }},
	})
	var idle []net.Conn
	for i := 0; i < 2; i++ {
		c, _ := net.Dial("tcp", e.addr)
		idle = append(idle, c)
	}
	defer func() {
		for _, c := range idle {
			c.Close()
		}
	}()
	time.Sleep(100 * time.Millisecond)
	// Over the cap the server closes at once, so the handshake cannot complete.
	if c, err := e.dial(t, ALPNAgent); err == nil {
		c.Close()
		t.Fatal("handshake admitted beyond the pending-handshake cap")
	}
	// After the deadline frees the slots, service resumes.
	eventually(t, 3*time.Second, "service to resume", func() bool {
		c, err := e.dial(t, ALPNAgent)
		if err != nil {
			return false
		}
		c.Close()
		return true
	})
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
