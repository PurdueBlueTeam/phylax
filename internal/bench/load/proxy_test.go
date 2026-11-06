package load

import (
	"io"
	"net"
	"testing"
	"time"
)

// echo starts a real TCP echo server and returns its address; the test closes
// every connection it accepted.
func echo(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns = append(conns, c)
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		for _, c := range conns {
			c.Close()
		}
		<-done
	})
	return ln.Addr().String()
}

func dialEcho(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func ping(t *testing.T, c net.Conn) {
	t.Helper()
	if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo %q", buf)
	}
	c.SetDeadline(time.Time{})
}

func TestProxyForwards(t *testing.T) {
	target := echo(t)
	p, err := NewProxy("127.0.0.1:0", target, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ping(t, dialEcho(t, p.Addr()))
}

func TestProxyCutClosesAndRefuses(t *testing.T) {
	target := echo(t)
	p, err := NewProxy("127.0.0.1:0", target, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	c1 := dialEcho(t, p.Addr())
	c2 := dialEcho(t, p.Addr())
	ping(t, c1)
	ping(t, c2)

	p.Cut()
	for _, c := range []net.Conn{c1, c2} {
		if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1)
		if _, err := c.Read(buf); err == nil {
			t.Fatal("open connection survived Cut")
		}
	}

	// The listener still accepts, then closes the connection.
	c3, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial during Cut: %v", err)
	}
	if err := c3.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c3.Read(make([]byte, 1)); err == nil {
		t.Fatal("a connection accepted during Cut was not closed")
	}
	c3.Close()

	p.Restore()
	ping(t, dialEcho(t, p.Addr()))
}

func TestProxyMaxConns(t *testing.T) {
	target := echo(t)
	p, err := NewProxy("127.0.0.1:0", target, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	c1 := dialEcho(t, p.Addr())
	c2 := dialEcho(t, p.Addr())
	ping(t, c1)
	ping(t, c2)

	c3 := dialEcho(t, p.Addr())
	if err := c3.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c3.Read(make([]byte, 1)); err == nil {
		t.Fatal("third connection was forwarded over maxConns")
	}
	c3.Close()

	// Closing one connection frees a slot; removal is asynchronous, so retry
	// briefly.
	c1.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		c4 := dialEcho(t, p.Addr())
		if err := c4.SetDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, err := c4.Write([]byte("ping")); err == nil {
			buf := make([]byte, 4)
			if _, err := io.ReadFull(c4, buf); err == nil && string(buf) == "ping" {
				c4.Close()
				return
			}
		}
		c4.Close()
		if time.Now().After(deadline) {
			t.Fatal("a slot was not freed after closing a connection")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestProxyCloseWaits(t *testing.T) {
	target := echo(t)
	p, err := NewProxy("127.0.0.1:0", target, 16)
	if err != nil {
		t.Fatal(err)
	}
	c := dialEcho(t, p.Addr())
	ping(t, c)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	n := len(p.conns)
	p.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d connections left after Close", n)
	}
	if _, err := net.DialTimeout("tcp", p.Addr(), time.Second); err == nil {
		t.Fatal("dial succeeded after Close")
	}
}
