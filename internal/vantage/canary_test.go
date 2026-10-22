package vantage

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func startCanary(t *testing.T, cfg CanaryConfig) (*Canary, *sink, context.CancelFunc) {
	t.Helper()
	cfg.Listen = "127.0.0.1"
	c, err := NewCanary(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := &sink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx, s.emit) }()
	select {
	case <-c.Ready():
	case err := <-done:
		t.Fatalf("canary failed to start: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("canary not ready")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("canary did not stop")
		}
	})
	return c, s, cancel
}

func TestCanaryTCPLeakAndBlocked(t *testing.T) {
	c, s, _ := startCanary(t, CanaryConfig{TCPPorts: []int{0}, UDPPorts: []int{0}})
	addrs := c.Addrs()
	tcpAddr, udpAddr := addrs[0].String(), addrs[1].String()

	out := SendCanary(context.Background(), "tcp", tcpAddr, "ubuntu-ecom", time.Second)
	if !out.Leak {
		t.Fatalf("%+v", out)
	}
	eventually(t, 2*time.Second, "tcp hit", func() bool { return len(s.kind(KindCanaryHit)) == 1 })
	h := s.kind(KindCanaryHit)[0]
	if h.Fields["host"] != "ubuntu-ecom" || h.Fields["tag_valid"] != true || h.Fields["proto"] != "tcp" || h.Fields["src"] != "127.0.0.1" {
		t.Fatalf("%+v", h.Fields)
	}
	if h.Priority != 1 { // PriorityHigh
		t.Errorf("priority %v", h.Priority)
	}

	out = SendCanary(context.Background(), "udp", udpAddr, "dc01", time.Second)
	if !out.Leak {
		t.Fatalf("udp: %+v", out)
	}
	eventually(t, 2*time.Second, "udp hit", func() bool { return len(s.kind(KindCanaryHit)) == 2 })

	// a port that policy blocks: nothing listening means "blocked as expected"
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().String()
	l.Close()
	out = SendCanary(context.Background(), "tcp", dead, "x", 500*time.Millisecond)
	if out.Leak || out.Error == "" {
		t.Fatalf("%+v", out)
	}
	if len(s.kind(KindCanaryHit)) != 2 {
		t.Error("a blocked attempt produced a hit")
	}
}

func TestCanaryUntaggedAndResolve(t *testing.T) {
	c, s, _ := startCanary(t, CanaryConfig{TCPPorts: []int{0}, ReadTimeout: 200 * time.Millisecond,
		Resolve: func(a netip.Addr) string { return "resolved-" + a.String() }})
	conn, err := net.Dial("tcp", c.Addrs()[0].String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	defer conn.Close()
	eventually(t, 2*time.Second, "untagged hit", func() bool { return len(s.kind(KindCanaryHit)) == 1 })
	f := s.kind(KindCanaryHit)[0].Fields
	if f["tag_valid"] != false || f["host"] != "resolved-127.0.0.1" {
		t.Fatalf("%+v", f)
	}
	buf := make([]byte, 16)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if n, _ := conn.Read(buf); n != 0 && strings.HasPrefix(string(buf[:n]), "ACK") {
		t.Error("an untagged connection must not be ACKed")
	}
}

func TestCanaryDedupAndRateLimit(t *testing.T) {
	fc := newFakeClock()
	c, s, _ := startCanary(t, CanaryConfig{TCPPorts: []int{0}, DedupWindow: 30 * time.Second, MaxEvents: 1, clock: fc.clock()})
	addr := c.Addrs()[0].String()
	for range 5 {
		SendCanary(context.Background(), "tcp", addr, "web1", time.Second)
	}
	eventually(t, 2*time.Second, "first hit", func() bool { return len(s.kind(KindCanaryHit)) >= 1 })
	time.Sleep(100 * time.Millisecond)
	if n := len(s.kind(KindCanaryHit)); n != 1 {
		t.Fatalf("%d events for 5 identical probes within the dedup window", n)
	}
	fc.Sleep(context.Background(), 31*time.Second)
	SendCanary(context.Background(), "tcp", addr, "web1", time.Second)
	eventually(t, 2*time.Second, "second hit", func() bool { return len(s.kind(KindCanaryHit)) == 2 })
	if got := s.kind(KindCanaryHit)[1].Fields["suppressed"]; got != 4 {
		t.Errorf("suppressed count %v, want 4", got)
	}
	// different hosts are different keys but the global limiter still bounds the rate
	for i := range 40 {
		SendCanary(context.Background(), "tcp", addr, "host-"+fmtInt(i), time.Second)
	}
	time.Sleep(200 * time.Millisecond)
	hits, dropped := c.Stats()
	if hits > 22 || dropped == 0 {
		t.Errorf("hits=%d dropped=%d: the global limiter (burst 20) did not bound the output", hits, dropped)
	}
}

func TestCanaryBindFailureAndValidation(t *testing.T) {
	if _, err := NewCanary(CanaryConfig{}); err == nil {
		t.Fatal("no ports accepted")
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	c, _ := NewCanary(CanaryConfig{Listen: "127.0.0.1", TCPPorts: []int{0, port}})
	done := make(chan error, 1)
	go func() { done <- c.Start(context.Background(), (&sink{}).emit) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a bind error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start hung after a bind failure (listeners leaked?)")
	}
}
