package controller

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
)

// loopbackTwo skips a test that needs the second IPv4 loopback address on a
// host that does not have it.
func loopbackTwo(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skip("127.0.0.2 is not a usable loopback address on this host")
	}
	ln.Close()
}

type alertLog struct {
	mu sync.Mutex
	a  []Alert
}

func (l *alertLog) add(a Alert) {
	l.mu.Lock()
	l.a = append(l.a, a)
	l.mu.Unlock()
}

func (l *alertLog) reuse() []Alert {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Alert
	for _, a := range l.a {
		if a.Kind == event.KindEnrollAlert && a.Reason == event.ReasonKeyReuse {
			out = append(out, a)
		}
	}
	return out
}

// agentSessionFrom dials the controller from a loopback address with one
// agent identity. close ends it.
type agentSessionFrom struct {
	sess   *link.Session
	cancel context.CancelFunc
}

func dialAgentFrom(t *testing.T, x *ctl, id *link.Identity, ip, host, token string) *agentSessionFrom {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}, Timeout: 5 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", x.addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := link.Client(ctx, raw, link.DialOptions{Identity: id, ServerPin: x.c.Pin(), ALPN: link.ALPNAgent})
	if err != nil {
		t.Fatal(err)
	}
	rctx, rcancel := context.WithCancel(context.Background())
	sess := link.NewSession(conn, link.Options{Role: link.RoleAgent, Handler: func(context.Context, link.Message) error { return nil }})
	go sess.Run(rctx)
	if err := sess.Send(rctx, link.PrioCritical, &link.Hello{Proto: 1, Minor: link.ProtoMinor, Host: host, Version: "test", LastSeq: 0, Token: token}); err != nil {
		rcancel()
		t.Fatal(err)
	}
	a := &agentSessionFrom{sess: sess, cancel: rcancel}
	t.Cleanup(a.close)
	return a
}

func (a *agentSessionFrom) close() {
	a.cancel()
	a.sess.Close()
}

// waitSessionAddr waits until host's live session came from ip ("" means no
// live session).
func waitSessionAddr(t *testing.T, c *Controller, host, ip string) {
	t.Helper()
	waitFor(t, 30*time.Second, "session of "+host+" from "+ip, func() bool {
		c.mu.Lock()
		s, ok := c.agents[host]
		c.mu.Unlock()
		if !ok {
			return false
		}
		s.mu.Lock()
		got, live := s.sessAddr, s.sess != nil
		s.mu.Unlock()
		if ip == "" {
			return !live
		}
		return live && got == ip
	})
}

func newStolenKeyCtl(t *testing.T, alerts *alertLog) *ctl {
	t.Helper()
	return newCtlWith(t, Config{AgentListen: "127.0.0.1:0", DataDir: t.TempDir(), SilenceThreshold: Duration(10 * time.Second)},
		Options{OnAlert: alerts.add})
}

func TestSameKeyFromTwoPlacesAlerts(t *testing.T) {
	loopbackTwo(t)
	var alerts alertLog
	x := newStolenKeyCtl(t, &alerts)
	tok, err := x.c.Enroller().MintToken("h1", 0)
	if err != nil {
		t.Fatal(err)
	}
	id, err := link.GenerateIdentity("h1")
	if err != nil {
		t.Fatal(err)
	}
	first := dialAgentFrom(t, x, id, "127.0.0.1", "h1", tok)
	waitSessionAddr(t, x.c, "h1", "127.0.0.1")

	second := dialAgentFrom(t, x, id, "127.0.0.2", "h1", "")
	waitSessionAddr(t, x.c, "h1", "127.0.0.2")
	deadline := time.Now().Add(3 * time.Second)
	for len(alerts.reuse()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no enroll.alert key_reuse after a second live session from another address")
		}
		time.Sleep(5 * time.Millisecond)
	}
	got := alerts.reuse()
	if len(got) != 1 {
		t.Fatalf("%d key_reuse alerts, want 1: %+v", len(got), got)
	}
	if !strings.Contains(got[0].Detail, "127.0.0.1") || !strings.Contains(got[0].Detail, "127.0.0.2") {
		t.Fatalf("detail %q does not name both addresses", got[0].Detail)
	}

	second.close()
	waitSessionAddr(t, x.c, "h1", "")
	first.close()
	third := dialAgentFrom(t, x, id, "127.0.0.2", "h1", "")
	waitSessionAddr(t, x.c, "h1", "127.0.0.2")
	time.Sleep(50 * time.Millisecond)
	if n := len(alerts.reuse()); n != 1 {
		t.Fatalf("%d key_reuse alerts after a reconnect from the same address, want 1", n)
	}
	third.close()
}

func TestKeyReuseAlertRateLimited(t *testing.T) {
	loopbackTwo(t)
	var alerts alertLog
	x := newStolenKeyCtl(t, &alerts)
	tok, err := x.c.Enroller().MintToken("h1", 0)
	if err != nil {
		t.Fatal(err)
	}
	id, err := link.GenerateIdentity("h1")
	if err != nil {
		t.Fatal(err)
	}
	cur := dialAgentFrom(t, x, id, "127.0.0.1", "h1", tok)
	waitSessionAddr(t, x.c, "h1", "127.0.0.1")
	for i := 0; i < 5; i++ {
		ip := "127.0.0.2"
		if i%2 == 1 {
			ip = "127.0.0.1"
		}
		cur = dialAgentFrom(t, x, id, ip, "h1", "")
		waitSessionAddr(t, x.c, "h1", ip)
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(alerts.reuse()); n != 1 {
		t.Fatalf("%d key_reuse alerts while flapping, want 1", n)
	}
	cur.close()
}
