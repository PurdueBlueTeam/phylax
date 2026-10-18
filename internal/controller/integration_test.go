package controller_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/controller"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/relay"
)

func testLog(t *testing.T, tag string) *log.Logger {
	return log.New(io.Discard, tag+" ", 0)
}

// startController runs a controller on a random loopback port.
func startController(t *testing.T, dir string) *controller.Controller {
	t.Helper()
	c, err := controller.New(dir, testLog(t, "ctl:"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Stop(); c.Store().Close() })
	go c.Run("127.0.0.1:0")
	deadline := time.Now().Add(5 * time.Second)
	for c.Addr() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if c.Addr() == nil {
		t.Fatal("controller did not start")
	}
	t.Logf("controller on %s pin %s", c.Addr(), c.Pin())
	return c
}

// startAgentAt dials addr with the pinned controller identity.
func startAgentAt(t *testing.T, addr string, pin link.Pin, host, token string) (*agent.Agent, context.CancelFunc) {
	t.Helper()
	bundle := agent.Bundle{
		Controller: addr,
		Pin:        pin,
		Host:       host,
		Token:      token,
		Roles:      []string{"capture"},
	}
	a, err := agent.New(t.TempDir(), bundle, testLog(t, "agt:"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go a.Run(ctx)
	return a, cancel
}

func startAgent(t *testing.T, c *controller.Controller, host, token string) (*agent.Agent, context.CancelFunc) {
	return startAgentAt(t, c.Addr().String(), c.Pin(), host, token)
}

// waitFor polls fn until true or the deadline.
func waitFor(t *testing.T, what string, d time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestEnrollAndEvents(t *testing.T) {
	c := startController(t, t.TempDir())
	token, err := c.IssueToken("t1", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := startAgent(t, c, "t1", token)

	waitFor(t, "enrollment", 10*time.Second, func() bool {
		h, err := c.Store().GetHost("t1")
		return err == nil && h.Status == "enrolled" && h.Pin != ""
	})
	for i := 0; i < 5; i++ {
		if err := a.Publish(fmt.Sprintf("process_start_%d", i), map[string]any{"pid": 100 + i}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "events mirrored and acked", 10*time.Second, func() bool {
		n, _ := c.Store().EventCount("t1")
		acked, _ := c.Store().Acked("t1")
		return n >= 5 && acked >= uint64(n)
	})
}

// TestControllerRestartNoLoss is the T18 local equivalent: restart the
// controller mid-stream; no lost or duplicated events.
func TestControllerRestartNoLoss(t *testing.T) {
	dir := t.TempDir()
	c1 := startController(t, dir)
	port := c1.Addr().String()
	token, _ := c1.IssueToken("t1", 5*time.Minute)
	a, _ := startAgent(t, c1, "t1", token)

	for i := 0; i < 10; i++ {
		if err := a.Publish(fmt.Sprintf("ev%d", i), map[string]any{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "first 10 mirrored", 10*time.Second, func() bool {
		n, _ := c1.Store().EventCount("t1")
		return n >= 10
	})

	// Kill the controller; the agent keeps spooling while disconnected.
	c1.Stop()
	c1.Store().Close()
	time.Sleep(500 * time.Millisecond)
	for i := 10; i < 15; i++ {
		if err := a.Publish(fmt.Sprintf("ev%d", i), map[string]any{"i": i}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Restart on the SAME port from the same state dir.
	c2, err := controller.New(dir, testLog(t, "ctl2:"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c2.Stop(); c2.Store().Close() })
	go c2.Run(port)
	deadline := time.Now().Add(5 * time.Second)
	for c2.Addr() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	waitFor(t, "reconnect + resend after restart", 60*time.Second, func() bool {
		n, _ := c2.Store().EventCount("t1")
		return n >= 15
	})
	n, _ := c2.Store().EventCount("t1")
	if n != 15 {
		t.Fatalf("events after restart = %d, want exactly 15 (no loss, no dupes)", n)
	}
}

// TestAgentKilledDark is the T21 local equivalent: agent dies, the
// controller marks the host dark within the silence threshold.
func TestAgentKilledDark(t *testing.T) {
	c := startController(t, t.TempDir())
	c.SetDarkAfter(2 * time.Second)
	token, _ := c.IssueToken("t1", 5*time.Minute)
	_, cancel := startAgent(t, c, "t1", token)

	waitFor(t, "first heartbeat", 10*time.Second, func() bool {
		h, err := c.Store().GetHost("t1")
		return err == nil && !h.LastHeartbeat.IsZero()
	})
	cancel() // agent killed

	waitFor(t, "dark marking", 20*time.Second, func() bool {
		dark, err := c.Store().HostsDarkAfter(time.Now().Add(-c.DarkAfter()))
		return err == nil && contains(dark, "t1")
	})
}

// TestRelaySplice is the T22 local equivalent: agent reaches the
// controller through a relay; the relay dies and the segment goes dark
// while local spooling continues; restarting the relay (same host, same
// identity, console-restored) restores the flow with no loss.
func TestRelaySplice(t *testing.T) {
	c := startController(t, t.TempDir())
	c.SetDarkAfter(2 * time.Second)

	relayToken, _ := c.IssueToken("r1", 5*time.Minute)
	agentToken, _ := c.IssueToken("t1", 10*time.Minute)

	relayDir := t.TempDir()
	runRelay := func(addr string) (context.CancelFunc, string) {
		r, err := relay.New(relayDir, relay.Parent{
			Address: c.Addr().String(),
			Pin:     c.Pin(),
			Host:    "r1",
			Token:   relayToken,
		}, []string{"127.0.0.1/8"}, nil, testLog(t, "rly:"))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go r.Run(ctx, addr)
		deadline := time.Now().Add(5 * time.Second)
		for r.Addr() == nil && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if r.Addr() == nil {
			t.Fatal("relay did not start")
		}
		t.Cleanup(cancel)
		return cancel, r.Addr().String()
	}
	kill1, relayAddr := runRelay("127.0.0.1:0")

	a, _ := startAgentAt(t, relayAddr, c.Pin(), "t1", agentToken)
	for i := 0; i < 6; i++ {
		if err := a.Publish(fmt.Sprintf("via_relay_%d", i), map[string]any{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "events through relay", 20*time.Second, func() bool {
		n, _ := c.Store().EventCount("t1")
		return n >= 6
	})

	// Kill the relay: segment goes dark at the controller; the agent
	// keeps spooling locally.
	spooled := func() int { return a.Spool().Count() }
	darkBefore := spooled()
	kill1()
	waitFor(t, "segment dark after relay death", 20*time.Second, func() bool {
		dark, err := c.Store().HostsDarkAfter(time.Now().Add(-c.DarkAfter()))
		return err == nil && contains(dark, "t1")
	})
	a.Publish("spooled_while_dark", map[string]any{"ok": true})
	waitFor(t, "local spooling continues", 10*time.Second, func() bool {
		return spooled() > darkBefore
	})

	// Console restore: the same relay host reboots (same identity dir,
	// pin-checked — no fresh token) and re-listens on the same address.
	kill2, addr2 := runRelay(relayAddr)
	_ = kill2
	if addr2 != relayAddr {
		t.Fatalf("restored relay on %s, want %s", addr2, relayAddr)
	}
	waitFor(t, "flow restored, no loss", 60*time.Second, func() bool {
		n, _ := c.Store().EventCount("t1")
		return n >= 7
	})
}


// TestBootstrapDownload is the T27 local equivalent (Linux leg): the
// console flow downloads the binary and bootstrap config over pinned TLS;
// a wrong pin aborts before any token is used.
func TestBootstrapDownload(t *testing.T) {
	c := startController(t, t.TempDir())
	c.SetBinary([]byte("phylax-agent-binary"))
	token, _ := c.IssueToken("t1", 5*time.Minute)
	if err := c.Store().EnrollHost("t1", "pending-pin", "pending-key", []string{"capture"}); err != nil {
		t.Fatal(err)
	}

	pinned := func(pin link.Pin) *http.Client {
		_, priv, _ := link.NewKeyPair()
		cert, _ := link.SelfSignedCert(priv, "console")
		cfg := link.ClientConfig(priv, cert, pin, nil)
		cfg.Certificates = nil // a bootstrap console presents no client cert
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: cfg,
			},
			Timeout: 10 * time.Second,
		}
	}

	// Wrong pin must fail at the TLS layer, before the token is used.
	if resp, err := pinned(link.Pin("AAAA" + c.Pin()[4:])).Get(
		"https://" + c.Addr().String() + "/phylax?host=t1&token=" + token); err == nil {
		resp.Body.Close()
		t.Fatal("wrong pin was accepted")
	}

	cl := pinned(c.Pin())
	resp, err := cl.Get("https://" + c.Addr().String() + "/phylax?host=t1&token=" + token)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "phylax-agent-binary" {
		t.Fatalf("binary = %q", b)
	}
	resp, err = cl.Get("https://" + c.Addr().String() + "/bootstrap.json?host=t1&token=" + token)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	var cfg controller.BootstrapConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Pin != c.Pin() || cfg.Host != "t1" || cfg.Token != token || cfg.Controller == "" {
		t.Fatalf("bootstrap config = %+v", cfg)
	}
}
