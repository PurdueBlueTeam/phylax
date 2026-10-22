package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/spool"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// ctl is a controller running on a fixed loopback address, restartable on the same data dir.
type ctl struct {
	t    *testing.T
	cfg  Config
	addr string
	c    *Controller
	stop context.CancelFunc
	done chan error
}

func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func (x *ctl) start() {
	x.t.Helper()
	c, err := New(context.Background(), x.cfg, Options{HostKnown: func(h string) bool { return h != "ghost" }})
	if err != nil {
		x.t.Fatal(err)
	}
	var ln net.Listener
	for i := 0; i < 50; i++ {
		if ln, err = net.Listen("tcp", x.addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		x.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	x.c, x.stop, x.done = c, cancel, make(chan error, 1)
	go func() { x.done <- c.Serve(ctx, ln) }()
}

func (x *ctl) shutdown() {
	x.t.Helper()
	x.stop()
	select {
	case err := <-x.done:
		if err != nil {
			x.t.Errorf("serve: %v", err)
		}
	case <-time.After(30 * time.Second):
		x.t.Fatal("controller did not shut down")
	}
	if err := x.c.Close(); err != nil {
		x.t.Error(err)
	}
}

func newCtl(t *testing.T) *ctl {
	cfg := Config{AgentListen: "127.0.0.1:0", DataDir: filepath.Join(t.TempDir(), "data"), SilenceThreshold: Duration(300 * time.Millisecond)}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	x := &ctl{t: t, cfg: cfg, addr: freeAddr(t)}
	x.start()
	t.Cleanup(func() {
		select {
		case <-x.done: // already shut down
		default:
			x.shutdown()
		}
	})
	return x
}

type spoolSource struct{ sp *spool.Spool }

func (s spoolSource) Events(after uint64, max int) ([]event.Event, error) {
	return s.sp.ResendFrom(after+1, max)
}

// agent is an in-process agent: spool + link client with reconnect.
type agent struct {
	t        *testing.T
	host     string
	id       *link.Identity
	sp       *spool.Spool
	ctl      *ctl
	pin      link.Pin
	token    string
	mu       sync.Mutex
	cur      *link.Session
	conns    atomic.Int64
	welcomed atomic.Bool
}

func (a *agent) kill() {
	a.mu.Lock()
	s := a.cur
	a.mu.Unlock()
	if s != nil {
		s.Close()
	}
}

func (a *agent) run(ctx context.Context) {
	bo := link.Backoff{Min: 10 * time.Millisecond, Max: 100 * time.Millisecond}
	for ctx.Err() == nil {
		a.once(ctx)
		select {
		case <-time.After(bo.Next()):
		case <-ctx.Done():
		}
	}
}

func (a *agent) once(ctx context.Context) {
	dctx, dcancel := context.WithTimeout(ctx, 2*time.Second)
	conn, err := link.Dial(dctx, a.ctl.addr, link.DialOptions{Identity: a.id, ServerPin: a.pin, ALPN: link.ALPNAgent})
	dcancel()
	if err != nil {
		return
	}
	sess := link.NewSession(conn, link.Options{Role: link.RoleAgent, Handler: func(_ context.Context, m link.Message) error {
		if _, ok := m.(*link.Welcome); ok {
			a.welcomed.Store(true)
		}
		return nil
	}})
	a.mu.Lock()
	a.cur = sess
	a.mu.Unlock()
	a.conns.Add(1)
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go sess.Run(rctx)
	a.sp.Rewind()
	head, _ := a.sp.Head()
	tok := a.token
	if a.welcomed.Load() {
		tok = ""
	}
	sess.Send(rctx, link.PrioCritical, &link.Hello{Proto: 1, Host: a.host, Version: "test", LastSeq: head, Token: tok})
	up := &link.Uplink{Session: sess, Source: spoolSource{a.sp}, Poll: 10 * time.Millisecond}
	go up.Run(rctx)
	go func() {
		tk := time.NewTicker(50 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-tk.C:
				h, _ := a.sp.Head()
				sess.TrySend(link.PrioCritical, &link.Heartbeat{Seq: h, HostClock: time.Now().Add(2 * time.Second), SpoolDepth: 1, Congestion: "ok"})
			case <-sess.Done():
				return
			case <-rctx.Done():
				return
			}
		}
	}()
	go func() {
		for {
			ch := sess.AckChanged()
			if seq, ok := sess.Acked(); ok {
				a.sp.Ack(seq)
			}
			select {
			case <-ch:
			case <-sess.Done():
				return
			case <-rctx.Done():
				return
			}
		}
	}()
	select {
	case <-sess.Done():
	case <-rctx.Done():
	}
}

func newAgent(t *testing.T, x *ctl, host, token string) *agent {
	id, err := link.GenerateIdentity(host)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := spool.Open(filepath.Join(t.TempDir(), "spool"), spool.Options{Agent: host, MaxBytes: 2 << 20, SegmentBytes: 128 << 10})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sp.Close() })
	return &agent{t: t, host: host, id: id, sp: sp, ctl: x, pin: x.c.Pin(), token: token}
}

// tryHello connects, says hello, and reports whether a welcome arrived.
func tryHello(t *testing.T, x *ctl, id *link.Identity, host, token string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := link.Dial(ctx, x.addr, link.DialOptions{Identity: id, ServerPin: x.c.Pin(), ALPN: link.ALPNAgent})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	got := make(chan struct{}, 1)
	sess := link.NewSession(conn, link.Options{Role: link.RoleAgent, Handler: func(_ context.Context, m link.Message) error {
		if _, ok := m.(*link.Welcome); ok {
			got <- struct{}{}
		}
		return nil
	}})
	go sess.Run(ctx)
	defer sess.Close()
	sess.Send(ctx, link.PrioCritical, &link.Hello{Proto: 1, Host: host, Version: "t", Token: token})
	select {
	case <-got:
		return true
	case <-sess.Done():
		return false
	case <-time.After(30 * time.Second):
		t.Fatal("neither welcome nor close")
		return false
	}
}

func hasAlert(c *Controller, host, kind string) bool {
	for _, a := range c.Alerts() {
		if a.Host == host && a.Kind == kind {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, d time.Duration, what string, f func() bool) {
	t.Helper()
	// d is the expected latency; a slow -race CI runner gets a generous floor.
	d = max(d, 30*time.Second)
	dl := time.Now().Add(d)
	for time.Now().Before(dl) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestEndToEnd(t *testing.T) {
	x := newCtl(t)
	tok, err := x.c.MintToken("h1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.c.MintToken("ghost", 0); !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("mint for host outside manifest: %v", err)
	}
	a := newAgent(t, x, "h1", tok)

	// Phase 1: with the link down, flood the spool with fat bulk events until
	// it sheds, so a spool.gap record is produced.
	expected := map[uint64]string{} // seq -> hash of every event the spool accepted
	var emu sync.Mutex
	appendEv := func(i int, prio event.Priority, pad int) {
		ev, err := a.sp.Append(event.Event{Kind: "test.ev", Priority: prio,
			Fields: map[string]any{"i": i, "pad": strings.Repeat("x", pad)}})
		if err != nil {
			if errors.Is(err, spool.ErrShed) || errors.Is(err, spool.ErrFull) {
				return
			}
			t.Errorf("append: %v", err)
			return
		}
		emu.Lock()
		expected[ev.Seq] = ev.Hash
		emu.Unlock()
	}
	for i := 0; i < 2000; i++ {
		appendEv(i, event.PriorityBulk, 2000)
	}
	if a.sp.Stats().Shed == 0 {
		t.Fatal("expected the flood to shed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	var agentDone sync.WaitGroup
	agentDone.Add(1)
	go func() { defer agentDone.Done(); a.run(ctx) }()

	// Phase 2: stream mixed-priority events (batches overtake each other),
	// killing the link several times, restarting the controller once.
	const n = 6000
	prod := make(chan struct{})
	go func() {
		defer close(prod)
		for i := 0; i < n; i++ {
			appendEv(i, event.Priority(i%4), 20+(i%7)*50)
			if i%100 == 0 {
				time.Sleep(20 * time.Millisecond)
			}
		}
		appendEv(n, event.PriorityCritical, 0) // final event flushes any pending gap record
	}()
	kills := 0
	restarted := false
	prodDone := false
	lastConns := int64(0)
	for !(prodDone && restarted) {
		select {
		case <-prod:
			prodDone = true
			prod = nil
		case <-time.After(80 * time.Millisecond):
		}
		if c := a.conns.Load(); c > lastConns && a.welcomed.Load() { // a fresh, established link
			switch {
			case kills < 6:
				a.kill()
				kills++
				lastConns = c
			case !restarted:
				x.shutdown()
				x.start()
				restarted = true
				lastConns = c
			}
		}
	}

	waitFor(t, 40*time.Second, "store to catch up", func() bool {
		head, _ := a.sp.Head()
		ag, err := x.c.Store().Agent(context.Background(), "h1")
		return err == nil && head > 0 && ag.LastSeq == head
	})
	cancel()
	agentDone.Wait()
	if a.conns.Load() < 8 {
		t.Errorf("expected many reconnects, got %d", a.conns.Load())
	}

	// Verify: every accepted event exactly once with a verified chain.
	st := x.c.Store()
	ag, _ := st.Agent(context.Background(), "h1")
	var all []event.Event
	var after uint64
	for {
		b, err := st.Events(context.Background(), store.Query{Agent: "h1", AfterSeq: after, Limit: 5000})
		if err != nil {
			t.Fatal(err)
		}
		if len(b) == 0 {
			break
		}
		all = append(all, b...)
		after = b[len(b)-1].Seq
	}
	prevSeq, prevHash := uint64(0), ""
	seen := map[uint64]bool{}
	gaps := 0
	for _, e := range all {
		if seen[e.Seq] {
			t.Fatalf("seq %d stored twice", e.Seq)
		}
		seen[e.Seq] = true
		if e.PrevHash != prevHash || e.Seq <= prevSeq {
			t.Fatalf("chain break at seq %d", e.Seq)
		}
		if h, _ := e.ComputeHash(); h != e.Hash {
			t.Fatalf("bad hash at seq %d", e.Seq)
		}
		if e.Kind == store.KindGap {
			gaps++
			prevSeq, prevHash = e.Seq, e.Hash
			continue
		}
		if want, ok := expected[e.Seq]; !ok || want != e.Hash {
			t.Fatalf("unexpected or altered event %d", e.Seq)
		}
		prevSeq, prevHash = e.Seq, e.Hash
	}
	if len(all)-gaps != len(expected) {
		t.Fatalf("stored %d events, agent accepted %d", len(all)-gaps, len(expected))
	}
	if gaps == 0 {
		t.Fatal("no gap record stored")
	}
	if g, _ := st.Gaps(context.Background(), "h1"); len(g) == 0 {
		t.Fatal("store recorded no gap")
	}
	if len(expected) < 5000 {
		t.Fatalf("only %d events streamed", len(expected))
	}
	t.Logf("events=%d gaps=%d reconnects=%d lastSeq=%d", len(expected), gaps, a.conns.Load(), ag.LastSeq)
	if s, ok := x.c.AgentStatus("h1"); !ok || s.Acked != ag.LastSeq {
		t.Errorf("status %+v", s)
	}
}

func TestEnrollmentRefusals(t *testing.T) {
	x := newCtl(t)
	id := func() *link.Identity { i, _ := link.GenerateIdentity("a"); return i }

	if tryHello(t, x, id(), "h2", "") {
		t.Fatal("unknown key without token was admitted")
	}
	if tryHello(t, x, id(), "h2", "NOTAREALTOKEN") {
		t.Fatal("bogus token admitted")
	}
	tok, _ := x.c.MintToken("h2", 0)
	if tryHello(t, x, id(), "other", tok) {
		t.Fatal("token for h2 enrolled host other")
	}
	if hasAlert(x.c, "other", "enroll.refused") == false {
		t.Error("no alert for wrong-host token")
	}
	// The wrong-host claim did not burn the token.
	k1 := id()
	if !tryHello(t, x, k1, "h2", tok) {
		t.Fatal("valid token refused")
	}
	// Idempotent retry with the same key succeeds (even without the token).
	if !tryHello(t, x, k1, "h2", tok) || !tryHello(t, x, k1, "h2", "") {
		t.Fatal("re-hello of enrolled key refused")
	}
	// Reused token with another key: refused.
	if tryHello(t, x, id(), "h2", tok) {
		t.Fatal("reused token admitted a second key")
	}
	if !hasAlert(x.c, "h2", "enroll.key_mismatch") {
		t.Error("no alert for a new key claiming an existing host")
	}
	// A token alone cannot re-key an enrolled host, and a key cannot enroll as a second host.
	tok2, _ := x.c.MintToken("h3", 0)
	if tryHello(t, x, k1, "h3", tok2) {
		t.Fatal("enrolled key enrolled as a second host")
	}
	// Restart: enrollment and token state persist.
	x.shutdown()
	x.start()
	if !tryHello(t, x, k1, "h2", "") {
		t.Fatal("enrolled agent refused after restart")
	}
	if tryHello(t, x, id(), "h2", tok) {
		t.Fatal("reused token admitted after restart")
	}
	ag, err := x.c.Store().Agent(context.Background(), "h2")
	if err != nil || ag.ID != "h2" {
		t.Fatalf("agent row: %v", err)
	}
}

func TestSilenceAndClockSkew(t *testing.T) {
	x := newCtl(t)
	tok, _ := x.c.MintToken("h4", 0)
	a := newAgent(t, x, "h4", tok)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); a.run(ctx) }()
	waitFor(t, 5*time.Second, "heartbeat", func() bool {
		s, ok := x.c.AgentStatus("h4")
		return ok && s.Connected && s.Congestion == "ok"
	})
	s, _ := x.c.AgentStatus("h4")
	if s.ClockSkew < time.Second || s.ClockSkew > 3*time.Second {
		t.Errorf("skew %v, want about 2s", s.ClockSkew)
	}
	cancel()
	wg.Wait()
	waitFor(t, 5*time.Second, "silence alert", func() bool { return hasAlert(x.c, "h4", "agent.silent") })
}

// A hostile agent sending a bad chain must produce an alert, keep the good
// prefix, and not take the controller down.
func TestChainErrorAlerts(t *testing.T) {
	x := newCtl(t)
	tok, _ := x.c.MintToken("h5", 0)
	id, _ := link.GenerateIdentity("h5")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := link.Dial(ctx, x.addr, link.DialOptions{Identity: id, ServerPin: x.c.Pin(), ALPN: link.ALPNAgent})
	if err != nil {
		t.Fatal(err)
	}
	sess := link.NewSession(conn, link.Options{Role: link.RoleAgent})
	go sess.Run(ctx)
	sess.Send(ctx, link.PrioCritical, &link.Hello{Proto: 1, Host: "h5", Token: tok})
	var evs []event.Event
	prev, ph := uint64(0), ""
	for i := 0; i < 5; i++ {
		e := event.Event{Agent: "h5", Time: time.Now(), Kind: "k"}
		e.Seal(prev, ph)
		prev, ph = e.Seq, e.Hash
		evs = append(evs, e)
	}
	evs[3].Hash = fmt.Sprintf("%064d", 7) // corrupt
	sess.Send(ctx, link.PrioTelemetry, &link.Events{Events: []event.Event{evs[2], evs[0], evs[1], evs[3], evs[4]}})
	waitFor(t, 5*time.Second, "chain alert", func() bool { return hasAlert(x.c, "h5", "store.chain_error") })
	ag, _ := x.c.Store().Agent(ctx, "h5")
	if ag.LastSeq != 3 {
		t.Fatalf("good prefix not kept: last_seq %d", ag.LastSeq)
	}
}
