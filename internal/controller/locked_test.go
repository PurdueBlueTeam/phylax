package controller

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/store"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

// newLockedController is a controller whose vault file exists and whose
// passphrase was not entered.
func newLockedController(t *testing.T) *Controller {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	v, err := vault.Create(path, []byte("pw"), vault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	v.Lock()
	cfg := Config{AgentListen: "127.0.0.1:0", DataDir: dir, VaultPath: path}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	c, err := New(context.Background(), cfg, Options{Vault: v})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func lockedEventCount(t *testing.T, c *Controller) int {
	t.Helper()
	evs, err := c.Store().Events(context.Background(), store.Query{Agent: ControllerAgent, Kind: event.KindControllerLocked, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return len(evs)
}

func waitLockedEvents(t *testing.T, c *Controller, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for lockedEventCount(t, c) < want {
		if time.Now().After(deadline) {
			t.Fatalf("want %d controller.locked events, have %d", want, lockedEventCount(t, c))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestStartLockedEmitsCritical(t *testing.T) {
	ctx := context.Background()
	c := newLockedController(t)
	locked, since := c.Locked()
	if !locked || since.IsZero() {
		t.Fatalf("Locked() = %v since %v", locked, since)
	}
	e, err := c.Store().Latest(ctx, ControllerAgent, event.KindControllerLocked)
	if err != nil {
		t.Fatal(err)
	}
	if e.Priority != event.PriorityCritical {
		t.Fatalf("priority %v", e.Priority)
	}
	v, err := event.Decode[event.ControllerLocked](e, event.KindControllerLocked)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(v.Stopped, "deadman_confirm") || v.Since == "" {
		t.Fatalf("payload %+v", v)
	}
	rows, err := c.Store().Alerts(ctx, "open", 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.Rule == event.KindControllerLocked && r.Severity == SeverityLevel("critical") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no critical alert row for controller.locked: %+v", rows)
	}
}

func TestLockedReemitsUntilUnlock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newLockedController(t)
	fc := newFakeClock(time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC))
	c.clk, c.now = fc, fc.Now
	if n := lockedEventCount(t, c); n != 1 {
		t.Fatalf("%d events at start, want 1", n)
	}
	go c.lockedLoop(ctx)
	fc.waitOps(t, 1)
	fc.Advance(5 * time.Minute)
	waitLockedEvents(t, c, 2)
	fc.Advance(5 * time.Minute)
	waitLockedEvents(t, c, 3)

	if err := c.Unlock([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	if locked, _ := c.Locked(); locked {
		t.Fatal("still locked after Unlock")
	}
	fc.Advance(10 * time.Minute)
	time.Sleep(20 * time.Millisecond)
	if n := lockedEventCount(t, c); n != 3 {
		t.Fatalf("%d events after unlock, want 3", n)
	}
}

func TestNoVaultIsNotLocked(t *testing.T) {
	c := newTestController(t)
	if locked, _ := c.Locked(); locked {
		t.Fatal("a controller without a vault is locked")
	}
	if _, err := c.Store().Latest(context.Background(), ControllerAgent, event.KindControllerLocked); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("controller.locked without a vault: %v", err)
	}
}

func TestSnapshotWriterSkipsWhileLocked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newLockedController(t)
	dir := t.TempDir()
	c.cfg.SnapshotDirs = []string{dir}
	c.cfg.SnapshotInterval = Duration(15 * time.Minute)
	fc := newFakeClock(time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC))
	c.clk, c.now = fc, fc.Now
	go c.RunSnapshots(ctx, func() []byte { return []byte("pw") })
	fc.waitOps(t, 1)

	fc.Advance(15 * time.Minute)
	waitStatus(t, c, "skipped: locked")
	if n := countSnapshots(t, dir); n != 0 {
		t.Fatalf("%d snapshots while locked", n)
	}
	if err := c.Unlock([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	fc.Advance(15 * time.Minute)
	deadline := time.Now().Add(3 * time.Second)
	for countSnapshots(t, dir) != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("%d snapshots after unlock, want 1", countSnapshots(t, dir))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// newLockedPlanCtl is a running controller with a locked vault.
func newLockedPlanCtl(t *testing.T, opt Options) *ctl {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	v, err := vault.Create(path, []byte("pw"), vault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	v.Lock()
	opt.Vault = v
	cfg := Config{AgentListen: "127.0.0.1:0", DataDir: filepath.Join(dir, "data"),
		ManifestPath: writeManifest(t, nil), SilenceThreshold: Duration(300 * time.Millisecond)}
	return newCtlWith(t, cfg, opt)
}

func TestDeadmanStillFiresWhileLocked(t *testing.T) {
	var confirms atomic.Int32
	x := newLockedPlanCtl(t, Options{OnControlSent: func(_ string, c *link.Control) {
		if c.Kind == plan.ControlDeadmanConfirm {
			confirms.Add(1)
		}
	}})
	if locked, _ := x.c.Locked(); !locked {
		t.Fatal("controller started unlocked")
	}
	_, root := newPlanAgent(t, x, "h1")
	file := writeAgentFile(t, root, "/tmp/phylax-locked-deadman", "original")
	p := plan.Plan{ID: "locked-deadman", OnFailure: plan.StopDependents, Class: plan.ClassClick, Nodes: []plan.Node{
		{ID: "a", Action: "file.write", Target: "h1", Risk: plan.RiskService, DeadmanSec: 2,
			Params: map[string]any{"path": "/tmp/phylax-locked-deadman", "content": "changed"}},
	}}
	if err := x.c.CreatePlan(ctx, p, "driver"); err != nil {
		t.Fatal(err)
	}
	if err := x.c.approveNow(ctx, p.ID, "driver"); err != nil {
		t.Fatal(err)
	}
	if err := x.c.Apply(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 15*time.Second, "the agent's dead-man timer to roll the change back", func() bool {
		b, err := readFileString(file)
		return err == nil && b == "original"
	})
	if n := confirms.Load(); n != 0 {
		t.Fatalf("%d deadman confirms sent while locked, want 0", n)
	}
}
