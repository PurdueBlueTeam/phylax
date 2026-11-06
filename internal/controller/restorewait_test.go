package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// restoredCtl builds a controller over a state-only snapshot of a controller
// that had hosts enrolled, so their rows record a restore point: the restart
// is what a restored controller sees.
func restoredCtl(t *testing.T, hosts ...string) (*ctl, map[string]*link.Identity) {
	t.Helper()
	x := newCtl(t)
	ctx := context.Background()
	ids := map[string]*link.Identity{}
	for _, h := range hosts {
		id, err := link.GenerateIdentity(h)
		if err != nil {
			t.Fatal(err)
		}
		if err := x.c.Store().EnrollAgent(ctx, h, id.Pin[:]); err != nil {
			t.Fatal(err)
		}
		// A chain with a head, so the restore records a restore point.
		var prev uint64
		var prevHash string
		for i := 0; i < 3; i++ {
			e := event.Event{Agent: h, Time: time.Now(), Kind: "test.ev", Fields: map[string]any{"i": i}}
			if err := e.Seal(prev, prevHash); err != nil {
				t.Fatal(err)
			}
			if _, err := x.c.Store().Ingest(ctx, h, []event.Event{e}); err != nil {
				t.Fatal(err)
			}
			prev, prevHash = e.Seq, e.Hash
		}
		ids[h] = id
	}
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := x.c.Store().Backup(ctx, snap, store.BackupOptions{StateOnly: true}); err != nil {
		t.Fatal(err)
	}
	x.shutdown()
	restoreCtl(t, x, snap)
	return x, ids
}

// restoreCtl restores snap into a new data dir (the identity and plan key
// follow) and starts x again on it.
func restoreCtl(t *testing.T, x *ctl, snap string) {
	t.Helper()
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "restored")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"identity.pem", "plan.key"} {
		b, err := os.ReadFile(filepath.Join(x.cfg.DataDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := store.Restore(ctx, snap, filepath.Join(dir, "phylax.db"), "controller restored")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	x.cfg.DataDir, x.cfg.IdentityPath = dir, filepath.Join(dir, "identity.pem")
	x.start()
}

// A restored controller signs nothing until every agent enrolled in the
// snapshot has reported, and an operator can release an agent by hand.
func TestSigningWaitsForAgents(t *testing.T) {
	x, ids := restoredCtl(t, "h1", "h2")
	ctx := context.Background()
	if ready, waiting := x.c.SigningReady(); ready || strings.Join(waiting, ",") != "h1,h2" {
		t.Fatalf("SigningReady() = %v %v; want false [h1 h2]", ready, waiting)
	}
	// Plan signing (a dry run's check steps) and facts are refused.
	p := plan.Plan{ID: "restore-p", Nodes: []plan.Node{{ID: "w", Action: "file.write", Target: "h1",
		Risk: plan.RiskService, Params: map[string]any{"path": "/etc/rp", "content": "x\n"}}}}
	if err := x.c.CreatePlan(ctx, p, "op"); err != nil {
		t.Fatal(err)
	}
	if _, err := x.c.DryRun(ctx, "restore-p"); err == nil || !strings.Contains(err.Error(), "restored: waiting for 2 agents") {
		t.Fatalf("dry run while waiting: %v", err)
	}
	fact := module.ControlMsg{Type: "fact", Fact: "round_clock", ID: "f1", TTL: time.Minute, Hosts: []string{"h1"}}
	if err := x.c.SendFact(ctx, "scorer", fact); err == nil || !strings.Contains(err.Error(), "restored: waiting for 2 agents") {
		t.Fatalf("fact while waiting: %v", err)
	}

	// h1's hello ends its part of the wait.
	if !tryHello(t, x, ids["h1"], "h1", "") {
		t.Fatal("h1's hello was refused")
	}
	waitFor(t, 10*time.Second, "h1 to leave the wait", func() bool {
		_, waiting := x.c.SigningReady()
		return len(waiting) == 1 && waiting[0] == "h2"
	})
	// The operator releases h2, which never came back; the release records
	// the operator and the epoch in force.
	if err := x.c.ReleaseRestoreWait(ctx, "driver", "h2"); err != nil {
		t.Fatal(err)
	}
	if ready, waiting := x.c.SigningReady(); !ready {
		t.Fatalf("still waiting for %v", waiting)
	}
	rows, err := x.c.Store().Audit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range rows {
		if r.Actor == "driver" && r.Action == "restore_wait_release" {
			found = true
			if !strings.Contains(r.Detail, "epoch 2") || !strings.Contains(r.Detail, "h2") {
				t.Fatalf("release audit detail %q", r.Detail)
			}
		}
	}
	if !found {
		t.Fatalf("no restore_wait_release audit row in %+v", rows)
	}
	// With the wait over, the dry run signs (its check step is missing here
	// because no agent session is connected, but no signing refusal).
	if _, err := x.c.DryRun(ctx, "restore-p"); err != nil && strings.Contains(err.Error(), "restored: waiting") {
		t.Fatalf("dry run after the wait: %v", err)
	}
}

// The wait survives a controller restart during it: the store's kv record is
// what a restored controller comes back to.
func TestRestoreWaitSurvivesRestart(t *testing.T) {
	x, ids := restoredCtl(t, "h1", "h2")
	x.shutdown()
	x.start()
	if ready, waiting := x.c.SigningReady(); ready || strings.Join(waiting, ",") != "h1,h2" {
		t.Fatalf("after a restart SigningReady() = %v %v; want false [h1 h2]", ready, waiting)
	}
	// ...and a hello still ends its part of it.
	if !tryHello(t, x, ids["h2"], "h2", "") {
		t.Fatal("h2's hello was refused")
	}
	waitFor(t, 10*time.Second, "h2 to leave the wait", func() bool {
		_, waiting := x.c.SigningReady()
		return len(waiting) == 1 && waiting[0] == "h1"
	})
}
