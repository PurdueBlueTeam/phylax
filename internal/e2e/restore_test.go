package e2e

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/spool"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// numberedModule emits one test.n12 event per number it receives.
type numberedModule struct{ trig <-chan int }

func (numberedModule) Name() string { return "n12" }

func (m numberedModule) Start(ctx context.Context, emit agent.Emit) error {
	for {
		select {
		case n := <-m.trig:
			emit(event.Event{Kind: "test.n12", Priority: event.PriorityNormal, Fields: map[string]any{"n": n}})
		case <-ctx.Done():
			return nil
		}
	}
}

// restoreFromSnapshot replaces the harness controller with one restored from
// snap: a new data dir holding the snapshot, the same identity and plan key,
// listening on the same address so the agents reconnect by themselves.
func (h *harness) restoreFromSnapshot(snap string) {
	t := h.t
	t.Helper()
	h.stopController()
	dir := filepath.Join(t.TempDir(), "restored")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"identity.pem", "plan.key"} {
		b, err := os.ReadFile(filepath.Join(h.cfg.DataDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := store.Restore(context.Background(), snap, filepath.Join(dir, "phylax.db"), "controller restored")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	h.cfg.DataDir = dir
	h.cfg.IdentityPath = filepath.Join(dir, "identity.pem")
	h.startController()
}

// seqOfNumber is the sequence the numbered test event n was stored at.
func seqOfNumber(t *testing.T, h *harness, host string, n int) uint64 {
	t.Helper()
	evs, err := h.c.Store().Events(context.Background(), store.Query{Agent: host, Kind: "test.n12", Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if v, ok := e.Fields["n"].(json.Number); ok && v.String() == strconv.Itoa(n) {
			return e.Seq
		}
	}
	t.Fatalf("no stored event n=%d for %s", n, host)
	return 0
}

// waitStored waits until n numbered test events are stored for host.
func waitStored(t *testing.T, h *harness, host string, n int) {
	t.Helper()
	eventually(t, "the numbered events to be stored", 20*time.Second, func() bool {
		return storedOfKind(t, h, host, "test.n12") >= n
	})
}

func storedOfKind(t *testing.T, h *harness, host, kind string) int {
	t.Helper()
	evs, err := h.c.Store().Events(context.Background(), store.Query{Agent: host, Kind: kind, Limit: store.MaxQueryLimit})
	if err != nil {
		t.Fatal(err)
	}
	return len(evs)
}

// snapshotStateOnly writes a state-only snapshot of the live store.
func snapshotStateOnly(t *testing.T, h *harness) string {
	t.Helper()
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := h.c.Store().Backup(context.Background(), snap, store.BackupOptions{StateOnly: true}); err != nil {
		t.Fatal(err)
	}
	return snap
}

// snapshotFull writes a full snapshot of the live store, including its events.
func snapshotFull(t *testing.T, h *harness) string {
	t.Helper()
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := h.c.Store().Backup(context.Background(), snap, store.BackupOptions{}); err != nil {
		t.Fatal(err)
	}
	return snap
}

// T23 CI half: a restored controller asks for the whole spool, verifies the
// run through the snapshot's recorded sequence and hash, backfills it and then
// accepts the events that were lost with the old controller.
func TestRestoreResendBackfillsAndExtends(t *testing.T) {
	h := newHarness(t)
	trig := make(chan int, 64)
	h.addHostMods("h1", agent.ModuleSpec{Module: numberedModule{trig: trig}})
	ctx := context.Background()

	for n := 1; n <= 12; n++ {
		trig <- n
	}
	waitStored(t, h, "h1", 12)
	snap := snapshotStateOnly(t, h)
	ag, err := h.c.Store().Agent(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	restoredSeq := ag.LastSeq
	for n := 13; n <= 30; n++ {
		trig <- n
	}
	waitStored(t, h, "h1", 30)

	h.restoreFromSnapshot(snap)
	if n, err := h.c.Store().Count(ctx, "h1"); err != nil || n != 0 {
		t.Fatalf("the state-only snapshot holds %d events (%v)", n, err)
	}
	eventually(t, "the resend to backfill 1..12 and extend to 30", 30*time.Second, func() bool {
		return storedOfKind(t, h, "h1", "test.n12") == 30
	})
	if g, err := h.c.Store().Gaps(ctx, "h1"); err != nil || len(g) != 0 {
		t.Fatalf("gaps after an untrimmed resend: %+v %v", g, err)
	}
	eps, err := h.c.Store().Epochs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 2 || eps[1].Reason != "controller restored" {
		t.Fatalf("epochs %+v", eps)
	}
	if n := storedOfKind(t, h, "h1", "agent.start"); n != 1 {
		t.Fatalf("agent.start stored %d times after the resend; want 1", n)
	}
	// The chain the controller now holds is continuous from seq 1.
	var seq uint64
	for {
		evs, err := h.c.Store().Events(ctx, store.Query{Agent: "h1", AfterSeq: seq, Limit: 1000})
		if err != nil {
			t.Fatal(err)
		}
		if len(evs) == 0 {
			break
		}
		for _, e := range evs {
			if e.Seq != seq+1 {
				t.Fatalf("restored chain jumps from %d to %d", seq, e.Seq)
			}
			seq = e.Seq
		}
	}
	if seq <= restoredSeq {
		t.Fatalf("chain ends at %d, at or before the restore point %d", seq, restoredSeq)
	}
}

// A restore resend can hold far more events below the restore point than one
// Ingest batch: every batch continues the run, all of it is backfilled, and the
// session stays up.
func TestRestoreResendBackfillsMoreThanOneBatch(t *testing.T) {
	h := newHarness(t)
	trig := make(chan int, 3000)
	h.addHostMods("h1", agent.ModuleSpec{Module: numberedModule{trig: trig}})
	ctx := context.Background()

	for n := 1; n <= 2500; n++ {
		trig <- n
	}
	waitStored(t, h, "h1", 2500)
	snap := snapshotStateOnly(t, h)
	ag, err := h.c.Store().Agent(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	restoredSeq := ag.LastSeq
	for n := 2501; n <= 2600; n++ {
		trig <- n
	}
	waitStored(t, h, "h1", 2600)

	h.restoreFromSnapshot(snap)
	eventually(t, "the resend to backfill 2500 events and extend to 2600", 60*time.Second, func() bool {
		return storedOfKind(t, h, "h1", "test.n12") == 2600
	})

	evs, err := h.c.Store().Events(ctx, store.Query{Agent: "h1", Kind: "test.n12", Limit: store.MaxQueryLimit})
	if err != nil {
		t.Fatal(err)
	}
	below := 0
	for _, e := range evs {
		if e.Seq <= restoredSeq {
			below++
		}
	}
	if below != 2500 {
		t.Fatalf("%d numbered events below the restore point %d; want 2500", below, restoredSeq)
	}
	if g, err := h.c.Store().Gaps(ctx, "h1"); err != nil || len(g) != 0 {
		t.Fatalf("gaps after a complete resend: %+v %v", g, err)
	}
	for _, a := range h.c.Alerts() {
		if a.Host == "h1" && a.Kind == "store.chain_error" {
			t.Fatalf("resend alert: %+v", a)
		}
	}

	// The session that carried the resend stays up: a new event is stored
	// without another hello.
	n, ok := h.c.AgentStatus("h1")
	if !ok || !n.Connected {
		t.Fatal("h1 is not connected after the resend")
	}
	trig <- 2601
	waitStored(t, h, "h1", 2601)
	if after, _ := h.c.AgentStatus("h1"); after.Connects != n.Connects {
		t.Fatalf("h1 reconnected after the resend (%d -> %d hellos)", n.Connects, after.Connects)
	}
}

// A state-only snapshot holds no events, so the whole 6000-event spool is
// resent. The controller cannot ack below its restore point until the run
// reaches it; the agent lifts the first resend over the link's window so the
// session completes and every event is backfilled once.
func TestRestoreResendWindowStateOnly(t *testing.T) {
	h := newHarness(t)
	trig := make(chan int, 6100)
	h.addHostMods("h1", agent.ModuleSpec{Module: numberedModule{trig: trig}})
	ctx := context.Background()

	for n := 1; n <= 6000; n++ {
		trig <- n
	}
	waitStored(t, h, "h1", 6000)
	snap := snapshotStateOnly(t, h)
	ag, err := h.c.Store().Agent(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	restoredSeq := ag.LastSeq

	h.restoreFromSnapshot(snap)
	eventually(t, "the 6000-event resend to be backfilled", 90*time.Second, func() bool {
		return storedOfKind(t, h, "h1", "test.n12") == 6000
	})

	evs, err := h.c.Store().Events(ctx, store.Query{Agent: "h1", Kind: "test.n12", Limit: store.MaxQueryLimit})
	if err != nil {
		t.Fatal(err)
	}
	below := 0
	for _, e := range evs {
		if e.Seq <= restoredSeq {
			below++
		}
	}
	if len(evs) != 6000 || below != 6000 {
		t.Fatalf("%d numbered events (%d below %d); want all 6000 once", len(evs), below, restoredSeq)
	}
	if g, err := h.c.Store().Gaps(ctx, "h1"); err != nil || len(g) != 0 {
		t.Fatalf("gaps after a complete resend: %+v %v", g, err)
	}
	for _, a := range h.c.Alerts() {
		if a.Host == "h1" && a.Kind == "store.chain_error" {
			t.Fatalf("resend alert: %+v", a)
		}
	}

	// The session that carried the resend stays up.
	n, ok := h.c.AgentStatus("h1")
	if !ok || !n.Connected {
		t.Fatal("h1 is not connected after the resend")
	}
	trig <- 6001
	waitStored(t, h, "h1", 6001)
	if after, _ := h.c.AgentStatus("h1"); after.Connects != n.Connects {
		t.Fatalf("h1 reconnected after the resend (%d -> %d hellos)", n.Connects, after.Connects)
	}
}

// A full snapshot holds the events below the restore point, so the controller
// asks only for the last 1000 below it. The run verifies the hash at the point,
// does not duplicate anything below it, and then stores the events that were
// lost with the old controller.
func TestRestoreResendWindowFullSnapshot(t *testing.T) {
	h := newHarness(t)
	trig := make(chan int, 6200)
	h.addHostMods("h1", agent.ModuleSpec{Module: numberedModule{trig: trig}})
	ctx := context.Background()

	for n := 1; n <= 6000; n++ {
		trig <- n
	}
	waitStored(t, h, "h1", 6000)
	snap := snapshotFull(t, h)
	ag, err := h.c.Store().Agent(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	restoredSeq := ag.LastSeq
	for n := 6001; n <= 6100; n++ {
		trig <- n
	}
	waitStored(t, h, "h1", 6100)

	h.restoreFromSnapshot(snap)
	eventually(t, "the short resend to verify the point and extend to 6100", 60*time.Second, func() bool {
		return storedOfKind(t, h, "h1", "test.n12") == 6100
	})

	evs, err := h.c.Store().Events(ctx, store.Query{Agent: "h1", Kind: "test.n12", Limit: store.MaxQueryLimit})
	if err != nil {
		t.Fatal(err)
	}
	below := 0
	prev := uint64(0)
	for _, e := range evs {
		if e.Seq <= prev {
			t.Fatalf("event seq %d follows %d: duplicate or out of order", e.Seq, prev)
		}
		prev = e.Seq
		if e.Seq <= restoredSeq {
			below++
		}
	}
	if len(evs) != 6100 || below != 6000 {
		t.Fatalf("%d numbered events (%d below %d); want 6100 with 6000 below, no duplicates", len(evs), below, restoredSeq)
	}
	if g, err := h.c.Store().Gaps(ctx, "h1"); err != nil || len(g) != 0 {
		t.Fatalf("gaps after a complete resend: %+v %v", g, err)
	}
	for _, a := range h.c.Alerts() {
		if a.Host == "h1" && a.Kind == "store.chain_error" {
			t.Fatalf("resend alert: %+v", a)
		}
	}
}

// A spool that no longer holds the events below the restore point (old acked
// segments were reclaimed) cannot verify them: the missing range becomes one
// gap with reason "controller restored" and the retained events are stored.
func TestRestoreResendSpoolTrimmedRecordsGap(t *testing.T) {
	h := newHarness(t)
	trig := make(chan int, 64)
	h1 := h.addHostMods("h1", agent.ModuleSpec{Module: numberedModule{trig: trig}})
	ctx := context.Background()

	for n := 1; n <= 12; n++ {
		trig <- n
	}
	waitStored(t, h, "h1", 12)
	snap := snapshotStateOnly(t, h)
	ag, err := h.c.Store().Agent(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	restoredSeq := ag.LastSeq
	for n := 13; n <= 30; n++ {
		trig <- n
	}
	waitStored(t, h, "h1", 30)
	keep := seqOfNumber(t, h, "h1", 21)
	// Trim the agent's spool to the events from n=21 on (the retained window
	// after reclamation) and restart it.
	h.stopController()
	h1.stop()
	trimSpool(t, h1.layout.SpoolDir(), keep)
	h1.start(h)

	h.restoreFromSnapshot(snap)
	eventually(t, "the retained events to be stored", 30*time.Second, func() bool {
		return storedOfKind(t, h, "h1", "test.n12") == 10
	})
	g, err := h.c.Store().Gaps(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if len(g) != 1 || g[0].From != restoredSeq+1 || g[0].To != keep-1 || g[0].Reason != "controller restored" {
		t.Fatalf("gaps %+v; want one gap %d..%d controller restored", g, restoredSeq+1, keep-1)
	}
	// Nothing below the gap was backfilled: the retained range is where the
	// stored numbered events start.
	evs, err := h.c.Store().Events(ctx, store.Query{Agent: "h1", Kind: "test.n12", Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) == 0 || evs[0].Seq != keep {
		t.Fatalf("stored numbered events start at %v; want the oldest retained event %d", evs, keep)
	}
}

// A resend whose history differs from the snapshot's is refused: nothing is
// stored, the controller alerts and the session ends; the honest agent with
// the same key still works afterwards.
func TestRestoreResendForgedHistoryRefused(t *testing.T) {
	h := newHarness(t)
	trig := make(chan int, 64)
	h1 := h.addHostMods("h1", agent.ModuleSpec{Module: numberedModule{trig: trig}})
	ctx := context.Background()

	for n := 1; n <= 12; n++ {
		trig <- n
	}
	waitStored(t, h, "h1", 12)
	snap := snapshotStateOnly(t, h)
	for n := 13; n <= 30; n++ {
		trig <- n
	}
	waitStored(t, h, "h1", 30)
	h.stopController()
	h1.stop()
	h.restoreFromSnapshot(snap)

	// A second state dir with the real h1 key but a different history.
	forger := h.addForger(t, "h1", h1)
	eventually(t, "the forged resend to be refused", 30*time.Second, func() bool {
		for _, a := range h.c.Alerts() {
			if a.Host == "h1" && a.Kind == "store.chain_error" {
				return true
			}
		}
		return false
	})
	if n, err := h.c.Store().Count(ctx, "h1"); err != nil || n != 0 {
		t.Fatalf("the forged history stored %d events (%v)", n, err)
	}
	forger.stop()

	// The honest agent still enrolls its resend and backfills.
	h1.start(h)
	eventually(t, "the honest agent to backfill", 30*time.Second, func() bool {
		return storedOfKind(t, h, "h1", "test.n12") == 30
	})
}

// ---- spool trimming ----

// trimSpool rebuilds the spool at dir with only the events at or above keep,
// as if the old acked segments had been reclaimed.
func trimSpool(t *testing.T, dir string, keep uint64) {
	t.Helper()
	old, err := spool.Open(dir, spool.Options{Agent: "h1", MaxBytes: 200 << 20})
	if err != nil {
		t.Fatal(err)
	}
	evs, err := old.ResendFrom(keep, 1000)
	if err != nil || len(evs) == 0 {
		t.Fatalf("resend from %d: %d events, %v", keep, len(evs), err)
	}
	before, err := old.ResendFrom(keep-1, 1)
	if err != nil || len(before) != 1 {
		t.Fatalf("event %d: %d events, %v", keep-1, len(before), err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Seed the chain head at keep-1 so the retained events keep their seq.
	m, err := json.Marshal(map[string]any{"v": 1, "ack": keep - 1, "ack_hash": before[0].Hash,
		"head_seq": keep - 1, "head_hash": before[0].Hash})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), m, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := spool.Open(dir, spool.Options{Agent: "h1"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, e := range evs {
		got, err := s.Append(e)
		if err != nil {
			t.Fatal(err)
		}
		if got.Seq != e.Seq || got.Hash != e.Hash {
			t.Fatalf("rebuilt event %d differs from the original", e.Seq)
		}
	}
	if err := s.Ack(keep + uint64(len(evs)) - 1); err != nil {
		t.Fatal(err)
	}
}

// addForger starts a second agent state dir with host's identity and a spool
// holding a different history, so it can claim to be host after a restore.
func (h *harness) addForger(t *testing.T, host string, real *testHost) *testHost {
	t.Helper()
	idRaw, err := os.ReadFile(real.layout.Identity())
	if err != nil {
		t.Fatal(err)
	}
	th := &testHost{name: host, root: t.TempDir(), svc: newFakeSvc(), layout: agent.Layout{Root: filepath.Join(t.TempDir(), "forged")}}
	if err := th.layout.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(th.layout.Identity(), idRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := th.layout.SaveState(agent.State{Enrolled: true}); err != nil {
		t.Fatal(err)
	}
	sp, err := spool.Open(th.layout.SpoolDir(), spool.Options{Agent: host})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 31; i++ {
		if _, err := sp.Append(event.Event{Kind: "test.n12", Priority: event.PriorityNormal,
			Fields: map[string]any{"n": i, "forged": "yes"}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := th.layout.SaveBundle(&agent.Bundle{Controllers: []string{h.addr}, ControllerPin: h.c.Pin().String(),
		Host: host, PlanKey: hex.EncodeToString(h.c.PlanPublicKey())}); err != nil {
		t.Fatal(err)
	}
	h.hosts["forger"] = th
	th.start(h)
	return th
}

// waitSigning waits for the restored controller to sign and returns its epoch.
func waitSigning(t *testing.T, h *harness) uint64 {
	t.Helper()
	eventually(t, "signing to be ready", 20*time.Second, func() bool {
		ready, _ := h.c.SigningReady()
		return ready
	})
	ep, err := h.c.Store().Epoch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return ep
}

// R7: a second restore from the same snapshot produces the same epoch, so the
// controller raises it above what the agents report before it signs anything.
func TestRestoreTwiceFromSameSnapshot(t *testing.T) {
	h := newHarness(t)
	h.addHost("h1")
	ctx := context.Background()
	if ep, _ := h.c.Store().Epoch(ctx); ep != 1 {
		t.Fatalf("start epoch %d, want 1", ep)
	}
	snap := snapshotStateOnly(t, h)

	// Restore #1: epoch 2. h1 accepts a control signed at (2, 1).
	h.restoreFromSnapshot(snap)
	if ep := waitSigning(t, h); ep != 2 {
		t.Fatalf("epoch after restore #1 = %d, want 2", ep)
	}
	if err := h.c.SendControl(ctx, "h1", plan.ControlSafeMode, true, nil); err != nil {
		t.Fatal(err)
	}
	eventually(t, "h1 to enter safe mode", 20*time.Second, func() bool {
		st, ok := h.c.AgentStatus("h1")
		return ok && st.SafeMode
	})
	var first *link.Control
	h.mu.Lock()
	for _, c := range h.ctls {
		if first == nil && c.Kind == plan.ControlSafeMode && c.On {
			first = c
		}
	}
	h.mu.Unlock()
	if first == nil || first.Epoch != 2 {
		t.Fatalf("first safe-mode control %+v; want epoch 2", first)
	}

	// Restore #2 from the same snapshot: the snapshot's epoch 1 again, so the
	// store starts at 2 again; h1 reports 2 and the controller raises to 3.
	h.stopController()
	h.restoreFromSnapshot(snap)
	if ep, _ := h.c.Store().Epoch(ctx); ep != 2 {
		t.Fatalf("epoch after restore #2 = %d, want the snapshot's 2 before any report", ep)
	}
	if ep := waitSigning(t, h); ep != 3 {
		t.Fatalf("epoch after h1's report = %d, want 3", ep)
	}

	// The (2, 1) control h1 already accepted is a replay now; without the
	// raise every new control would look like one.
	before := len(h.agentEvents("h1", "agent.control_refused"))
	h.c.SendRaw(ctx, "h1", first)
	eventually(t, "the replayed control to be refused", 20*time.Second, func() bool {
		return len(h.agentEvents("h1", "agent.control_refused")) > before
	})

	// A control signed after the report is in the raised epoch and accepted.
	if err := h.c.SendControl(ctx, "h1", plan.ControlSafeMode, false, nil); err != nil {
		t.Fatal(err)
	}
	eventually(t, "h1 to leave safe mode", 20*time.Second, func() bool {
		st, ok := h.c.AgentStatus("h1")
		return ok && !st.SafeMode
	})
	h.mu.Lock()
	var last *link.Control
	for _, c := range h.ctls {
		if c.Kind == plan.ControlSafeMode && !c.On {
			last = c
		}
	}
	h.mu.Unlock()
	if last == nil || last.Epoch != 3 {
		t.Fatalf("the control after the raise is %+v; want epoch 3", last)
	}
}
