package controller

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/enroll"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// chainEvents builds n sealed events for agent, starting at seq 1.
func chainEvents(t *testing.T, agent string, n int) []event.Event {
	t.Helper()
	out := make([]event.Event, n)
	hash := ""
	for i := range out {
		e := event.Event{Agent: agent, Time: time.Unix(0, 0).UTC().Add(time.Duration(i) * time.Second),
			Kind: "test.event", Fields: map[string]any{"i": i}}
		if err := e.Seal(uint64(i), hash); err != nil {
			t.Fatal(err)
		}
		out[i] = e
		hash = e.Hash
	}
	return out
}

// newSnapshotController is a controller with two enrolled agents that have
// events, and a token file, in a fresh data dir.
func newSnapshotController(t *testing.T) (*Controller, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{AgentListen: "127.0.0.1:0", DataDir: dir}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	c, err := New(context.Background(), cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	ctx := context.Background()
	for _, h := range []string{"h1", "h2"} {
		if err := c.Store().EnrollAgent(ctx, h, []byte("key-"+h)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Store().Ingest(ctx, h, chainEvents(t, h, 10)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Enroller().MintToken("h1", time.Minute); err != nil {
		t.Fatal(err)
	}
	return c, dir
}

func TestSnapshotRoundTrip(t *testing.T) {
	ctx := context.Background()
	c, dir := newSnapshotController(t)
	now := time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	snapDir := t.TempDir()
	path, err := c.WriteSnapshot(ctx, snapDir, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if base := filepath.Base(path); !strings.HasPrefix(base, "phylax-snapshot-") || !strings.HasSuffix(base, ".age") {
		t.Fatalf("snapshot name %q", base)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode: %v %v", fi, err)
	}

	newDir := filepath.Join(t.TempDir(), "restored")
	if err := RestoreSnapshot(ctx, path, []byte("wrong"), newDir, "test restore", false); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if err := RestoreSnapshot(ctx, path, []byte("pw"), newDir, "test restore", false); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(newDir, "phylax.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"h1", "h2"} {
		a, err := st.Agent(ctx, h)
		if err != nil {
			t.Fatal(err)
		}
		if a.LastSeq != 10 || a.LastHash == "" {
			t.Fatalf("%s: %+v", h, a)
		}
		n, err := st.Count(ctx, h)
		if err != nil || n != 0 {
			t.Fatalf("%s events after state-only restore: %d %v", h, n, err)
		}
	}
	st.Close()

	for _, name := range []string{"identity.pem", "plan.key", "tokens.json"} {
		want, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(newDir, name))
		if err != nil {
			t.Fatalf("%s restored: %v", name, err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("%s differs after restore", name)
		}
	}

	cfg2 := Config{AgentListen: "127.0.0.1:0", DataDir: newDir}
	if err := cfg2.Validate(); err != nil {
		t.Fatal(err)
	}
	c2, err := New(ctx, cfg2, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if c2.Pin() != c.Pin() {
		t.Fatal("restored controller has a different pin")
	}
	if !bytes.Equal(c2.PlanPublicKey(), c.PlanPublicKey()) {
		t.Fatal("restored controller has a different plan key")
	}
}

func TestSnapshotKeepsNewestEight(t *testing.T) {
	ctx := context.Background()
	c, _ := newSnapshotController(t)
	now := time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	dir := t.TempDir()
	for i := 0; i < 10; i++ {
		now = now.Add(time.Second)
		if _, err := c.WriteSnapshot(ctx, dir, []byte("pw")); err != nil {
			t.Fatal(err)
		}
	}
	files, err := filepath.Glob(filepath.Join(dir, "phylax-snapshot-*.age"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 8 {
		t.Fatalf("%d snapshots left, want 8: %v", len(files), files)
	}
	for i := 0; i < 8; i++ {
		want := "phylax-snapshot-" + now.Add(time.Duration(i-7)*time.Second).Format("20060102T150405Z") + ".age"
		if filepath.Base(files[i]) != want {
			t.Fatalf("kept %v, want the newest 8 ending %s", files, want)
		}
	}
}

func TestSnapshotRefusesExistingDataDir(t *testing.T) {
	ctx := context.Background()
	c, _ := newSnapshotController(t)
	path, err := c.WriteSnapshot(ctx, t.TempDir(), []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "phylax.db"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = RestoreSnapshot(ctx, path, []byte("pw"), dataDir, "restore", false)
	if err == nil || !strings.Contains(err.Error(), "phylax.db") {
		t.Fatalf("err = %v, want one naming phylax.db", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dataDir, "phylax.db")); string(b) != "existing" {
		t.Fatal("refused restore changed the database")
	}
	if err := RestoreSnapshot(ctx, path, []byte("pw"), dataDir, "restore", true); err != nil {
		t.Fatalf("force: %v", err)
	}
}

func TestSnapshotRejectsPathTraversal(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "evil.age")
	mk := func(name string) {
		var plain bytes.Buffer
		tw := tar.NewWriter(&plain)
		body := []byte("evil")
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		r, err := age.NewScryptRecipient("pw")
		if err != nil {
			t.Fatal(err)
		}
		r.SetWorkFactor(10)
		var out bytes.Buffer
		w, err := age.Encrypt(&out, r)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(plain.Bytes())
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"../x", "/etc/x", "sub/x"} {
		mk(name)
		dataDir := filepath.Join(t.TempDir(), "data")
		err := RestoreSnapshot(ctx, path, []byte("pw"), dataDir, "restore", false)
		if err == nil || !strings.Contains(err.Error(), "entry") {
			t.Fatalf("%q: err = %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(dataDir, "..", "x")); err == nil {
			t.Fatalf("%q wrote outside the data dir", name)
		}
		if _, err := os.Stat("/etc/x"); err == nil {
			t.Fatalf("%q wrote /etc/x", name)
		}
	}
}

// waitStatus waits for the snapshot writer's status to contain want.
func waitStatus(t *testing.T, c *Controller, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if strings.Contains(c.SnapshotStatus(), want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("snapshot status %q does not contain %q", c.SnapshotStatus(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func countSnapshots(t *testing.T, dir string) int {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "phylax-snapshot-*.age"))
	if err != nil {
		t.Fatal(err)
	}
	return len(files)
}

func TestRunSnapshotsDebouncesAndWaitsForPassphrase(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := actionsCore(t)
	c := newTestControllerWithRegistry(t, reg, nil)
	dir := t.TempDir()
	fc := newFakeClock(time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC))
	c.clk, c.now = fc, fc.Now
	c.cfg.SnapshotDirs = []string{dir}
	c.cfg.SnapshotInterval = Duration(15 * time.Minute)
	var pass []byte
	go c.RunSnapshots(ctx, func() []byte { return pass })
	fc.waitOps(t, 1)

	fc.Advance(15 * time.Minute)
	waitStatus(t, c, "skipped: locked")
	if n := countSnapshots(t, dir); n != 0 {
		t.Fatalf("%d snapshots without a passphrase", n)
	}

	pass = []byte("pw")
	if err := c.Enroller().Announce(ctx, "h1", c.Pin(), enroll.Result{Enrolled: true}); err != nil {
		t.Fatal(err)
	}
	fc.waitOps(t, 1) // the debounce timer the writer armed
	// A plan completion inside the same 30 s window coalesces into that write.
	p := plan.Plan{ID: "snap-plan", OnFailure: plan.StopDependents, Nodes: []plan.Node{
		{ID: "n1", Action: "ctltest.local", Target: "ctl", Params: map[string]any{}},
	}}
	if err := c.CreatePlan(ctx, p, "driver"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DryRun(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if err := c.ApprovePlan(ctx, p.ID, "driver"); err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Wait(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	fc.Advance(30 * time.Second)
	waitStatus(t, c, "wrote")
	if n := countSnapshots(t, dir); n != 1 {
		t.Fatalf("%d snapshots after two triggers inside 30 s, want 1", n)
	}

	fc.Advance(15 * time.Minute)
	deadline := time.Now().Add(3 * time.Second)
	for countSnapshots(t, dir) != 2 {
		if time.Now().After(deadline) {
			t.Fatalf("%d snapshots after a tick, want 2", countSnapshots(t, dir))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// actionsCore gives the local controller-side test action a registry to live
// in; the action itself is defined in exec_test.go.
func actionsCore(t *testing.T) *actions.Registry {
	t.Helper()
	reg := actions.Core()
	reg.Register(ctlAction{new(atomic.Int32)})
	return reg
}
