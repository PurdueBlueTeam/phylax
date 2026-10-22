package agent

import (
	"context"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

type fakeBackstop struct{ disarmed []string }

func (f *fakeBackstop) Arm(context.Context, string, time.Time) error { return nil }
func (f *fakeBackstop) Disarm(_ context.Context, id string) error {
	f.disarmed = append(f.disarmed, id)
	return nil
}

func TestRollbackFiresArmedEntryFromJournal(t *testing.T) {
	l := Layout{Root: t.TempDir()}
	calls := 0
	RegisterRollbackHandler("fake-kind", func(_ context.Context, e deadman.Entry) error { calls++; return nil })
	m, err := deadman.Open(l.DeadmanDir(), deadman.Options{Handlers: RollbackHandlers()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Arm(context.Background(), deadman.ArmRequest{ID: "node-9", Kind: "fake-kind", Timeout: time.Hour}); err != nil {
		t.Fatal(err)
	}
	m.Close() // the agent died; only the OS timer remains

	bs := &fakeBackstop{}
	e, err := Rollback(context.Background(), l, "node-9", RollbackOptions{Backstop: bs})
	if err != nil || e.State != deadman.StateRolledBack || e.FiredBy != "os-timer" || calls != 1 {
		t.Fatalf("%+v %v calls=%d", e, err, calls)
	}
	if len(bs.disarmed) != 1 {
		t.Fatalf("backstop not disarmed: %v", bs.disarmed)
	}
	// second timer (in-process raced it): idempotent, handler not run again
	if e, err = Rollback(context.Background(), l, "node-9", RollbackOptions{}); err != nil || calls != 1 || e.State != deadman.StateRolledBack {
		t.Fatalf("not idempotent: %+v %v %d", e, err, calls)
	}
	if _, err := Rollback(context.Background(), l, "../x", RollbackOptions{}); err == nil {
		t.Fatal("bad id accepted")
	}
	if _, err := Rollback(context.Background(), l, "missing", RollbackOptions{}); err == nil {
		t.Fatal("missing entry accepted")
	}
}

func TestBundleValidation(t *testing.T) {
	pin := "sha256//" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	good := `{"controllers":["10.0.0.1:8443"],"controller_pin":"` + pin + `","host":"h"}`
	if _, err := ParseBundle([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{}`, `{"controllers":["nohostport"],"controller_pin":"` + pin + `","host":"h"}`,
		`{"controllers":["a:1"],"controller_pin":"zz","host":"h"}`, `{"controllers":["a:1"],"controller_pin":"` + pin + `"}`, `x`} {
		if _, err := ParseBundle([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
