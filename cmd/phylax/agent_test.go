package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

func TestAgentRollbackSubcommand(t *testing.T) {
	osBackstop = func(agent.Layout) deadman.Backstop { return nil }
	dir := t.TempDir()
	l := agent.Layout{Root: dir}
	fired := 0
	agent.RegisterRollbackHandler("cmd-test", func(context.Context, deadman.Entry) error { fired++; return nil })
	m, err := deadman.Open(l.DeadmanDir(), deadman.Options{Handlers: agent.RollbackHandlers()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Arm(context.Background(), deadman.ArmRequest{ID: "n1", Kind: "cmd-test", Timeout: time.Hour}); err != nil {
		t.Fatal(err)
	}
	m.Close()

	// id last, as the OS timer passes it
	if err := commands["agent"].run(context.Background(), []string{"rollback", "--state-dir", dir, "n1"}); err != nil {
		t.Fatal(err)
	}
	if fired != 1 {
		t.Fatalf("handler ran %d times", fired)
	}
	m, _ = deadman.Open(l.DeadmanDir(), deadman.Options{})
	defer m.Close()
	if e, _ := m.Get("n1"); e.State != deadman.StateRolledBack || e.FiredBy != "os-timer" {
		t.Fatalf("%+v", e)
	}
	if err := commands["agent"].run(context.Background(), []string{"rollback", "--state-dir", dir}); err == nil {
		t.Fatal("missing id accepted")
	}
	if err := commands["agent"].run(context.Background(), []string{"bogus"}); err == nil {
		t.Fatal("bogus subcommand accepted")
	}
}

func TestAgentUnitDryRun(t *testing.T) {
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	err := commands["agent"].run(context.Background(), []string{"unit", "--secret", "0011223344556677", "--dir", "/opt/x"})
	w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	out := string(buf[:n])
	if !strings.Contains(out, "ExecStart=/opt/x/") || !strings.Contains(out, "agent run --state-dir /opt/x/state") || strings.Contains(out, "phylax agent") {
		t.Fatal(out)
	}
}
