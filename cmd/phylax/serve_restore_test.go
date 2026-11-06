package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/controller"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

func TestServeRestoreFlag(t *testing.T) {
	ctx := context.Background()
	src := t.TempDir()
	cfg := controller.Config{AgentListen: "127.0.0.1:0", DataDir: src}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	c, err := controller.New(ctx, cfg, controller.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Store().EnrollAgent(ctx, "h1", []byte("key-h1")); err != nil {
		c.Close()
		t.Fatal(err)
	}
	e := event.Event{Agent: "h1", Time: time.Unix(0, 0).UTC(), Kind: "test.event", Fields: map[string]any{"i": 1}}
	if err := e.Seal(0, ""); err != nil {
		c.Close()
		t.Fatal(err)
	}
	if _, err := c.Store().Ingest(ctx, "h1", []event.Event{e}); err != nil {
		c.Close()
		t.Fatal(err)
	}
	snap, err := c.WriteSnapshot(ctx, t.TempDir(), []byte("pw"))
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	newDir := filepath.Join(t.TempDir(), "restored")
	t.Setenv("PHYLAX_VAULT_PASSPHRASE", "pw")
	sctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	err = commands["serve"].run(sctx, []string{
		"-data-dir", newDir,
		"-listen", "127.0.0.1:0",
		"-ui-listen", "off",
		"-restore", snap,
		"-restore-reason", "from test",
	})
	if err != nil {
		t.Fatalf("serve -restore: %v", err)
	}

	st, err := store.Open(ctx, filepath.Join(newDir, "phylax.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	eps, err := st.Epochs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 2 || eps[1].Epoch != 2 || eps[1].Reason != "from test" {
		t.Fatalf("epochs after -restore: %+v", eps)
	}
	a, err := st.Agent(ctx, "h1")
	if err != nil || a.LastSeq != 1 {
		t.Fatalf("restored agent: %+v %v", a, err)
	}
	if _, err := os.Stat(filepath.Join(newDir, "identity.pem")); err != nil {
		t.Fatalf("identity restored: %v", err)
	}
}
