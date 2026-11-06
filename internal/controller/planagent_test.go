package controller

import (
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	phyagent "github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/link"
)

// newPlanCtl starts a served controller with a manifest and plan templates.
func newPlanCtl(t *testing.T, files, plans map[string]string, opt Options) *ctl {
	t.Helper()
	dir := writeManifest(t, files)
	pdir := t.TempDir()
	for name, body := range plans {
		p := filepath.Join(pdir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := Config{AgentListen: "127.0.0.1:0", DataDir: filepath.Join(t.TempDir(), "data"),
		ManifestPath: dir, PlansPath: pdir, SilenceThreshold: Duration(300 * time.Millisecond)}
	return newCtlWith(t, cfg, opt)
}

// newPlanAgent starts a real agent (spool, link, executor) for host and returns
// it with the filesystem root its actions see.
func newPlanAgent(t *testing.T, x *ctl, host string) (*phyagent.Agent, string) {
	t.Helper()
	tok, err := x.c.Enroller().MintToken(host, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	l := phyagent.Layout{Root: filepath.Join(t.TempDir(), "agent")}
	if err := l.SaveBundle(&phyagent.Bundle{Controllers: []string{x.addr}, ControllerPin: x.c.Pin().String(),
		Host: host, Token: tok, PlanKey: hex.EncodeToString(x.c.PlanPublicKey())}); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := phyagent.New(phyagent.Config{Layout: l, Logger: log,
		Exec:       &phyagent.ExecConfig{Env: actions.NewEnv(host, root)},
		Backoff:    link.Backoff{Min: 10 * time.Millisecond, Max: 100 * time.Millisecond},
		Supervisor: phyagent.SupervisorOptions{Backoff: link.Backoff{Min: time.Millisecond, Max: 10 * time.Millisecond}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("agent did not stop")
		}
	})
	waitFor(t, 10*time.Second, "agent connection", func() bool {
		st, ok := x.c.AgentStatus(host)
		return ok && st.Connected
	})
	return a, root
}

// writeAgentFile creates a file under an agent's action root.
func writeAgentFile(t *testing.T, root, path, content string) string {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func readAgentFile(t *testing.T, root, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func readFileString(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}
