package controller

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	phyagent "github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

type healthReporterMod struct{}

func (healthReporterMod) Name() string { return "hx" }
func (healthReporterMod) Start(ctx context.Context, _ phyagent.Emit) error {
	<-ctx.Done()
	return nil
}
func (healthReporterMod) Health() module.Health {
	return module.Health{State: module.StateOK, Info: map[string]string{"rules_hash": "abc"}}
}

func TestAgentHealthFromHeartbeat(t *testing.T) {
	x := newCtl(t)
	m := &manifest.Manifest{Hosts: map[string]manifest.Host{
		"h1": {Segment: "lan", IP: "10.0.0.10", OS: manifest.OS{Family: "debian"}},
	}}
	if err := x.c.SetConfigInputs(context.Background(), ConfigInputs{Manifest: m}); err != nil {
		t.Fatal(err)
	}
	tok, err := x.c.MintToken("h1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	enabled := func(cfg *plan.AgentConfig) (string, bool) {
		if cfg.Modules.Net == nil {
			return "", false
		}
		return "v1", true
	}
	healthy := phyagent.Factory{Name: "hx", Section: enabled,
		Build: func(phyagent.Env, *plan.AgentConfig) (phyagent.ModuleSpec, error) {
			return phyagent.ModuleSpec{Module: healthReporterMod{}}, nil
		}}
	unavailable := phyagent.Factory{Name: "hxun", Section: enabled,
		Build: func(phyagent.Env, *plan.AgentConfig) (phyagent.ModuleSpec, error) {
			return phyagent.ModuleSpec{}, fmt.Errorf("%w: needs linux", phyagent.ErrUnavailable)
		}}
	l := phyagent.Layout{Root: filepath.Join(t.TempDir(), "state")}
	if err := l.SaveBundle(&phyagent.Bundle{Controllers: []string{x.addr}, ControllerPin: x.c.Pin().String(),
		Host: "h1", Token: tok, PlanKey: hex.EncodeToString(x.c.PlanPublicKey())}); err != nil {
		t.Fatal(err)
	}
	a, err := phyagent.New(phyagent.Config{Layout: l, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		HeartbeatInterval: 20 * time.Millisecond, Backoff: link.Backoff{Min: 10 * time.Millisecond, Max: 100 * time.Millisecond},
		Supervisor: phyagent.SupervisorOptions{Backoff: link.Backoff{Min: time.Millisecond, Max: 10 * time.Millisecond}},
		Factories:  []phyagent.Factory{healthy, unavailable}})
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
	waitFor(t, 10*time.Second, "agent connected", func() bool {
		st, ok := x.c.AgentStatus("h1")
		return ok && st.Connected
	})
	waitFor(t, 10*time.Second, "module health in heartbeat", func() bool {
		h := x.c.AgentHealth("h1")
		un, ok := h["hxun"]
		return h["hx"].Info["rules_hash"] == "abc" && ok && un.State == module.StateUnavailable &&
			len(un.Gaps) == 1 && un.Gaps[0].What == "hxun"
	})
}
