package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

func init() {
	register(command{name: "guard", summary: "print a host's scoring-guard rules from the manifest (guard <host> [--dir D])", run: runGuard})
}

// guardFile is the agent's scoring-guard configuration (a StaticGuard as JSON),
// produced by `phylax guard <host>` and shipped with the host's bootstrap.
func guardFile(l agent.Layout) string { return filepath.Join(l.Root, "guard.json") }

func loadGuard(l agent.Layout) (actions.ScoringGuard, error) {
	b, err := os.ReadFile(guardFile(l))
	if errors.Is(err, fs.ErrNotExist) {
		return actions.StaticGuard{Groups: actions.DefaultAccessGroups}, nil
	}
	if err != nil {
		return nil, err
	}
	var g actions.StaticGuard
	if err := json.Unmarshal(b, &g); err != nil {
		return nil, fmt.Errorf("%s: %w", guardFile(l), err)
	}
	return g, nil
}

// agentEnv builds the real-host action environment for this agent.
func agentEnv(l agent.Layout) (*actions.Env, error) {
	b, err := l.LoadBundle()
	if err != nil {
		return nil, err
	}
	g, err := loadGuard(l)
	if err != nil {
		return nil, err
	}
	env := actions.NewEnv(b.Host, "/")
	env.Guard = g
	env.QuarantineDir = filepath.Join(l.Root, "quarantine")
	if tl, err := actions.OpenTagLog(filepath.Join(l.Root, "tags.jsonl")); err == nil {
		env.Tags = tl
	}
	// The agent.* actions replace the binary or rename the service through the
	// detached swap helper.
	env.StartSwap = startSwapHelper
	return env, nil
}

// agentExec enables step execution when the bootstrap carries the plan key;
// an agent without one keeps rejecting steps.
func agentExec(l agent.Layout) (*agent.ExecConfig, error) {
	b, err := l.LoadBundle()
	if err != nil {
		return nil, err
	}
	if b.PlanKey == "" {
		return nil, nil
	}
	env, err := agentEnv(l)
	if err != nil {
		return nil, err
	}
	return &agent.ExecConfig{Env: env, FreshCheck: true}, nil
}

func runGuard(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("guard", flag.ContinueOnError)
	dir := fs.String("dir", defaultManifestDir(), "manifest directory")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: phylax guard <host> [--dir D]")
	}
	m, err := manifest.LoadDir(*dir, manifest.Options{})
	if err != nil {
		return err
	}
	if _, ok := m.Hosts[pos[0]]; !ok {
		return fmt.Errorf("unknown host %q", pos[0])
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(actions.GuardFromManifest(m, pos[0]))
}
