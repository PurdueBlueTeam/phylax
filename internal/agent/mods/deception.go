package mods

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/decoys"
	"github.com/PurdueBlueTeam/phylax/internal/honeytokens"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// DeceptionFile is the per-host decoy/honeytoken configuration the deploy plan
// writes into the agent state directory (generated at competition time).
const DeceptionFile = "deception.json"

func hasDecoyRole(c *plan.AgentConfig) bool { return slices.Contains(c.Roles, "decoys") }

// declaredPorts are the ports of every service the host declares (the net
// module's service map, "proto/port"): a decoy never sits on any of them, a
// superset of the scored ports.
func declaredPorts(c *plan.AgentConfig) []uint16 {
	var out []uint16
	if c.Modules.Net == nil {
		return nil
	}
	for k := range c.Modules.Net.Services {
		if _, p, ok := strings.Cut(k, "/"); ok {
			if n, err := strconv.ParseUint(p, 10, 16); err == nil {
				out = append(out, uint16(n))
			}
		}
	}
	return out
}

func init() {
	agent.RegisterFactory(agent.Factory{
		Name: "decoys",
		Section: func(c *plan.AgentConfig) (string, bool) {
			if !hasDecoyRole(c) {
				return "", false
			}
			return fp([]any{c.Version, c.Epoch}), true
		},
		Build: buildDecoys,
	})
	agent.RegisterFactory(agent.Factory{
		Name: "honeywatch",
		Section: func(c *plan.AgentConfig) (string, bool) {
			if !hasDecoyRole(c) || runtime.GOOS != "linux" {
				return "", false
			}
			return fp([]any{c.Version, c.Epoch}), true
		},
		Build: buildHoneywatch,
	})
}

func buildDecoys(env agent.Env, c *plan.AgentConfig) (agent.ModuleSpec, error) {
	lc, err := decoys.LoadLocalConfig(filepath.Join(env.StateDir, DeceptionFile))
	if err != nil {
		return agent.ModuleSpec{}, unavailable("no decoy configuration: " + err.Error())
	}
	reg, err := lc.Registry()
	if err != nil {
		return agent.ModuleSpec{}, err
	}
	cfg := decoys.Config{Host: env.Host, Bind: lc.Bind, Tokens: reg, Logger: env.Logger,
		ScoredPorts: append(append([]uint16(nil), lc.ScoredPorts...), declaredPorts(c)...)}
	for _, l := range lc.Listeners {
		cfg.Listeners = append(cfg.Listeners, decoys.Listener{Kind: l.Kind, Port: l.Port})
	}
	m, err := decoys.New(cfg) // refuses a scored or declared port
	if err != nil {
		return agent.ModuleSpec{}, err
	}
	return spec(m, 20, 50), nil
}

func buildHoneywatch(env agent.Env, c *plan.AgentConfig) (agent.ModuleSpec, error) {
	lc, err := decoys.LoadLocalConfig(filepath.Join(env.StateDir, DeceptionFile))
	if err != nil || len(lc.WatchPaths) == 0 {
		return agent.ModuleSpec{}, unavailable("no honey files to watch")
	}
	reg, err := lc.Registry()
	if err != nil {
		return agent.ModuleSpec{}, err
	}
	w, err := honeytokens.NewFanotify()
	if err != nil {
		return agent.ModuleSpec{}, unavailable(err.Error())
	}
	return spec(&honeytokens.WatchModule{W: w, Paths: lc.WatchPaths, Reg: reg, Host: env.Host,
		IgnorePID: os.Getpid()}, 10, 20), nil
}
