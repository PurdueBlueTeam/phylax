//go:build linux

package mods

import (
	"os"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/collect/audit"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func init() {
	agent.RegisterFactory(agent.Factory{
		Name: "audit",
		Section: func(c *plan.AgentConfig) (string, bool) {
			if c.Modules.Audit == nil {
				return "", false
			}
			return fp(c.Modules.Audit), true
		},
		Build: func(env agent.Env, c *plan.AgentConfig) (agent.ModuleSpec, error) {
			s := c.Modules.Audit
			if os.Geteuid() != 0 {
				return agent.ModuleSpec{}, unavailable("the kernel audit netlink socket needs root")
			}
			cfg := audit.Config{
				WebRoots:      s.WebRoots,
				ExtraWatches:  append(append([]string(nil), s.ExtraWatches...), s.ServiceBinaries...),
				ExcludePaths:  []string{env.StateDir},
				NetRules:      s.NetRules,
				SweepInterval: time.Duration(s.SweepIntervalSec) * time.Second,
				Logger:        env.Logger,
			}
			if exe, err := os.Executable(); err == nil {
				cfg.SelfPaths = []string{exe, env.StateDir}
			}
			m, err := audit.New(cfg)
			if err != nil {
				return agent.ModuleSpec{}, err
			}
			return spec(m, s.RatePerSec, s.Burst), nil
		},
	})
}
