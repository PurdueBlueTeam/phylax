package mods

import (
	"fmt"
	"net/netip"
	"runtime"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	netmod "github.com/PurdueBlueTeam/phylax/internal/collect/net"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func init() {
	agent.RegisterFactory(agent.Factory{
		Name: "net",
		Section: func(c *plan.AgentConfig) (string, bool) {
			if c.Modules.Net == nil || !c.Modules.Net.Enabled {
				return "", false
			}
			return fp(c.Modules.Net), true
		},
		Build: func(env agent.Env, c *plan.AgentConfig) (agent.ModuleSpec, error) {
			s := c.Modules.Net
			if runtime.GOOS != "linux" {
				return agent.ModuleSpec{}, unavailable("net telemetry needs Linux sock_diag")
			}
			cfg := netmod.Config{
				Interval:    time.Duration(s.IntervalMS) * time.Millisecond,
				Services:    s.Services,
				HashExe:     s.HashExe,
				NFLogGroups: s.NFLogGroups,
				Logger:      env.Logger,
			}
			for _, ct := range s.Canaries {
				a, err := netip.ParseAddr(ct.Addr)
				if err != nil {
					return agent.ModuleSpec{}, fmt.Errorf("net canary %q: %w", ct.Addr, err)
				}
				t, err := netmod.ParseCanaryTarget(a.String(), ct.Port, ct.Tag)
				if err != nil {
					return agent.ModuleSpec{}, err
				}
				cfg.CanaryTargets = append(cfg.CanaryTargets, t)
			}
			return spec(netmod.New(cfg), s.RatePerSec, s.Burst), nil
		},
	})
}
