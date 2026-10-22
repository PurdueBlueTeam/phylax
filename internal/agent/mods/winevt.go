package mods

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/collect/winevt"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func init() {
	agent.RegisterFactory(agent.Factory{
		Name: "winevt",
		Section: func(c *plan.AgentConfig) (string, bool) {
			if c.Modules.Winevt == nil {
				return "", false
			}
			return fp(c.Modules.Winevt), true
		},
		Build: func(env agent.Env, c *plan.AgentConfig) (agent.ModuleSpec, error) {
			s := c.Modules.Winevt
			if runtime.GOOS != "windows" {
				return agent.ModuleSpec{}, unavailable("Windows event log collection needs Windows")
			}
			cfg := winevt.Config{
				BookmarkPath: filepath.Join(env.StateDir, "winevt.bookmarks"),
				Host:         env.Host,
				SysmonHints:  s.SysmonHints,
				Logger:       env.Logger,
			}
			for _, ch := range s.Channels {
				cfg.Channels = append(cfg.Channels, winevt.Channel{Name: ch.Name, Include: ch.Include, All: ch.All, Exclude: ch.Exclude})
			}
			if exe, err := os.Executable(); err == nil {
				cfg.DropExe = []string{exe}
			}
			m, err := winevt.New(cfg)
			if err != nil {
				return agent.ModuleSpec{}, err
			}
			return spec(m, s.RatePerSec, s.Burst), nil
		},
	})
}
