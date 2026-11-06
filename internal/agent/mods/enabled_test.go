package mods

import (
	"runtime"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// enabledCfg is a signed-config stand-in whose every block carries enabled.
func enabledCfg(on bool) *plan.AgentConfig {
	lim := plan.ModuleLimits{Common: module.Common{Enabled: on}}
	return &plan.AgentConfig{Roles: []string{"capture", "decoys"}, Modules: plan.ModuleSettings{
		Health:    &plan.HealthSettings{ModuleLimits: lim},
		Audit:     &plan.AuditSettings{ModuleLimits: lim},
		Net:       &plan.NetSettings{ModuleLimits: lim},
		Winevt:    &plan.WinevtSettings{ModuleLimits: lim},
		Integrity: &plan.IntegritySettings{ModuleLimits: lim},
		Detect:    &plan.DetectSettings{ModuleLimits: lim},
		Deception: &plan.DeceptionSettings{Common: module.Common{Enabled: on}},
	}}
}

// TestSectionHonoursEnabled checks every block-driven factory: a block with
// enabled false keeps the module off, enabled true (with its roles) runs it.
// "capture" has no config block of its own (it reads the net block and the
// capture role), so it is covered by its own test.
func TestSectionHonoursEnabled(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range agent.Registered() {
		switch f.Name {
		case "health", "capture":
			continue // health is on without a block; capture is role-only
		case "honeywatch":
			if runtime.GOOS != "linux" {
				continue
			}
		}
		if _, on := f.Section(enabledCfg(false)); on {
			t.Errorf("%s enabled with enabled: false", f.Name)
		}
		if _, on := f.Section(enabledCfg(true)); !on {
			t.Errorf("%s off with enabled: true", f.Name)
		}
		seen[f.Name] = true
	}
	for _, want := range []string{"audit", "net", "winevt", "integrity", "detect", "decoys"} {
		if !seen[want] {
			t.Errorf("factory %s not covered", want)
		}
	}
}
