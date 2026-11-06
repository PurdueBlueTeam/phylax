package controller

import (
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/module"
)

func TestModuleRows(t *testing.T) {
	rows := moduleRows("h1", map[string]module.Health{
		"winevt": {State: module.StateDegraded, Detail: "sysmon", Gaps: []module.Gap{{What: "sysmon", Why: "service stopped"}}},
		"audit":  {State: module.StateOK},
	})
	if len(rows) != 2 || rows[0].Module != "audit" || rows[1].Module != "winevt" {
		t.Fatalf("rows are not one sorted row per module: %+v", rows)
	}
	if rows[0].Agent != "h1" || rows[0].State != string(module.StateOK) {
		t.Errorf("audit row: %+v", rows[0])
	}
	if !rows[0].PreContract || !rows[1].PreContract {
		t.Errorf("a module with no manifest in the registry must be marked pre-contract: %+v", rows)
	}
	if rows[1].Detail != "sysmon" || len(rows[1].Gaps) != 1 || rows[1].Gaps[0] != "sysmon: service stopped" {
		t.Errorf("winevt row: %+v", rows[1])
	}

	// controllerAgent rows come from ModuleHealth; an empty map is no rows.
	if got := moduleRows(ControllerAgent, nil); len(got) != 0 {
		t.Errorf("no health, no rows: %+v", got)
	}
}
