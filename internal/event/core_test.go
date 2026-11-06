package event

import "testing"

var coreAlert = map[string]bool{"agent.silent": true, "controller.locked": true, "store.quota": true,
	"plan.failed": true, "enroll.alert": true}

func TestCoreKindsDeclared(t *testing.T) {
	kinds := []string{"agent.start", "agent.health", "agent.step", "agent.step_result", "agent.step_refused", "evidence.blob",
		"agent.config_applied", "agent.config_rejected", "agent.control_refused", "agent.module_crash", "controller.fact",
		"agent.deadman_recovered", "agent.deadman_recovery_error", "agent.enrolled", "agent.reenrolled",
		"agent.silent", "agent.resumed", "spool.gap", "plan.failed", "operator.edit", "enroll.alert",
		"controller.locked", "store.quota", "inventory.snapshot", "inventory.row", "inventory.probe_result"}
	if len(kinds) != 26 {
		t.Fatal("table has 26 core kinds")
	}
	for _, k := range kinds {
		ty, ok := Lookup(k)
		if !ok || ty.Schema != 1 || ty.Alert != coreAlert[k] {
			t.Errorf("%s: %+v %v", k, ty, ok)
		}
	}
}

func TestSpoolGapShapeValidates(t *testing.T) {
	// the spool builds gap records as a map; it must decode against SpoolGap
	e := Event{Kind: "spool.gap", Schema: 1, Fields: map[string]any{"from": uint64(3), "to": uint64(9), "count": uint64(7), "class": "bulk"}}
	if err := Validate(e); err != nil {
		t.Fatal(err)
	}
}

func TestNewCoreKindsValidate(t *testing.T) {
	for kind, v := range map[string]any{
		KindPlanFailed:           PlanFailed{Reason: ReasonDeadmanFired, Host: "h1", Plan: "p1", Node: "n1"},
		KindEnrollAlert:          EnrollAlert{Reason: ReasonHashMismatch, Host: "h1", Served: "aa", Reported: "bb"},
		KindOperatorEdit:         OperatorEdit{Module: "checks", Op: "edit", Subject: "http", Record: map[string]any{"service": "http"}, By: "david", At: "2026-11-07T14:00:00Z"},
		KindInventorySnapshot:    InventorySnapshot{Table: "accounts", Schema: 1, Epoch: 2, Reason: "baseline", Count: 1, CollectedAt: "2026-11-07T14:00:00Z"},
		KindInventoryRow:         InventoryRow{Table: "accounts", Epoch: 2, Op: "added", Key: "bob", Row: map[string]any{"name": "bob"}, CollectedAt: "2026-11-07T14:00:00Z"},
		KindInventoryProbeResult: InventoryProbeResult{Probe: "accounts_uid0", Host: "h1", Columns: []string{"name"}, CollectedAt: "2026-11-07T14:00:00Z"},
		KindControllerLocked:     ControllerLocked{Since: "2026-11-07T14:00:00Z", Stopped: []string{"auto plans"}},
		KindStoreQuota:           StoreQuota{UsedPct: 91, Shed: []string{"bulk"}},
	} {
		e, err := New(kind, v)
		if err != nil || Validate(e) != nil {
			t.Errorf("%s: %v", kind, err)
		}
	}
}

func TestNoShowAlertValidates(t *testing.T) {
	e, err := New(KindEnrollAlert, EnrollAlert{Reason: ReasonNoShow, Host: "h1", WindowSec: 600, Since: "2026-11-07T14:00:00Z"})
	if err != nil || Validate(e) != nil {
		t.Fatalf("%v", err)
	}
}
