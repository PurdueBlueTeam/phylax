package event

import "testing"

var coreAlert = map[string]bool{"agent.deadman_fired": true, "agent.silent": true, "enroll.refused": true,
	"enroll.key_mismatch": true, "enroll.key_reuse": true, "enroll.hash_mismatch": true, "enroll.no_show": true,
	"controller.locked": true, "store.quota": true,
	"plan.deadman_fired": true, "plan.rollback_failed": true, "plan.restore_failed": true,
	"plan.confirm_failed": true, "plan.auto_halted": true}

func TestCoreKindsDeclared(t *testing.T) {
	kinds := []string{"agent.start", "agent.health", "agent.step", "agent.step_result", "agent.step_refused", "evidence.blob",
		"agent.config_applied", "agent.config_rejected", "agent.control_refused", "agent.module_crash", "controller.fact",
		"agent.deadman_fired", "agent.deadman_recovered", "agent.deadman_recovery_error", "agent.enrolled", "agent.reenrolled",
		"agent.silent", "agent.resumed", "spool.gap", "enroll.refused", "enroll.key_mismatch", "enroll.key_reuse",
		"enroll.hash_mismatch", "enroll.no_show", "controller.locked", "store.quota",
		"plan.step_timeout", "plan.bad_result", "plan.deadman_fired", "plan.rollback_failed", "plan.restore_failed",
		"plan.confirm_failed", "plan.auto_halted"}
	if len(kinds) != 33 {
		t.Fatal("table has 33 core kinds")
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
		KindEnrollHashMismatch: EnrollHashMismatch{Host: "h1", Served: "aa", Reported: "bb"},
		KindEnrollNoShow:       EnrollNoShow{Host: "h1", WindowSec: 600, Since: "2026-11-07T14:00:00Z"},
		KindControllerLocked:   ControllerLocked{Since: "2026-11-07T14:00:00Z", Stopped: []string{"auto plans"}},
		KindStoreQuota:         StoreQuota{Level: "bulk", UsedPct: 91, Shed: []string{"bulk"}},
	} {
		e, err := New(kind, v)
		if err != nil || Validate(e) != nil {
			t.Errorf("%s: %v", kind, err)
		}
	}
}
