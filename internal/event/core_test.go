package event

import "testing"

var coreAlert = map[string]bool{"agent.deadman_fired": true, "agent.silent": true, "enroll.key_mismatch": true,
	"enroll.key_reuse": true, "plan.deadman_fired": true, "plan.rollback_failed": true, "plan.restore_failed": true,
	"plan.confirm_failed": true, "plan.auto_halted": true}

func TestCoreKindsDeclared(t *testing.T) {
	kinds := []string{"agent.start", "agent.health", "agent.step", "agent.step_result", "agent.step_refused", "evidence.blob",
		"agent.config_applied", "agent.config_rejected", "agent.control_refused", "agent.module_crash", "controller.fact",
		"agent.deadman_fired", "agent.deadman_recovered", "agent.deadman_recovery_error", "agent.enrolled", "agent.reenrolled",
		"agent.silent", "agent.resumed", "spool.gap", "enroll.refused", "enroll.key_mismatch", "enroll.key_reuse",
		"plan.step_timeout", "plan.bad_result", "plan.deadman_fired", "plan.rollback_failed", "plan.restore_failed",
		"plan.confirm_failed", "plan.auto_halted"}
	if len(kinds) != 29 {
		t.Fatal("table has 29 core kinds")
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
