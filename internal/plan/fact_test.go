package plan

import "testing"

func TestFactSender(t *testing.T) {
	for fact, mod := range map[string]string{"work_window": "teamfeed", "round_clock": "scorer", "gpo_finding": "ad", "scorer_probe_result": "checks", "creds_txn": "creds"} {
		if got, ok := FactSender(fact); !ok || got != mod {
			t.Errorf("%s: %s %v", fact, got, ok)
		}
	}
	if _, ok := FactSender("made_up"); ok {
		t.Error("unknown subtype")
	}
}
