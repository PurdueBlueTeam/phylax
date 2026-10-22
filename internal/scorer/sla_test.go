package scorer

import "testing"

func fails(tr *SLATracker, svc string, from, n int) (alerts []SLAAlert) {
	for r := from; r < from+n; r++ {
		alerts = append(alerts, tr.ObserveRound(r, map[string]Outcome{svc: OutcomeFail})...)
	}
	return
}

func TestSLAStreakAlertsAndReset(t *testing.T) {
	tr := NewSLATracker(SLAConfig{Threshold: 5})
	al := fails(tr, "web", 1, 5)
	if len(al) != 3 || al[0].Level != AlertWarn || al[0].Streak != 3 || al[1].Level != AlertCritical || al[2].Level != AlertPenalty {
		t.Fatalf("alerts: %+v", al)
	}
	if tr.Streak("web") != 0 || tr.Penalties("web") != 1 {
		t.Fatalf("after penalty streak %d pens %d", tr.Streak("web"), tr.Penalties("web"))
	}
	// A pass resets mid-streak; no further alert.
	fails(tr, "web", 6, 2)
	tr.ObserveRound(8, map[string]Outcome{"web": OutcomePass})
	if tr.Streak("web") != 0 {
		t.Fatal("pass did not reset")
	}
	// Unknown (silence) neither advances nor resets.
	fails(tr, "web", 9, 2)
	tr.ObserveRound(11, map[string]Outcome{"web": OutcomeUnknown})
	if tr.Streak("web") != 2 {
		t.Fatalf("unknown changed streak: %d", tr.Streak("web"))
	}
}

func TestSLADiscardedRoundFreezes(t *testing.T) {
	tr := NewSLATracker(SLAConfig{Threshold: 5})
	fails(tr, "web", 1, 2)
	tr.Discard(3) // dropped before it was observed
	if al := fails(tr, "web", 3, 1); len(al) != 0 || tr.Streak("web") != 2 {
		t.Fatalf("discarded round advanced the streak: %d %v", tr.Streak("web"), al)
	}
	// A pass in a discarded round must not reset either.
	tr.Discard(4)
	tr.ObserveRound(4, map[string]Outcome{"web": OutcomePass})
	if tr.Streak("web") != 2 {
		t.Fatalf("discarded pass reset the streak: %d", tr.Streak("web"))
	}
	// Retroactive discard: 3 failures then the last found discarded.
	tr2 := NewSLATracker(SLAConfig{Threshold: 5})
	fails(tr2, "ssh", 1, 3)
	tr2.Discard(3)
	if tr2.Streak("ssh") != 2 {
		t.Fatalf("retroactive discard: %d", tr2.Streak("ssh"))
	}
	// Retroactive discard can undo a penalty.
	tr3 := NewSLATracker(SLAConfig{Threshold: 3})
	fails(tr3, "x", 1, 3)
	if tr3.Penalties("x") != 1 {
		t.Fatal("setup")
	}
	tr3.Discard(2)
	if tr3.Penalties("x") != 0 || tr3.Streak("x") != 2 {
		t.Fatalf("pens %d streak %d", tr3.Penalties("x"), tr3.Streak("x"))
	}
}

func TestSLAOperatorVerdictOverrides(t *testing.T) {
	tr := NewSLATracker(SLAConfig{Threshold: 5})
	fails(tr, "smtp", 1, 3)
	al := tr.Verdict(3, "smtp", true) // inference said fail, portal says up
	if tr.Streak("smtp") != 0 {
		t.Fatalf("verdict ignored: %d", tr.Streak("smtp"))
	}
	_ = al
	if a, d := tr.Calibration(); a != 0 || d != 1 {
		t.Fatalf("calibration %d/%d", a, d)
	}
	tr.Verdict(2, "smtp", false)
	if a, _ := tr.Calibration(); a != 1 {
		t.Fatal("agreement not counted")
	}
	// Verdict for a round we never observed adds it.
	al = tr.Verdict(10, "smtp", false)
	if tr.Streak("smtp") != 1 || len(al) != 0 {
		t.Fatalf("%d %v", tr.Streak("smtp"), al)
	}
	tr.SetThreshold(3)
	if tr.Threshold() != 3 {
		t.Fatal("threshold")
	}
}

func TestSLAPerServiceIndependent(t *testing.T) {
	tr := NewSLATracker(SLAConfig{})
	tr.ObserveRound(1, map[string]Outcome{"a": OutcomeFail, "b": OutcomePass})
	tr.ObserveRound(2, map[string]Outcome{"a": OutcomeFail, "b": OutcomeFail})
	if tr.Streak("a") != 2 || tr.Streak("b") != 1 || tr.Streak("none") != 0 {
		t.Fatal("independence")
	}
}

func TestSLALogTrimFoldsState(t *testing.T) {
	tr := NewSLATracker(SLAConfig{Threshold: 5, MaxRounds: 4})
	fails(tr, "w", 1, 12)
	if tr.Penalties("w") != 2 || tr.Streak("w") != 2 {
		t.Fatalf("pens %d streak %d", tr.Penalties("w"), tr.Streak("w"))
	}
}
