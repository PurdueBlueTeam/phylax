package plan

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestBusyResultValidates(t *testing.T) {
	f := newFixture(t)
	st := f.issue(t, "baseline", IssueOpts{Phase: PhaseApply})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	exp, err := st.Expect()
	if err != nil {
		t.Fatal(err)
	}
	for _, outcome := range []string{OutcomeBusy, OutcomeVerified} {
		r, err := NewResult(st, outcome)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Sign(key); err != nil {
			t.Fatal(err)
		}
		if err := r.VerifyExpect(&key.PublicKey, exp); err != nil {
			t.Fatalf("%s refused: %v", outcome, err)
		}
	}
	r, err := NewResult(st, "bogus")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Sign(key); err != nil {
		t.Fatal(err)
	}
	if err := r.VerifyExpect(&key.PublicKey, exp); err == nil {
		t.Fatal("bogus outcome accepted")
	}
}
