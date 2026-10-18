package controller

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// TestSignStepRoundTrip: a step signed by the controller verifies against
// the plan public key shipped in bootstrap bundles, using the canonical
// string the agent recomputes.
func TestSignStepRoundTrip(t *testing.T) {
	c, err := New(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Store().Close()

	st := &link.Step{
		Plan:   "p1",
		Node:   "n1",
		Epoch:  1,
		Seq:    7,
		Op:     "run",
		Action: "file.write",
		Params: map[string]any{"path": "/tmp/x", "content": "hi"},
	}
	c.signStep(st)
	if st.Sig == "" {
		t.Fatal("empty signature")
	}
	pub, err := base64.StdEncoding.DecodeString(c.PlanKeyPub())
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("bad plan key pub: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(st.Sig)
	if err != nil {
		t.Fatal(err)
	}
	// the canonical string the agent recomputes from the wire step
	ps, _ := json.Marshal(st.Params)
	can := st.Plan + "|" + st.Node + "|" + strconv.Itoa(st.Epoch) + "|" +
		strconv.FormatUint(st.Seq, 10) + "|" + st.Op + "|" + st.Phase + "|" + st.Action + "|" + string(ps)
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(can), sig) {
		t.Fatal("signature does not verify against canonical string")
	}
	// plan.Canonical must agree with the wire form
	if got := plan.Canonical(st.Plan, st.Node, st.Epoch, st.Seq, st.Op, st.Phase, st.Action, st.Params); got != can {
		t.Fatalf("canonical mismatch:\n%q\n%q", got, can)
	}
}
