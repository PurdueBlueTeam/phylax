package plan

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/link"
)

// Every signed field survives the trip through the typed link message; a
// field added to StepBody without a wire field fails here.
func TestStepWireRoundTripEveryField(t *testing.T) {
	f := newFixture(t)
	s := f.issue(t, "fw_shadow", IssueOpts{Secrets: []byte("sec"), RollbackData: []byte("rb")})
	// make every field non-zero so a dropped one is noticed
	typ := reflect.TypeOf(StepBody{})
	for i := 0; i < typ.NumField(); i++ {
		if reflect.ValueOf(s.StepBody).Field(i).IsZero() {
			t.Fatalf("fixture leaves %s zero", typ.Field(i).Name)
		}
	}
	w := StepToWire(s)
	b, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	m, err := link.Unmarshal(link.TypeStep, b)
	if err != nil {
		t.Fatal(err)
	}
	got := StepFromWire(m.(*link.Step))
	if !reflect.DeepEqual(s, got) {
		t.Fatalf("round trip changed the step:\n%+v\n%+v", s, got)
	}
	// and it still verifies, being rebuilt only from typed fields
	must(t, f.ver.Verify(got))
}

func TestControlSignVerifyAndRefusals(t *testing.T) {
	f := newFixture(t)
	now := t0
	sg := &ControlSigner{Key: f.signer.Key, Epoch: 1, Seqs: &MemSeq{}, Now: func() time.Time { return now }}
	st := FileSeqStore{Path: filepath.Join(t.TempDir(), "c.json")}
	v := &ControlVerifier{Key: f.pub, HostID: "h1", Store: st, Now: func() time.Time { return now }}
	c, err := sg.Issue("h1", ControlDeadmanConfirm, true, []byte(`{"plan":"p","node":"n"}`))
	if err != nil {
		t.Fatal(err)
	}
	// typed wire round trip
	w, _ := json.Marshal(ControlToWire(c))
	m, err := link.Unmarshal(link.TypeControl, w)
	if err != nil {
		t.Fatal(err)
	}
	rc := ControlFromWire(m.(*link.Control))
	must(t, v.Verify(rc))
	wantErr(t, v.Verify(rc), ErrReplay)

	// tamper every field
	typ := reflect.TypeOf(ControlBody{})
	for i := 0; i < typ.NumField(); i++ {
		c2, _ := sg.Issue("h1", ControlSafeMode, false, nil)
		fv := reflect.ValueOf(&c2.ControlBody).Elem().Field(i)
		switch fv.Kind() {
		case reflect.String:
			fv.SetString(fv.String() + "x")
		case reflect.Int:
			fv.SetInt(fv.Int() + 1)
		case reflect.Int64:
			fv.SetInt(fv.Int() + 1)
		case reflect.Uint64:
			fv.SetUint(fv.Uint() + 1)
		case reflect.Bool:
			fv.SetBool(!fv.Bool())
		case reflect.Slice:
			fv.SetBytes([]byte(`{"x":1}`))
		}
		if err := v.Verify(c2); err == nil || !strings.Contains(err.Error(), "bad signature") {
			t.Errorf("tampered %s: %v", typ.Field(i).Name, err)
		}
	}
	// other key, other host, expired, not yet valid, too long a window
	rogue := *sg
	rogue.Key = rogueKey(t)
	cr, _ := rogue.Issue("h1", ControlSafeMode, true, nil)
	wantErr(t, v.Verify(cr), ErrBadSignature)
	ch, _ := sg.Issue("h2", ControlSafeMode, true, nil)
	wantErr(t, v.Verify(ch), ErrWrongHost)
	ce, _ := sg.Issue("h1", ControlSafeMode, true, nil)
	now = now.Add(time.Hour)
	wantErr(t, v.Verify(ce), ErrExpired)
	now = t0
	late := *sg
	late.Now = func() time.Time { return t0.Add(time.Hour) }
	cl, _ := late.Issue("h1", ControlSafeMode, true, nil)
	wantErr(t, v.Verify(cl), ErrNotYetValid)
	long := *sg
	long.Validity = time.Hour
	cw, _ := long.Issue("h1", ControlSafeMode, true, nil)
	wantErr(t, v.Verify(cw), ErrMalformed)
	// a step signature is not a control signature (domain separation)
	step := f.issue(t, "fw_shadow", IssueOpts{})
	fake := &Control{ControlBody: ControlBody{V: 1, Host: "h1", Kind: "safe_mode", Args: json.RawMessage("{}"), Epoch: 1, Seq: 50,
		NotBefore: t0.Unix(), NotAfter: t0.Add(time.Minute).Unix()}, Sig: step.Sig}
	wantErr(t, v.Verify(fake), ErrBadSignature)
}

func TestRunRestoreAndLost(t *testing.T) {
	p := samplePlan()
	r := mkRun(t, p)
	r.ApprovePlan("alice", t0)
	st := r.Snapshot()
	r2 := mkRun(t, p)
	must(t, r2.Restore(st, nil, map[string]Approval{}))
	if !reflect.DeepEqual(r2.Snapshot(), st) {
		t.Fatal("restore changed states")
	}
	if err := r2.Restore(map[string]State{"nope": StateApplied}, nil, nil); err == nil {
		t.Fatal("restored an unknown node")
	}
	if err := r2.Restore(map[string]State{p.Nodes[0].ID: "weird"}, nil, nil); err == nil {
		t.Fatal("restored an unknown state")
	}
}

func rogueKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}
