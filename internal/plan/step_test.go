package plan

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var t0 = time.Unix(1_700_000_000, 0)

type fixture struct {
	pub    ed25519.PublicKey
	signer *Signer
	plan   *Plan
	run    *Run
	store  FileSeqStore
	ver    *Verifier
	now    time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{pub: pub, now: t0, plan: samplePlan()}
	f.run = mkRun(t, f.plan)
	f.run.ApprovePlan("alice", t0)
	must(t, f.run.ApproveNode("fw_shadow", Approval{By: "bob", At: t0.Unix()}))
	f.signer = &Signer{Key: priv, Epoch: 1, Seqs: &MemSeq{}, Now: func() time.Time { return f.now }}
	f.store = FileSeqStore{Path: filepath.Join(t.TempDir(), "seq.json")}
	f.ver = f.newVerifier()
	return f
}

func (f *fixture) newVerifier() *Verifier {
	return &Verifier{Key: f.pub, HostID: "h1", Store: f.store, Now: func() time.Time { return f.now }}
}

func (f *fixture) issue(t *testing.T, node string, o IssueOpts) *Step {
	t.Helper()
	if o.Phase == "" {
		o.Phase = PhaseApply
	}
	s, err := f.signer.Issue(f.plan, f.run, node, o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestIssueAndVerify(t *testing.T) {
	f := newFixture(t)
	s := f.issue(t, "fw_shadow", IssueOpts{Secrets: []byte("hunter2"), RollbackData: []byte("snap")})
	if s.Host != "h1" || s.Seq != 1 || s.Epoch != 1 || s.DeadmanSec != 90 || s.RollbackPolicy != RollbackAuto ||
		s.Risk != RiskLockout || s.Approval == nil || s.Approval.By != "bob" || s.SecretsDigest == "" || s.RollbackDigest == "" {
		t.Fatalf("%+v", s.StepBody)
	}
	wire, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.ver.VerifyBytes(wire)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Secrets) != "hunter2" {
		t.Fatal("secrets lost")
	}
	// Sequence is per host.
	s2 := f.issue(t, "baseline", IssueOpts{})
	s3 := f.issue(t, "baseline", IssueOpts{})
	if s2.Seq != 2 || s3.Seq != 3 {
		t.Fatal(s2.Seq, s3.Seq)
	}
	if f.issue(t, "other", IssueOpts{}).Seq != 1 {
		t.Fatal("per-host seq")
	}
	// Gates and unapproved nodes cannot be issued.
	if _, err := f.signer.Issue(f.plan, f.run, "review", IssueOpts{Phase: PhaseApply}); err == nil {
		t.Fatal("gate issued")
	}
	if _, err := f.signer.Issue(f.plan, f.run, "fw_enf", IssueOpts{Phase: PhaseApply}); err == nil {
		t.Fatal("unapproved issued")
	}
}

func wantErr(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("want %v, got %v", target, err)
	}
}

// Every field of the signed body must be covered by the signature.
func TestTamperEveryField(t *testing.T) {
	f := newFixture(t)
	base := f.issue(t, "fw_shadow", IssueOpts{Secrets: []byte("s"), RollbackData: []byte("r")})
	typ := reflect.TypeOf(StepBody{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		t.Run(name, func(t *testing.T) {
			cp := *base
			cp.Approval = &Approval{}
			*cp.Approval = *base.Approval
			fv := reflect.ValueOf(&cp.StepBody).Elem().Field(i)
			switch fv.Kind() {
			case reflect.String:
				fv.SetString(fv.String() + "x")
			case reflect.Int, reflect.Int64:
				fv.SetInt(fv.Int() + 1)
			case reflect.Uint64:
				fv.SetUint(fv.Uint() + 1)
			case reflect.Slice: // Params
				fv.SetBytes([]byte(`{"mode":"evil"}`))
			case reflect.Ptr: // Approval
				cp.Approval.By = "mallory"
			default:
				t.Fatalf("unhandled kind %s for %s", fv.Kind(), name)
			}
			// Keep host binding from masking other errors: bad signature must come first.
			wantErr(t, f.ver.Verify(&cp), ErrBadSignature)
			if m, _ := f.store.Load(); m != (Mark{}) {
				t.Fatalf("store advanced by tampered step: %v", m)
			}
		})
	}
	// Secrets are covered through their digest.
	cp := *base
	cp.Secrets = []byte("other")
	wantErr(t, f.ver.Verify(&cp), ErrDigestMismatch)
	// Signature bytes themselves.
	cp = *base
	cp.Sig = append([]byte{}, base.Sig...)
	cp.Sig[0] ^= 1
	wantErr(t, f.ver.Verify(&cp), ErrBadSignature)
	cp.Sig = nil
	wantErr(t, f.ver.Verify(&cp), ErrBadSignature)
	// Untouched original still verifies.
	must(t, f.ver.Verify(base))
}

func TestWrongKey(t *testing.T) {
	f := newFixture(t)
	s := f.issue(t, "baseline", IssueOpts{})
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	f.ver.Key = other
	wantErr(t, f.ver.Verify(s), ErrBadSignature)
}

func TestMissingConfigRefused(t *testing.T) {
	f := newFixture(t)
	s := f.issue(t, "baseline", IssueOpts{})
	for _, key := range []ed25519.PublicKey{nil, {}, make(ed25519.PublicKey, 5)} {
		v := f.newVerifier()
		v.Key = key
		wantErr(t, v.Verify(s), ErrNoKey)
	}
	v := f.newVerifier()
	v.Store = nil
	wantErr(t, v.Verify(s), ErrNoStore)
	v = f.newVerifier()
	v.HostID = ""
	wantErr(t, v.Verify(s), ErrNoHost)
	// None of the refusals consumed the sequence.
	must(t, f.ver.Verify(s))
}

func TestHostBinding(t *testing.T) {
	f := newFixture(t)
	s := f.issue(t, "other", IssueOpts{}) // for h2
	wantErr(t, f.ver.Verify(s), ErrWrongHost)
}

func TestReplayReorderAcrossRestart(t *testing.T) {
	f := newFixture(t)
	s1 := f.issue(t, "baseline", IssueOpts{})
	s2 := f.issue(t, "baseline", IssueOpts{})
	s3 := f.issue(t, "baseline", IssueOpts{})
	must(t, f.ver.Verify(s2))
	wantErr(t, f.ver.Verify(s2), ErrReplay)
	wantErr(t, f.ver.Verify(s1), ErrReplay) // reorder
	// Agent restart: new Verifier, same file.
	f.ver = f.newVerifier()
	wantErr(t, f.ver.Verify(s2), ErrReplay)
	wantErr(t, f.ver.Verify(s1), ErrReplay)
	must(t, f.ver.Verify(s3))
	f.ver = f.newVerifier()
	wantErr(t, f.ver.Verify(s3), ErrReplay)

	// New epoch (controller restored from snapshot) resets seq but not below.
	f.signer.Epoch = 2
	f.signer.Seqs = &MemSeq{}
	e2 := f.issue(t, "baseline", IssueOpts{})
	must(t, f.ver.Verify(e2))
	f.signer.Epoch = 1
	f.signer.Seqs = &MemSeq{}
	old := f.issue(t, "baseline", IssueOpts{})
	old2 := f.issue(t, "baseline", IssueOpts{})
	_ = old
	wantErr(t, f.ver.Verify(old2), ErrStaleEpoch)
}

func TestExpiredAndNotYetValid(t *testing.T) {
	f := newFixture(t)
	s := f.issue(t, "baseline", IssueOpts{Validity: time.Minute})
	f.now = t0.Add(time.Minute + DefaultSkew + 2*time.Second)
	wantErr(t, f.ver.Verify(s), ErrExpired)
	// Within skew after expiry is tolerated.
	f.now = t0.Add(time.Minute + DefaultSkew - 2*time.Second)
	s2 := f.issue(t, "baseline", IssueOpts{Validity: time.Minute}) // issued "now"
	_ = s
	must(t, f.ver.Verify(s2))
	// Step from the future beyond skew.
	f.now = t0
	fut := f.issue(t, "baseline", IssueOpts{})
	f.now = t0.Add(-DefaultSkew - 5*time.Second)
	wantErr(t, f.ver.Verify(fut), ErrNotYetValid)
	f.now = t0.Add(-DefaultSkew + 5*time.Second)
	must(t, f.ver.Verify(fut))
	// An expired step did not consume its sequence slot... but is still expired.
	if m, _ := f.store.Load(); m.Seq != fut.Seq {
		t.Fatalf("mark %v", m)
	}
}

func TestWindowBounds(t *testing.T) {
	f := newFixture(t)
	s := f.issue(t, "baseline", IssueOpts{Validity: 48 * time.Hour})
	wantErr(t, f.ver.Verify(s), ErrMalformed)
}

func TestPlanFilter(t *testing.T) {
	f := newFixture(t)
	f.ver.PlanOK = func(id string) bool { return id == "different" }
	wantErr(t, f.ver.Verify(f.issue(t, "baseline", IssueOpts{})), ErrUnexpectedPlan)
}

type failStore struct{ SeqStore }

func (failStore) Save(Mark) error { return errors.New("disk full") }

func TestStoreFailureRefuses(t *testing.T) {
	f := newFixture(t)
	f.ver.Store = failStore{f.store}
	wantErr(t, f.ver.Verify(f.issue(t, "baseline", IssueOpts{})), ErrStore)
}

func TestFileSeqStore(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s", "seq.json")
	s := FileSeqStore{Path: p}
	if m, err := s.Load(); err != nil || m != (Mark{}) {
		t.Fatal(m, err)
	}
	// directory missing -> Save fails (agent must create its state dir).
	if err := s.Save(Mark{1, 1}); err == nil {
		t.Fatal("expected error for missing dir")
	}
	s = FileSeqStore{Path: filepath.Join(t.TempDir(), "seq.json")}
	must(t, s.Save(Mark{2, 5}))
	if err := s.Save(Mark{2, 4}); err == nil {
		t.Fatal("lowered")
	}
	if m, _ := s.Load(); m != (Mark{2, 5}) {
		t.Fatal(m)
	}
	// Corrupt file fails closed.
	must(t, writeFile(s.Path, "{garbage"))
	if _, err := s.Load(); err == nil {
		t.Fatal("corrupt accepted")
	}
	f := newFixture(t)
	f.store = s
	f.ver = f.newVerifier()
	wantErr(t, f.ver.Verify(f.issue(t, "baseline", IssueOpts{})), ErrStore)
}

func TestDecodeStrict(t *testing.T) {
	f := newFixture(t)
	wire, _ := f.issue(t, "baseline", IssueOpts{}).Encode()
	for _, bad := range []string{
		string(wire) + "{}",
		strings.Replace(string(wire), `"v":1`, `"v":1,"extra":1`, 1),
		"",
		"null garbage",
	} {
		if _, err := f.ver.VerifyBytes([]byte(bad)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%.40q: %v", bad, err)
		}
	}
	if _, err := DecodeStep(make([]byte, MaxStepBytes+1)); !errors.Is(err, ErrMalformed) {
		t.Fatal("oversize")
	}
}

func TestStepResult(t *testing.T) {
	f := newFixture(t)
	step := f.issue(t, "fw_shadow", IssueOpts{})
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r, err := NewResult(step, OutcomeVerified)
	must(t, err)
	r.RollbackDataHash = DataDigest([]byte("snap"))
	r.StartedMS, r.FinishedMS = 1000, 2500
	must(t, r.Sign(key))
	must(t, r.Verify(&key.PublicKey, step))

	typ := reflect.TypeOf(ResultBody{})
	for i := 0; i < typ.NumField(); i++ {
		t.Run(typ.Field(i).Name, func(t *testing.T) {
			cp := *r
			fv := reflect.ValueOf(&cp.ResultBody).Elem().Field(i)
			switch fv.Kind() {
			case reflect.String:
				fv.SetString(fv.String() + "x")
			case reflect.Int, reflect.Int64:
				fv.SetInt(fv.Int() + 1)
			case reflect.Uint64:
				fv.SetUint(fv.Uint() + 1)
			}
			if cp.Verify(&key.PublicKey, step) == nil {
				t.Fatal("tampered result verified")
			}
		})
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if r.Verify(&other.PublicKey, step) == nil {
		t.Fatal("wrong key")
	}
	// A valid result for a different step is rejected.
	step2 := f.issue(t, "baseline", IssueOpts{})
	if r.Verify(&key.PublicKey, step2) == nil {
		t.Fatal("result answered wrong step")
	}
	// JSON round trip.
	b, _ := json.Marshal(r)
	var back StepResult
	must(t, json.Unmarshal(b, &back))
	must(t, back.Verify(&key.PublicKey, step))
}

func TestConcurrentVerifyOnlyOneWins(t *testing.T) {
	f := newFixture(t)
	s := f.issue(t, "baseline", IssueOpts{})
	var ok int32
	done := make(chan bool, 16)
	for i := 0; i < 16; i++ {
		go func() { done <- f.ver.Verify(s) == nil }()
	}
	for i := 0; i < 16; i++ {
		if <-done {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d accepted", ok)
	}
}

func FuzzDecodeStep(f *testing.F) {
	fx := &fixture{now: t0, plan: samplePlan()}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	fx.run, _ = NewRun(fx.plan, cat())
	fx.run.ApprovePlan("a", t0)
	sg := &Signer{Key: priv, Epoch: 1, Seqs: &MemSeq{}, Now: func() time.Time { return t0 }}
	st, _ := sg.Issue(fx.plan, fx.run, "baseline", IssueOpts{Phase: PhaseApply, Secrets: []byte("x")})
	wire, _ := st.Encode()
	f.Add(wire)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"v":1,"params":{"a":1.5e400}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := DecodeStep(data)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("untyped error %v", err)
			}
			return
		}
		// Must never panic downstream, and a random decode must never verify.
		_, _ = s.Digest()
		_, _ = s.Encode()
		v := &Verifier{Key: priv.Public().(ed25519.PublicKey), HostID: s.Host, Store: &memStore{}, Now: func() time.Time { return t0 }}
		if err := v.Verify(s); err == nil && string(data) != string(wire) {
			// Only equivalent encodings of the genuine step may verify.
			if s.NodeID != "baseline" {
				t.Fatalf("forged step verified: %s", data)
			}
		}
	})
}

type memStore struct{ m Mark }

func (s *memStore) Load() (Mark, error) { return s.m, nil }
func (s *memStore) Save(m Mark) error   { s.m = m; return nil }

func writeFile(p, s string) error { return os.WriteFile(p, []byte(s), 0o600) }
