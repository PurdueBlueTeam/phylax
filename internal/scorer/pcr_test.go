package scorer

import (
	"context"
	"errors"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/creds"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

type fakeHost struct {
	changes, reverts []string
	failChange       bool
}

func (h *fakeHost) Change(_ context.Context, a string, _ []string, p vault.Secret) error {
	if h.failChange {
		return errors.New("winrm timeout")
	}
	h.changes = append(h.changes, a)
	return nil
}
func (h *fakeHost) Revert(_ context.Context, a string, _ []string, p vault.Secret) error {
	h.reverts = append(h.reverts, a)
	return nil
}

type fakeSub struct {
	reply PCRReply
	err   error
	got   []string
}

func (s *fakeSub) Submit(_ context.Context, path, csv string) (PCRReply, error) {
	s.got = append(s.got, path+"|"+csv)
	return s.reply, s.err
}

type fakeVer struct{ err error }

func (v fakeVer) Login(context.Context, string, vault.Secret) error { return v.err }

func burstAt(e *Estimator, s time.Time) {
	for j := 0; j < 16; j++ {
		e.Observe(s.Add(time.Duration(j*2) * time.Millisecond))
	}
}

// rig builds an estimator with 30 learned rounds (60+-5) and returns the last burst start.
func rig(t *testing.T) (*Estimator, time.Time) {
	t.Helper()
	e := NewEstimator(ClockConfig{})
	starts := feed(e, rand.New(rand.NewSource(11)), 30, 60, 5, 0, 0)
	return e, starts[len(starts)-1]
}

func pw(t *testing.T, user string) vault.Secret {
	t.Helper()
	s, err := Generate(creds.NewGenerator(), user)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func plan(t *testing.T, en *Engine, user string, now time.Time) Txn {
	t.Helper()
	tx, err := en.Plan(PlanRequest{Account: user, CredlistPath: "/creds/linux.csv", Hosts: []string{"h1", "h2"},
		OldPass: pw(t, user), NewPass: pw(t, user)}, now)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestPCRHappyPathHumanInTheLoop(t *testing.T) {
	e, last := rig(t)
	host, sub := &fakeHost{}, &fakeSub{}
	en := NewEngine(PCRConfig{}, e, host, sub, nil)
	tx := plan(t, en, "alice", last)
	if err := en.CanRotate("alice"); !errors.Is(err, ErrPCRPending) {
		t.Fatal("planned txn must block rotation")
	}
	if _, err := en.Plan(PlanRequest{Account: "alice", CredlistPath: "/c", Hosts: []string{"h"}, NewPass: pw(t, "alice")}, last); !errors.Is(err, ErrPCRPending) {
		t.Fatal("second plan for same account accepted")
	}
	// Inside the burst: refused, nothing changed.
	var nw NotInWindowError
	if err := en.ApplyHost(context.Background(), tx.ID, last.Add(500*time.Millisecond)); !errors.As(err, &nw) || len(host.changes) != 0 {
		t.Fatalf("applied during burst: %v", err)
	}
	now := last.Add(10 * time.Second)
	if err := en.ApplyHost(context.Background(), tx.ID, now); err != nil {
		t.Fatal(err)
	}
	s, err := en.Prepare([]string{tx.ID})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s.Block.Text, "alice,") || s.Path != "/creds/linux.csv" {
		t.Fatalf("csv %+v", s)
	}
	if err := en.Submit(context.Background(), s.ID, now); !errors.Is(err, ErrScriptedDisabled) || len(sub.got) != 0 {
		t.Fatal("scripted path must be off by default")
	}
	if err := en.ConfirmSubmission(s.ID, PCRReply{Count: 1}, now.Add(15*time.Second)); err != nil {
		t.Fatal(err)
	}
	got, _ := en.Get(tx.ID)
	if got.State != StatePCRSubmitted || got.Race || !en.Pending("alice") {
		t.Fatalf("%+v", got)
	}
	// Old-snapshot burst evidence is ignored; a later pass verifies.
	if c := en.ObserveScorerLogin("alice", false, got.SubmitBurstSeq, now); len(c) != 0 {
		t.Fatal("stale burst counted")
	}
	if c := en.ObserveScorerLogin("alice", true, got.SubmitBurstSeq+1, now.Add(40*time.Second)); len(c) != 1 {
		t.Fatal("not verified")
	}
	got, _ = en.Get(tx.ID)
	if got.State != StateVerified || en.Pending("alice") || en.CanRotate("alice") != nil {
		t.Fatalf("%+v", got)
	}
	var rec creds.Record
	if err := en.SyncRecord(tx.ID, &rec); err != nil || rec.PCRState != creds.PCRConfirmed || rec.PCRRef != tx.ID {
		t.Fatalf("%+v %v", rec, err)
	}
	if strings.Contains(fmtAll(got), got.NewPass.Reveal()) {
		t.Fatal("secret leaked through formatting")
	}
}

func fmtAll(tx Txn) string {
	return strings.Join([]string{sprint(tx), sprint(&tx)}, " ")
}

func TestPCRRefusals(t *testing.T) {
	e, last := rig(t)
	en := NewEngine(PCRConfig{}, e, &fakeHost{}, nil, nil)
	if _, err := en.Plan(PlanRequest{Account: "a", Hosts: []string{"h"}, NewPass: pw(t, "a")}, last); !errors.Is(err, ErrNoCredlist) {
		t.Fatal("host-only change accepted")
	}
	if _, err := en.Plan(PlanRequest{Account: "a", CredlistPath: "/c", Hosts: []string{"h"}, NewPass: vault.NewSecretString("short,pw")}, last); err == nil {
		t.Fatal("unsafe password accepted")
	}
	tx := plan(t, en, "bob", last)
	// 40s in: the 30s needed does not fit before the earliest next burst.
	var nw NotInWindowError
	if err := en.ApplyHost(context.Background(), tx.ID, last.Add(40*time.Second)); !errors.As(err, &nw) {
		t.Fatalf("late window accepted: %v", err)
	}
	// Unknown clock.
	en2 := NewEngine(PCRConfig{}, NewEstimator(ClockConfig{}), &fakeHost{}, nil, nil)
	tx2 := plan(t, en2, "bob", last)
	if err := en2.ApplyHost(context.Background(), tx2.ID, last); !errors.As(err, &nw) {
		t.Fatal("unknown clock accepted")
	}
	// Low confidence: 10 bursts is provisional-free but only just.
	e3 := NewEstimator(ClockConfig{})
	st := feed(e3, rand.New(rand.NewSource(2)), 4, 60, 5, 0, 0)
	en3 := NewEngine(PCRConfig{}, e3, &fakeHost{}, nil, nil)
	tx3 := plan(t, en3, "bob", st[3])
	var lc LowConfidenceError
	if err := en3.ApplyHost(context.Background(), tx3.ID, st[3].Add(10*time.Second)); !errors.As(err, &lc) {
		t.Fatalf("low confidence accepted: %v", err)
	}
	en4 := NewEngine(PCRConfig{AllowLowConfidence: true}, e3, &fakeHost{}, nil, nil)
	tx4 := plan(t, en4, "bob", st[3])
	if err := en4.ApplyHost(context.Background(), tx4.ID, st[3].Add(10*time.Second)); err != nil {
		t.Fatalf("override failed: %v", err)
	}
}

func TestPCRHostChangeFailureRollsBack(t *testing.T) {
	e, last := rig(t)
	host := &fakeHost{failChange: true}
	en := NewEngine(PCRConfig{}, e, host, nil, nil)
	tx := plan(t, en, "alice", last)
	if err := en.ApplyHost(context.Background(), tx.ID, last.Add(10*time.Second)); err == nil {
		t.Fatal("want error")
	}
	got, _ := en.Get(tx.ID)
	if got.State != StateRolledBack || len(host.reverts) != 1 || en.Pending("alice") {
		t.Fatalf("%+v", got)
	}
}

func TestPCRScriptedPath(t *testing.T) {
	e, last := rig(t)
	host, sub := &fakeHost{}, &fakeSub{reply: PCRReply{Count: 2}}
	en := NewEngine(PCRConfig{Scripted: true}, e, host, sub, nil)
	a, b := plan(t, en, "alice", last), plan(t, en, "bob", last)
	now := last.Add(10 * time.Second)
	for _, id := range []string{a.ID, b.ID} {
		if err := en.ApplyHost(context.Background(), id, now); err != nil {
			t.Fatal(err)
		}
	}
	s, err := en.Prepare([]string{a.ID, b.ID})
	if err != nil {
		t.Fatal(err)
	}
	// Not inside a burst or too late.
	if err := en.Submit(context.Background(), s.ID, last.Add(45*time.Second)); err == nil {
		t.Fatal("scripted submit outside the window")
	}
	if err := en.Submit(context.Background(), s.ID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(sub.got) != 1 || strings.Count(sub.got[0], "\n") != 1 {
		t.Fatalf("%v", sub.got)
	}
	if x, _ := en.Get(a.ID); x.State != StatePCRSubmitted {
		t.Fatal(x.State)
	}
}

func TestPCRReplyMismatchSkipped(t *testing.T) {
	e, last := rig(t)
	host := &fakeHost{}
	en := NewEngine(PCRConfig{}, e, host, nil, nil)
	a, b := plan(t, en, "alice", last), plan(t, en, "Bob", last)
	now := last.Add(10 * time.Second)
	_ = en.ApplyHost(context.Background(), a.ID, now)
	_ = en.ApplyHost(context.Background(), b.ID, now)
	s, _ := en.Prepare([]string{a.ID, b.ID})
	err := en.ConfirmSubmission(s.ID, PCRReply{Count: 1, Skipped: []string{"Bob"}}, now.Add(5*time.Second))
	if !errors.Is(err, ErrReplyMismatch) {
		t.Fatalf("err %v", err)
	}
	ga, _ := en.Get(a.ID)
	gb, _ := en.Get(b.ID)
	if ga.State != StatePCRSubmitted || gb.State != StateFailed || gb.PCRUnknown || gb.PCRApplied {
		t.Fatalf("alice %s bob %s %+v", ga.State, gb.State, gb)
	}
	// Bob's PCR never applied: rollback reverts the host only, no CSV.
	rs, err := en.Rollback(context.Background(), b.ID, now.Add(6*time.Second))
	if err != nil || rs != nil {
		t.Fatalf("%v %v", rs, err)
	}
	if gb, _ = en.Get(b.ID); gb.State != StateRolledBack || len(host.reverts) != 1 {
		t.Fatalf("%+v", gb)
	}
}

func TestPCRAmbiguousCountRollbackResubmitsOldValue(t *testing.T) {
	e, last := rig(t)
	host := &fakeHost{}
	en := NewEngine(PCRConfig{}, e, host, nil, nil)
	a := plan(t, en, "alice", last)
	now := last.Add(10 * time.Second)
	_ = en.ApplyHost(context.Background(), a.ID, now)
	s, _ := en.Prepare([]string{a.ID})
	if err := en.ConfirmSubmission(s.ID, PCRReply{Count: 0}, now.Add(2*time.Second)); !errors.Is(err, ErrReplyMismatch) {
		t.Fatal(err)
	}
	ga, _ := en.Get(a.ID)
	if ga.State != StateFailed || !ga.PCRUnknown {
		t.Fatalf("%+v", ga)
	}
	// Rollback refused outside the window.
	if _, err := en.Rollback(context.Background(), a.ID, last.Add(500*time.Millisecond)); err == nil {
		t.Fatal("rollback inside burst")
	}
	rs, err := en.Rollback(context.Background(), a.ID, now.Add(3*time.Second))
	if err != nil || rs == nil || !rs.Rollback {
		t.Fatalf("%v %v", rs, err)
	}
	if !strings.HasPrefix(rs.Block.Text, "alice,"+a.OldPass.Reveal()) || strings.Contains(rs.Block.Text, a.NewPass.Reveal()) {
		t.Fatal("rollback CSV must carry the OLD value")
	}
	if got, _ := en.Get(a.ID); got.State != StateFailed || !got.HostReverted {
		t.Fatalf("host revert recorded, PCR rollback pending: %+v", got)
	}
	if err := en.ConfirmSubmission(rs.ID, PCRReply{Count: 1}, now.Add(20*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got, _ := en.Get(a.ID); got.State != StateRolledBack || en.Pending("alice") {
		t.Fatalf("%+v", got)
	}
}

// The enqueue race: the PCR lands while the next round is being enqueued.
func TestPCREnqueueRace(t *testing.T) {
	for _, race := range []bool{false, true} {
		e, last := rig(t)
		en := NewEngine(PCRConfig{}, e, &fakeHost{}, nil, nil)
		a := plan(t, en, "alice", last)
		now := last.Add(10 * time.Second)
		_ = en.ApplyHost(context.Background(), a.ID, now)
		s, _ := en.Prepare([]string{a.ID})
		next := last.Add(62 * time.Second)
		burstAt(e, next)
		at := now.Add(5 * time.Second)
		if race {
			at = next.Add(-300 * time.Millisecond) // inside the enqueue pad, before the burst's connections
		}
		if err := en.ConfirmSubmission(s.ID, PCRReply{Count: 1}, at); err != nil {
			t.Fatal(err)
		}
		g, _ := en.Get(a.ID)
		if g.Race != race {
			t.Fatalf("race=%v flagged %v", race, g.Race)
		}
		if race && g.SubmitBurstSeq != e.BurstSeqAt(last.Add(time.Second)) {
			t.Fatal("the racing burst must not be treated as already past")
		}
		burstSeq := g.SubmitBurstSeq + 1
		en.ObserveScorerLogin("alice", false, burstSeq, next.Add(time.Second))
		g, _ = en.Get(a.ID)
		if race && (g.State != StatePCRSubmitted || !g.Tolerated) {
			t.Fatalf("race: first failure should be forgiven: %+v", g)
		}
		if !race && g.State != StateFailed {
			t.Fatalf("no race: failure must fail: %s", g.State)
		}
		if race { // a second failed burst is real
			en.ObserveScorerLogin("alice", false, burstSeq+1, next.Add(time.Minute))
			if g, _ = en.Get(a.ID); g.State != StateFailed {
				t.Fatalf("second failure: %s", g.State)
			}
		}
	}
}

func TestPCRKaliVerification(t *testing.T) {
	e, last := rig(t)
	en := NewEngine(PCRConfig{}, e, &fakeHost{}, nil, fakeVer{})
	a := plan(t, en, "alice", last)
	now := last.Add(10 * time.Second)
	_ = en.ApplyHost(context.Background(), a.ID, now)
	s, _ := en.Prepare([]string{a.ID})
	_ = en.ConfirmSubmission(s.ID, PCRReply{Count: 1}, now.Add(time.Second))
	g, _ := en.Get(a.ID)
	en.ObserveScorerLogin("alice", true, g.SubmitBurstSeq+1, now)
	if g, _ = en.Get(a.ID); g.State != StatePCRSubmitted || g.CredsState() != creds.PCRVerifying {
		t.Fatalf("scorer pass alone must not verify when the Kali check is configured: %+v", g.State)
	}
	if err := en.Verify(context.Background(), a.ID, now); err != nil {
		t.Fatal(err)
	}
	if g, _ = en.Get(a.ID); g.State != StateVerified {
		t.Fatal(g.State)
	}
	// Kali failure => failed.
	e2, last2 := rig(t)
	en2 := NewEngine(PCRConfig{}, e2, &fakeHost{}, nil, fakeVer{errors.New("denied")})
	b := plan(t, en2, "bob", last2)
	n2 := last2.Add(10 * time.Second)
	_ = en2.ApplyHost(context.Background(), b.ID, n2)
	s2, _ := en2.Prepare([]string{b.ID})
	_ = en2.ConfirmSubmission(s2.ID, PCRReply{Count: 1}, n2)
	if err := en2.Verify(context.Background(), b.ID, n2); err == nil {
		t.Fatal("want error")
	}
	if g, _ := en2.Get(b.ID); g.State != StateFailed {
		t.Fatal(g.State)
	}
}

func TestPCRTickNotices(t *testing.T) {
	e, last := rig(t)
	en := NewEngine(PCRConfig{}, e, &fakeHost{}, nil, nil)
	a := plan(t, en, "alice", last)
	now := last.Add(10 * time.Second)
	_ = en.ApplyHost(context.Background(), a.ID, now)
	if n := en.Tick(now.Add(time.Second)); len(n) != 0 {
		t.Fatal(n)
	}
	n := en.Tick(last.Add(70 * time.Second))
	if len(n) != 1 || n[0].Kind != "pcr_deadline_missed" || len(en.Tick(last.Add(71*time.Second))) != 0 {
		t.Fatalf("%v", n)
	}
	s, _ := en.Prepare([]string{a.ID})
	_ = en.ConfirmSubmission(s.ID, PCRReply{Count: 1}, last.Add(72*time.Second))
	n = en.Tick(last.Add(time.Hour))
	if len(n) != 1 || n[0].Kind != "verify_overdue" {
		t.Fatalf("%v", n)
	}
	if g, _ := en.Get(a.ID); g.State != StatePCRSubmitted {
		t.Fatal("silence must not change state")
	}
}

func TestPlanForRecordAndCancel(t *testing.T) {
	e, last := rig(t)
	en := NewEngine(PCRConfig{}, e, &fakeHost{}, nil, nil)
	rec := creds.Record{Account: "alice", Host: "web", Scored: true, Credlist: "/creds/web.csv", Role: creds.RoleService}
	tx, err := en.PlanForRecord(rec, []string{"web"}, pw(t, "alice"), pw(t, "alice"), last)
	if err != nil {
		t.Fatal(err)
	}
	_ = en.SyncRecord(tx.ID, &rec)
	if rec.PCRState != creds.PCRPlanned {
		t.Fatal(rec.PCRState)
	}
	if _, err := en.PlanForRecord(creds.Record{Account: "x", Host: "h"}, []string{"h"}, vault.Secret{}, vault.Secret{}, last); err == nil {
		t.Fatal("unscored record planned as PCR")
	}
	if _, err := en.Rollback(context.Background(), tx.ID, last); err != nil {
		t.Fatal(err)
	}
	if g, _ := en.Get(tx.ID); g.State != StateRolledBack || en.Pending("alice") {
		t.Fatal(g.State)
	}
}

func TestIllegalTransitionsPanic(t *testing.T) {
	en := NewEngine(PCRConfig{}, NewEstimator(ClockConfig{}), &fakeHost{}, nil, nil)
	defer func() {
		if recover() == nil {
			t.Fatal("verified -> planned must be impossible")
		}
	}()
	en.move(&Txn{State: StateVerified}, StatePlanned, t0, "")
}
