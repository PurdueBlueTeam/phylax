package palo_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/devices"
	"github.com/PurdueBlueTeam/phylax/internal/devices/palo"
	"github.com/PurdueBlueTeam/phylax/internal/devices/palo/palotest"
	"github.com/PurdueBlueTeam/phylax/internal/devices/palo/xmlapi"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
)

const seed = `<config version="11.0.0"><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
<rulebase><security><rules><entry name="human-rule"><from><member>inside</member></from><to><member>outside</member></to><action>allow</action></entry></rules></security></rulebase>
</entry></vsys><deviceconfig><system><hostname>pa1</hostname></system></deviceconfig></entry></devices></config>`

type env struct {
	srv  *palotest.Server
	ad   *palo.Adapter
	evil *xmlapi.Client
}

func setup(t *testing.T) *env {
	t.Helper()
	srv := palotest.New()
	t.Cleanup(srv.Close)
	srv.SeedRunning(seed)
	key := srv.AddAdmin("phylax", "pw")
	ekey := srv.AddAdmin("evil", "pw")
	ad, err := palo.New(palo.Config{
		Device: "palo1", Admin: "phylax", Key: key,
		Transport:    devices.Transport{HTTP: srv.Client(), Host: srv.URL},
		PollInterval: 5 * time.Millisecond, JobTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &env{srv, ad, &xmlapi.Client{BaseURL: srv.URL, Key: ekey, HTTP: srv.Client()}}
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

func intent(t *testing.T) *render.PaloIntent {
	t.Helper()
	m, err := manifest.LoadDir("../../../manifest/2027", manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	pi, err := render.PaloIntents(m, "palo1")
	if err != nil {
		t.Fatal(err)
	}
	return pi
}

func ruleXPath(name string) string {
	return xmlapi.EntryXPath(palotest.VsysPath+"/rulebase/security/rules", name)
}

func simpleRule(name string) devices.ChangeSet {
	el := `<entry name="` + name + `"><from><member>outside</member></from><to><member>inside</member></to><source><member>any</member></source><destination><member>10.9.9.9</member></destination><service><member>any</member></service><action>allow</action><tag><member>phylax-managed</member></tag></entry>`
	return devices.ChangeSet{Ops: []devices.Op{palo.MakeOp("rule.upsert", name, ruleXPath(name), el)}}
}

func hasNode(n *xmlapi.Node, xpath string) bool {
	st, err := xmlapi.ParseXPath(xpath)
	return err == nil && n.Select(st) != nil
}

func ok(ctx context.Context) error { return nil }

func TestTranslateRealIntent(t *testing.T) {
	e := setup(t)
	pi := intent(t)
	tr, err := e.ad.Translate(pi)
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Policy.Ops) < 5 {
		t.Fatalf("only %d ops", len(tr.Policy.Ops))
	}
	rules, nats := 0, 0
	for _, op := range tr.Policy.Ops {
		var p palo.Payload
		if err := jsonUnmarshal(op.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if _, err := xmlapi.ParseNode([]byte(p.Element)); err != nil {
			t.Fatalf("%s: element is not valid XML: %v\n%s", op.Key, err, p.Element)
		}
		if op.Kind != "tag.upsert" && !strings.Contains(p.Element, "<member>phylax-managed</member>") {
			t.Errorf("%s: not tagged phylax-managed", op.Key)
		}
		if len(op.Key) > 31 {
			t.Errorf("%s: name longer than 31", op.Key)
		}
		switch op.Kind {
		case "rule.upsert":
			rules++
		case "nat.upsert":
			nats++
		}
	}
	if rules == 0 || nats == 0 {
		t.Errorf("rules=%d nats=%d", rules, nats)
	}
	if tr.PolicyRisk != devices.RiskLockout {
		t.Errorf("policy risk %s: the device_access rule is lockout class", tr.PolicyRisk)
	}
	if len(tr.Mgmt.Ops) == 0 && len(tr.Warnings) == 0 {
		t.Error("management lockdown produced neither ops nor a warning")
	}
}

func TestSafeChangeHappyPath(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	tr, err := e.ad.Translate(intent(t))
	if err != nil {
		t.Fatal(err)
	}
	last, err := e.ad.Snapshot(c, "last-good")
	if err != nil {
		t.Fatal(err)
	}
	res, err := devices.SafeChange(c, e.ad, devices.Request{
		Opts:       devices.TxOptions{Plan: "P1", Node: "n1", Scope: devices.ScopePolicy, Risk: tr.PolicyRisk, LastGood: &last},
		Changes:    tr.Policy,
		Health:     e.ad.HealthCheck(palo.FlowsFromIntent(intent(t)), nil),
		ConsoleAck: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	run := e.srv.Running()
	if !hasNode(run, ruleXPath("phylax-icmp")) || !hasNode(run, ruleXPath("human-rule")) {
		t.Fatal("running config lacks the new rule or lost the human one")
	}
	if e.srv.JournalLen() != 0 || e.srv.LockOwner() != "" {
		t.Errorf("journal=%d lock=%q after success", e.srv.JournalLen(), e.srv.LockOwner())
	}
	if res.After == nil || res.After.Hash == res.Before.Hash {
		t.Error("post snapshot did not change")
	}
	if len(res.Tainted) != 0 {
		t.Errorf("tainted: %v", res.Tainted)
	}
	if !e.srv.Saved("phylax-" + res.TxID + ".xml") {
		t.Error("no named copy saved after confirm")
	}
	for _, op := range e.srv.Ops() {
		if strings.HasPrefix(op, "commit") && op != "commit action=partial admins=phylax" {
			t.Errorf("commit is not an admin-scoped partial: %s", op)
		}
	}
	// And drift against the new known-good is empty.
	rep, err := e.ad.Drift(c, *res.After)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Drifted || len(rep.Events) != 0 {
		t.Errorf("drift after our own change: %+v", rep)
	}
}

func TestForeignPendingRefused(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	if err := e.evil.ConfigSet(c, palotest.VsysPath+"/rulebase/security/rules", `<entry name="evil-rule"><action>allow</action></entry>`); err != nil {
		t.Fatal(err)
	}
	before := e.srv.Running()
	_, err := devices.SafeChange(c, e.ad, devices.Request{Opts: devices.TxOptions{Plan: "P", Node: "n", Risk: devices.RiskService}, Changes: simpleRule("phylax-a"), Health: ok})
	if !errors.Is(err, devices.ErrForeignPending) || !errors.Is(err, devices.ErrPreflight) {
		t.Fatalf("want foreign-pending preflight refusal, got %v", err)
	}
	if string(e.srv.Running().Marshal()) != string(before.Marshal()) {
		t.Error("running config changed")
	}
	if e.srv.JournalLen() != 1 {
		t.Errorf("journal %d: we must neither commit nor discard the foreign edit", e.srv.JournalLen())
	}
	for _, op := range e.srv.Ops() {
		if strings.HasPrefix(op, "commit") {
			t.Errorf("commit attempted: %s", op)
		}
	}
	if e.srv.LockOwner() != "" {
		t.Error("lock taken on a refused change")
	}
}

func TestForeignPendingAppearsMidTx(t *testing.T) {
	// The pending check after staging catches a foreign edit that slipped in
	// (for example before our lock). Simulate with a Tx driven by hand.
	e := setup(t)
	c := ctx(t)
	tx, err := e.ad.Begin(c, devices.TxOptions{Plan: "P", Node: "n"})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close(c)
	if err := tx.Lock(c); err != nil {
		t.Fatal(err)
	}
	if err := tx.Stage(c, simpleRule("phylax-a")); err != nil {
		t.Fatal(err)
	}
	e.srv.ReleaseLock() // lock removed out from under us
	if err := e.evil.ConfigSet(c, palotest.VsysPath+"/rulebase/security/rules", `<entry name="evil-rule"><action>allow</action></entry>`); err != nil {
		t.Fatal(err)
	}
	ps, err := tx.Pending(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps.Ours) != 1 || len(ps.Foreign) != 1 || !strings.Contains(ps.Foreign[0], "evil") {
		t.Fatalf("pending = %+v", ps)
	}
	if err := tx.Rollback(c, devices.RollbackDiscardStaged); err != nil {
		t.Fatal(err)
	}
	if e.srv.JournalLen() != 1 {
		t.Errorf("rollback must discard only our edits; journal=%d", e.srv.JournalLen())
	}
	if hasNode(e.srv.Candidate(), ruleXPath("phylax-a")) {
		t.Error("our staged rule survived discard")
	}
}

func TestLockHeld(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	e.srv.HoldLock("evil", "editing")
	_, err := devices.SafeChange(c, e.ad, devices.Request{Opts: devices.TxOptions{Plan: "P", Node: "n", Risk: devices.RiskService}, Changes: simpleRule("phylax-a"), Health: ok})
	if !errors.Is(err, devices.ErrLocked) {
		t.Fatalf("fail-fast: want ErrLocked, got %v", err)
	}
	if hasNode(e.srv.Candidate(), ruleXPath("phylax-a")) {
		t.Error("staged despite the lock")
	}

	// With LockWait the runner waits for the holder to finish.
	go func() { time.Sleep(60 * time.Millisecond); e.srv.ReleaseLock() }()
	_, err = devices.SafeChange(c, e.ad, devices.Request{Opts: devices.TxOptions{Plan: "P", Node: "n2", Risk: devices.RiskService, LockWait: 3 * time.Second}, Changes: simpleRule("phylax-a"), Health: ok})
	if err != nil {
		t.Fatalf("wait for lock: %v", err)
	}
	if !hasNode(e.srv.Running(), ruleXPath("phylax-a")) {
		t.Error("change not applied after waiting")
	}
}

func TestCommitJobFailureRollsBack(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	e.srv.FailCommit = "Error: rule references undefined zone"
	before := e.srv.Running()
	res, err := devices.SafeChange(c, e.ad, devices.Request{Opts: devices.TxOptions{Plan: "P", Node: "n", Risk: devices.RiskService}, Changes: simpleRule("phylax-a"), Health: ok})
	if !errors.Is(err, devices.ErrCommit) || !strings.Contains(err.Error(), "undefined zone") {
		t.Fatalf("want commit failure with detail, got %v", err)
	}
	if res == nil || !res.RolledBack {
		t.Fatalf("not rolled back: %+v", res)
	}
	if string(e.srv.Running().Marshal()) != string(before.Marshal()) {
		t.Error("running changed")
	}
	if hasNode(e.srv.Candidate(), ruleXPath("phylax-a")) {
		t.Error("our edit left in the candidate")
	}
	if e.srv.LockOwner() != "" {
		t.Error("lock leaked")
	}
}

func TestValidateFailureRefuses(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	e.srv.FailValidate = "missing application"
	_, err := devices.SafeChange(c, e.ad, devices.Request{Opts: devices.TxOptions{Plan: "P", Node: "n", Risk: devices.RiskService}, Changes: simpleRule("phylax-a"), Health: ok})
	if !errors.Is(err, devices.ErrValidation) {
		t.Fatalf("got %v", err)
	}
	for _, op := range e.srv.Ops() {
		if strings.HasPrefix(op, "commit") {
			t.Errorf("committed after failed validation: %s", op)
		}
	}
	if hasNode(e.srv.Candidate(), ruleXPath("phylax-a")) {
		t.Error("staged edit left behind")
	}
}

func TestHealthFailureReverts(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	before := e.srv.Running()
	res, err := devices.SafeChange(c, e.ad, devices.Request{
		Opts: devices.TxOptions{Plan: "P", Node: "n", Risk: devices.RiskService}, Changes: simpleRule("phylax-a"),
		Health: func(ctx context.Context) error {
			if !hasNode(e.srv.Running(), ruleXPath("phylax-a")) {
				t.Error("health ran before the commit was active")
			}
			return errors.New("scorer probe to 10.9.9.9:80 failed")
		},
	})
	if !errors.Is(err, devices.ErrHealth) {
		t.Fatalf("got %v", err)
	}
	if !res.RolledBack {
		t.Fatal("not rolled back")
	}
	if string(e.srv.Running().Marshal()) != string(before.Marshal()) {
		t.Errorf("running not restored:\n%s", e.srv.Running())
	}
	if e.srv.JournalLen() != 0 || e.srv.LockOwner() != "" {
		t.Errorf("journal=%d lock=%q", e.srv.JournalLen(), e.srv.LockOwner())
	}
}

func TestPolicyMatchHealthCatchesBlockedFlow(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	// A deny rule on a scored flow: the policy-match health check must see it and revert.
	deny := `<entry name="phylax-oops"><from><member>outside</member></from><to><member>inside</member></to><source><member>any</member></source><destination><member>10.9.9.9</member></destination><service><member>any</member></service><action>deny</action><tag><member>phylax-managed</member></tag></entry>`
	cs := devices.ChangeSet{Ops: []devices.Op{palo.MakeOp("rule.upsert", "phylax-oops", ruleXPath("phylax-oops"), deny)}}
	flows := []palo.Flow{{From: "outside", To: "inside", Src: "198.51.100.10", Dst: "10.9.9.9", Port: 80, Proto: 6}}
	res, err := devices.SafeChange(c, e.ad, devices.Request{Opts: devices.TxOptions{Plan: "P", Node: "n", Risk: devices.RiskService}, Changes: cs, Health: e.ad.HealthCheck(flows, nil)})
	if !errors.Is(err, devices.ErrHealth) || !strings.Contains(err.Error(), "phylax-oops") {
		t.Fatalf("got %v", err)
	}
	if !res.RolledBack || hasNode(e.srv.Running(), ruleXPath("phylax-oops")) {
		t.Error("deny rule still live")
	}
}

func TestUnmanagedItemsAreNotEdited(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	before := e.srv.Running()
	cs := simpleRule("human-rule") // same name as the untagged human rule
	_, err := devices.SafeChange(c, e.ad, devices.Request{Opts: devices.TxOptions{Plan: "P", Node: "n", Risk: devices.RiskService}, Changes: cs, Health: ok})
	if !errors.Is(err, devices.ErrNotManaged) {
		t.Fatalf("got %v", err)
	}
	if string(e.srv.Running().Marshal()) != string(before.Marshal()) || e.srv.JournalLen() != 0 {
		t.Error("device changed")
	}
	del := devices.ChangeSet{Ops: []devices.Op{palo.MakeOp("rule.delete", "human-rule", ruleXPath("human-rule"), "")}}
	_, err = devices.SafeChange(c, e.ad, devices.Request{Opts: devices.TxOptions{Plan: "P", Node: "n2", Risk: devices.RiskService}, Changes: del, Health: ok})
	if !errors.Is(err, devices.ErrNotManaged) {
		t.Fatalf("delete: got %v", err)
	}
}

func TestLockoutNeedsConsoleAck(t *testing.T) {
	e := setup(t)
	_, err := devices.SafeChange(ctx(t), e.ad, devices.Request{Opts: devices.TxOptions{Plan: "P", Node: "n", Risk: devices.RiskLockout}, Changes: simpleRule("phylax-a"), Health: ok})
	if !errors.Is(err, devices.ErrNoDeadman) {
		t.Fatalf("PAN-OS has no commit-confirm; got %v", err)
	}
}

func mgmtIntent(from string) *render.PaloIntent {
	return &render.PaloIntent{Device: "palo1", Tag: render.ManagedTag, InsideZone: "inside", OutsideZone: "outside",
		Mgmt: &render.PaloMgmt{PermittedFrom: []render.Endpoint{{Host: "ctl", Value: from}}, Commit: render.CommitManagement, Risk: render.RiskLockout, Additive: true}}
}

func TestMgmtLockoutRollsBackOnFreshConnection(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	// Warm the keep-alive connection: it stays allowed after the ACL changes.
	if _, err := e.ad.Info(c); err != nil {
		t.Fatal(err)
	}
	tr, err := e.ad.Translate(mgmtIntent("203.0.113.9")) // not our address
	if err != nil {
		t.Fatal(err)
	}
	res, err := devices.SafeChange(c, e.ad, devices.Request{
		Opts:    devices.TxOptions{Plan: "P", Node: "mgmt", Scope: devices.ScopeManagement, Risk: devices.RiskLockout},
		Changes: tr.Mgmt, Health: ok, ConsoleAck: true})
	if !errors.Is(err, devices.ErrProbe) {
		t.Fatalf("want fresh-connection probe failure, got %v", err)
	}
	if !res.RolledBack {
		t.Fatalf("not rolled back: %v", err)
	}
	if hasNode(e.srv.Running(), palotest.PermittedIPPath) && e.srv.Running().Select(mustSteps(palotest.PermittedIPPath)) != nil &&
		len(e.srv.Running().Select(mustSteps(palotest.PermittedIPPath)).Children) != 0 {
		t.Errorf("ACL not restored: %s", e.srv.Running())
	}
	if err := e.ad.Probe(c); err != nil {
		t.Fatalf("management unreachable after rollback: %v", err)
	}
}

func mustSteps(x string) []xmlapi.Step {
	s, err := xmlapi.ParseXPath(x)
	if err != nil {
		panic(err)
	}
	return s
}

func TestMgmtLockdownAdditiveThenRemove(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	// Start wide open: an explicit 0.0.0.0/0 entry.
	e.srv.SeedRunning(strings.Replace(seed, "<hostname>pa1</hostname>", "<hostname>pa1</hostname><permitted-ip><entry name=\"0.0.0.0/0\"/></permitted-ip>", 1))
	tr, err := e.ad.Translate(mgmtIntent("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	opts := devices.TxOptions{Plan: "P", Node: "mgmt", Scope: devices.ScopeManagement, Risk: devices.RiskLockout}
	if _, err := devices.SafeChange(c, e.ad, devices.Request{Opts: opts, Changes: tr.Mgmt, Health: ok, ConsoleAck: true}); err != nil {
		t.Fatalf("additive step: %v", err)
	}
	acl := e.srv.Running().Select(mustSteps(palotest.PermittedIPPath))
	if len(acl.Children) != 2 {
		t.Fatalf("additive step should leave both entries: %s", acl)
	}
	rem, err := e.ad.MgmtRemovals(c, tr)
	if err != nil {
		t.Fatal(err)
	}
	if len(rem.Ops) != 1 || rem.Ops[0].Key != "0.0.0.0/0" {
		t.Fatalf("removals = %+v", rem.Ops)
	}
	opts.Node = "mgmt-remove"
	if _, err := devices.SafeChange(c, e.ad, devices.Request{Opts: opts, Changes: rem, Health: ok, ConsoleAck: true}); err != nil {
		t.Fatalf("remove step: %v", err)
	}
	acl = e.srv.Running().Select(mustSteps(palotest.PermittedIPPath))
	if len(acl.Children) != 1 || acl.Children[0].Attr("name") != "127.0.0.1/32" {
		t.Fatalf("final ACL: %s", acl)
	}
	// Two separate commits, neither combined with service rules.
	commits := 0
	for _, op := range e.srv.Ops() {
		if strings.HasPrefix(op, "commit") {
			commits++
		}
	}
	if commits != 2 {
		t.Errorf("commits = %d, want 2", commits)
	}
}

func TestDriftDetectsForeignChange(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	last, err := e.ad.Snapshot(c, "known-good")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := e.ad.Drift(c, last)
	if err != nil || rep.Drifted || len(rep.Events) != 0 {
		t.Fatalf("clean device drifted: %+v %v", rep, err)
	}
	// Red team: add an allow-all rule and a new admin, then commit.
	if err := e.evil.ConfigSet(c, palotest.VsysPath+"/rulebase/security/rules", `<entry name="backdoor"><action>allow</action></entry>`); err != nil {
		t.Fatal(err)
	}
	if err := e.evil.ConfigSet(c, "/config/mgt-config/users", `<entry name="rt"><permissions/></entry>`); err != nil {
		t.Fatal(err)
	}
	// Staged but not committed: the hash is unchanged, but pending is flagged.
	rep, err = e.ad.Drift(c, last)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Drifted {
		t.Error("pending edits are not drift of the running config")
	}
	var sawPending, sawAdminAdd bool
	for _, ev := range rep.Events {
		sawPending = sawPending || ev.Change == "pending" && ev.Actor == "evil"
		sawAdminAdd = sawAdminAdd || ev.Change == "admin_add" && ev.Actor == "evil"
	}
	if !sawPending || !sawAdminAdd {
		t.Errorf("events: %+v", rep.Events)
	}
	if _, nc, err := e.evil.CommitPartialAdmin(c, "evil", "oops"); err != nil || nc {
		t.Fatalf("commit: %v %v", err, nc)
	}
	rep, err = e.ad.Drift(c, last)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Drifted || rep.Diff.Empty() {
		t.Fatalf("committed foreign change not detected: %+v", rep)
	}
	var sawDiff, sawCommit bool
	for _, ev := range rep.Events {
		if ev.Ours {
			t.Errorf("foreign event marked ours: %+v", ev)
		}
		sawDiff = sawDiff || ev.Change == "diff" && strings.Contains(ev.Path, "backdoor")
		sawCommit = sawCommit || ev.Change == "commit" && ev.Actor == "evil" && ev.SrcIP != ""
	}
	if !sawDiff || !sawCommit {
		t.Errorf("events: %+v", rep.Events)
	}
	// Preflight with the stale known-good now refuses a change.
	_, err = devices.SafeChange(c, e.ad, devices.Request{Opts: devices.TxOptions{Plan: "P", Node: "n", Risk: devices.RiskService, LastGood: &last}, Changes: simpleRule("phylax-a"), Health: ok})
	if !errors.Is(err, devices.ErrPreflight) || !strings.Contains(err.Error(), "drift") {
		t.Fatalf("want drift refusal, got %v", err)
	}
}

func TestForeignLockIsDriftEvent(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	last, _ := e.ad.Snapshot(c, "k")
	e.srv.HoldLock("evil", "hands off")
	rep, err := e.ad.Drift(c, last)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range rep.Events {
		if ev.Change == "lock" && ev.Actor == "evil" {
			return
		}
	}
	t.Errorf("no lock event: %+v", rep.Events)
}

func TestForeignCommitDuringTxTaintsResult(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	res, err := devices.SafeChange(c, e.ad, devices.Request{
		Opts: devices.TxOptions{Plan: "P", Node: "n", Risk: devices.RiskService}, Changes: simpleRule("phylax-a"),
		Health: func(ctx context.Context) error {
			// A foreign admin edits and commits while our health check runs.
			if err := e.evil.ConfigSet(ctx, palotest.VsysPath+"/rulebase/security/rules", `<entry name="sneaky"><action>allow</action></entry>`); err != nil {
				return err
			}
			_, _, err := e.evil.CommitPartialAdmin(ctx, "evil", "x")
			return err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tainted) == 0 {
		t.Error("foreign commit during the window must taint the new known-good")
	}
}

func TestAdminsAndEvents(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	e.srv.SetSessions([]xmlapi.Admin{{Name: "evil", From: "10.1.1.1", Type: "Web"}})
	st, err := e.ad.Admins(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Sessions) != 1 || st.Sessions[0].Name != "evil" || len(st.Configured) != 3 {
		t.Errorf("admins = %+v", st)
	}
	e.srv.AddLog("system", map[string]string{"admin": "evil", "host": "10.1.1.1", "eventid": "auth-fail", "opaque": "failed authentication for user 'root'"})
	e.srv.AddLog("traffic", map[string]string{"src": "10.2.2.2", "action": "deny"})
	evs, cur, err := e.ad.Events(c, devices.EventFilter{Source: "system"})
	if err != nil || len(evs) != 1 || evs[0].Actor != "evil" || !strings.Contains(evs[0].Detail, "failed") {
		t.Fatalf("system events: %+v %v", evs, err)
	}
	again, _, err := e.ad.Events(c, devices.EventFilter{Source: "system", Since: cur})
	if err != nil || len(again) != 0 {
		t.Errorf("cursor did not advance: %+v %v", again, err)
	}
	tr, _, err := e.ad.Events(c, devices.EventFilter{Source: "traffic"})
	if err != nil || len(tr) != 1 || tr[0].SrcIP != "10.2.2.2" {
		t.Errorf("traffic: %+v %v", tr, err)
	}
	if _, _, err := e.ad.Events(c, devices.EventFilter{Source: "bogus"}); err == nil {
		t.Error("unknown source accepted")
	}
}

func TestReleaseStaleLock(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	e.srv.HoldLock("phylax", "crashed plan")
	if err := e.ad.ReleaseStaleLock(c); err != nil || e.srv.LockOwner() != "" {
		t.Fatalf("stale lock: %v owner=%q", err, e.srv.LockOwner())
	}
	e.srv.HoldLock("evil", "theirs")
	if err := e.ad.ReleaseStaleLock(c); err != nil || e.srv.LockOwner() != "evil" {
		t.Fatalf("must not touch another admin's lock: %v owner=%q", err, e.srv.LockOwner())
	}
}

func TestInfoAndCaps(t *testing.T) {
	e := setup(t)
	in, err := e.ad.Info(ctx(t))
	if err != nil || in.Version != "11.0.2" || in.Hostname != "fake-pa" || in.Uptime != time.Hour+2*time.Minute+3*time.Second {
		t.Fatalf("info = %+v %v", in, err)
	}
	cp := e.ad.Caps()
	if cp.SoftDeadman || cp.NativeConfirm || !cp.ConfigLock || !cp.ScopedCommit {
		t.Errorf("caps = %+v", cp)
	}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
