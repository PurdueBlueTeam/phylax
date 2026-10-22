package vyos_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PurdueBlueTeam/phylax/internal/devices"
	"github.com/PurdueBlueTeam/phylax/internal/devices/vyos"
	"github.com/PurdueBlueTeam/phylax/internal/devices/vyos/vyostest"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
)

var seedLines = []string{
	"set interfaces ethernet eth0 address '10.0.0.1/24'",
	"set service ssh port '22'",
	"set system login user phylax authentication plaintext-password 'x'",
	"set firewall ipv4 forward filter rule 110 description 'human rule'",
	"set firewall ipv4 forward filter rule 110 action 'accept'",
}

type env struct {
	srv *vyostest.Server
	ad  *vyos.Adapter
}

func setup(t *testing.T) *env {
	t.Helper()
	srv := vyostest.New()
	t.Cleanup(srv.Close)
	srv.Seed(seedLines...)
	ad, err := vyos.New(vyos.Config{
		Device:    "vyos1",
		Transport: devices.Transport{HTTP: srv.HTTP.Client(), Host: "127.0.0.1"},
		SSH: vyos.SSHConfig{Addr: srv.SSHAddr, User: "phylax", Auth: []ssh.AuthMethod{ssh.Password("pw")},
			HostKey: ssh.FixedHostKey(srv.HostKey), ExecWait: 10 * time.Second},
		HTTPBase: srv.HTTP.URL, APIKey: "k",
	})
	if err != nil {
		t.Fatal(err)
	}
	return &env{srv, ad}
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func ok(context.Context) error { return nil }

func rule(n int, port string) devices.ChangeSet {
	base := "firewall ipv4 forward filter rule " + string(rune('0'+n/100)) + string(rune('0'+n/10%10)) + string(rune('0'+n%10))
	return devices.ChangeSet{Ops: []devices.Op{vyos.MakeOp("rule.upsert", base, base,
		"delete "+base,
		"set "+base+" description 'phylax-managed: test'",
		"set "+base+" action 'accept'",
		"set "+base+" protocol 'tcp'",
		"set "+base+" destination port '"+port+"'")}}
}

func intent(t *testing.T) *render.VyOSIntent {
	t.Helper()
	m, err := manifest.LoadDir("../../../manifest/2027", manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	name := ""
	for n, d := range m.Devices {
		if d.Vendor == "vyos" {
			name = n
		}
	}
	vi, err := render.VyOSIntents(m, name)
	if err != nil {
		t.Fatal(err)
	}
	return vi
}

func noRebootCommands(t *testing.T, srv *vyostest.Server) {
	t.Helper()
	for _, op := range srv.Ops() {
		for _, bad := range []string{"commit-confirm", "reboot", "rollback", "poweroff"} {
			if strings.Contains(op, bad) {
				t.Errorf("forbidden command sent: %s", op)
			}
		}
	}
}

func TestTranslateRealIntent(t *testing.T) {
	e := setup(t)
	vi := intent(t)
	tr, err := e.ad.Translate(vi, vyos.TranslateOpts{OutboundInterface: "eth0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Policy.Ops) == 0 {
		t.Fatal("no policy ops")
	}
	icmp := false
	for _, op := range tr.Policy.Ops {
		var p vyos.Payload
		if err := json.Unmarshal(op.Payload, &p); err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(p.Cmds, "\n")
		if !strings.Contains(joined, "description 'phylax-managed") {
			t.Errorf("%s: description does not carry the managed tag", op.Key)
		}
		if strings.Contains(joined, "protocol 'icmp'") {
			icmp = true
		}
	}
	if !icmp {
		t.Error("ICMP accept rule missing")
	}
	// Every generated command must pass the adapter's own safety filter when staged.
	tx, _ := e.ad.Begin(ctx(t), devices.TxOptions{Plan: "p", Node: "n"})
	if err := tx.Stage(ctx(t), tr.Policy); err != nil {
		t.Fatalf("generated policy rejected by Stage: %v", err)
	}
	if err := tx.Stage(ctx(t), tr.Mgmt); err != nil {
		t.Fatalf("generated mgmt rejected by Stage: %v", err)
	}
	if vi.Mgmt != nil && len(tr.Mgmt.Ops) == 0 && len(tr.Warnings) == 0 {
		t.Error("mgmt lockdown neither generated nor warned")
	}
}

func TestSafeChangeHappyPathSavesAfterHealth(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	last, err := e.ad.Snapshot(c, "good")
	if err != nil {
		t.Fatal(err)
	}
	var savedDuringHealth []string
	res, err := devices.SafeChange(c, e.ad, devices.Request{
		Opts:    devices.TxOptions{Plan: "P", Node: "n", Scope: devices.ScopePolicy, Risk: devices.RiskService, LastGood: &last},
		Changes: rule(120, "80,443"),
		Health: func(ctx context.Context) error {
			savedDuringHealth = e.srv.SavedLines()
			if !e.srv.TimerArmed("phylax-revert") {
				t.Error("dead-man not armed during the health check")
			}
			return e.ad.HealthCheck(nil)(ctx)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !e.srv.Has("set firewall ipv4 forward filter rule 120 destination port '80,443'") {
		t.Fatalf("change not live: %v", e.srv.Lines())
	}
	if slices.Contains(savedDuringHealth, "set firewall ipv4 forward filter rule 120 action 'accept'") {
		t.Error("config was saved before the health check passed")
	}
	if !slices.Equal(e.srv.Lines(), e.srv.SavedLines()) {
		t.Error("config not saved after confirm")
	}
	if e.srv.TimerArmed("phylax-revert") {
		t.Error("dead-man still armed after confirm")
	}
	if e.srv.HasFile("/config/archive/phylax/pre-" + res.TxID + ".boot") {
		t.Error("pre-change snapshot not cleaned up")
	}
	if !e.srv.Has("set firewall ipv4 forward filter rule 110 action 'accept'") {
		t.Error("human rule lost")
	}
	if rep, err := e.ad.Drift(c, *res.After); err != nil || rep.Drifted || len(rep.Events) != 0 {
		t.Errorf("drift after our change: %+v %v", rep, err)
	}
	noRebootCommands(t, e.srv)
}

func TestHealthFailureRevertsAndNeverSaves(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	before := e.srv.Lines()
	res, err := devices.SafeChange(c, e.ad, devices.Request{
		Opts: devices.TxOptions{Plan: "P", Node: "n", Risk: devices.RiskService}, Changes: rule(120, "80"),
		Health: func(ctx context.Context) error { return errors.New("scorer probe failed") },
	})
	if !errors.Is(err, devices.ErrHealth) || !res.RolledBack {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	if !slices.Equal(e.srv.Lines(), before) {
		t.Errorf("running not restored: %v", e.srv.Lines())
	}
	if !slices.Equal(e.srv.SavedLines(), before) {
		t.Error("boot config touched")
	}
	if e.srv.TimerArmed("phylax-revert") {
		t.Error("timer left armed after a manual revert")
	}
	noRebootCommands(t, e.srv)
}

func TestCommitFailureRollsBack(t *testing.T) {
	e := setup(t)
	before := e.srv.Lines()
	e.srv.FailCommit = "firewall rule 120 refers to a missing group"
	res, err := devices.SafeChange(ctx(t), e.ad, devices.Request{Opts: devices.TxOptions{Plan: "P", Node: "n", Risk: devices.RiskService}, Changes: rule(120, "80"), Health: ok})
	if !errors.Is(err, devices.ErrCommit) || !strings.Contains(err.Error(), "missing group") || !res.RolledBack {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	if !slices.Equal(e.srv.Lines(), before) || e.srv.TimerArmed("phylax-revert") {
		t.Error("device not clean")
	}
}

func TestDeadmanTimerFiresWithoutController(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	before := e.srv.Lines()
	tx, err := e.ad.Begin(c, devices.TxOptions{Plan: "P", Node: "n", Risk: devices.RiskLockout, Deadman: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if pf, err := tx.Preflight(c); err != nil || !pf.OK {
		t.Fatalf("preflight %+v %v", pf, err)
	}
	if err := tx.Stage(c, rule(120, "80")); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Commit(c); err != nil {
		t.Fatal(err)
	}
	if !e.srv.Has("set firewall ipv4 forward filter rule 120 action 'accept'") {
		t.Fatal("not applied")
	}
	// The controller "dies" here: no Confirm, no Rollback; Close must not disarm.
	_ = tx.Close(c)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && !slices.Equal(e.srv.Lines(), before) {
		time.Sleep(20 * time.Millisecond)
	}
	if !slices.Equal(e.srv.Lines(), before) {
		t.Fatalf("router did not revert itself: %v", e.srv.Lines())
	}
	if !slices.Equal(e.srv.SavedLines(), before) {
		t.Error("boot config changed")
	}
}

func TestSlowHealthCheckLetsDeadmanWinAndRunnerRollsBack(t *testing.T) {
	e := setup(t)
	before := e.srv.Lines()
	_, err := devices.SafeChange(ctx(t), e.ad, devices.Request{
		Opts: devices.TxOptions{Plan: "P", Node: "n", Risk: devices.RiskLockout, Deadman: 400 * time.Millisecond}, Changes: rule(120, "80"),
		Health: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }, // hangs until the runner's bound
	})
	if !errors.Is(err, devices.ErrHealth) {
		t.Fatalf("got %v", err)
	}
	if !slices.Equal(e.srv.Lines(), before) {
		t.Errorf("not reverted: %v", e.srv.Lines())
	}
}

const dropLine = "set firewall ipv4 input filter rule 900 action 'drop'"

func mgmtIntent() *render.VyOSIntent {
	return &render.VyOSIntent{Device: "vyos1", Tag: render.ManagedTag,
		Mgmt: &render.VyOSMgmt{PermittedFrom: []render.Endpoint{{Host: "ctl", Value: "203.0.113.9"}}, Ports: []uint16{22, 443}, Risk: render.RiskLockout}}
}

func TestMgmtLockoutDetectedByFreshConnectionAndDeadmanReverts(t *testing.T) {
	e := setup(t)
	before := e.srv.Lines()
	e.srv.BlockSSH = func(lines []string) bool { return slices.Contains(lines, dropLine) } // the drop rule really cuts new logins
	tr, err := e.ad.Translate(mgmtIntent(), vyos.TranslateOpts{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := devices.SafeChange(ctx(t), e.ad, devices.Request{
		Opts:    devices.TxOptions{Plan: "P", Node: "mgmt", Scope: devices.ScopeManagement, Risk: devices.RiskLockout, Deadman: 600 * time.Millisecond},
		Changes: tr.Mgmt, Health: ok})
	if !errors.Is(err, devices.ErrProbe) {
		t.Fatalf("want fresh-connection probe failure, got %v", err)
	}
	// We cannot reach the router to revert by hand; the report must say the timer will.
	if !errors.Is(err, devices.ErrRollback) || !strings.Contains(err.Error(), "dead-man") || res.RolledBack {
		t.Fatalf("expected a failed manual rollback that defers to the dead-man: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && !slices.Equal(e.srv.Lines(), before) {
		time.Sleep(20 * time.Millisecond)
	}
	if !slices.Equal(e.srv.Lines(), before) {
		t.Fatalf("dead-man did not restore access: %v", e.srv.Lines())
	}
	if err := e.ad.Probe(ctx(t)); err != nil {
		t.Fatalf("router unreachable after the dead-man: %v", err)
	}
}

func TestMgmtChangeThatKeepsAccessCommits(t *testing.T) {
	e := setup(t)
	tr, _ := e.ad.Translate(mgmtIntent(), vyos.TranslateOpts{})
	_, err := devices.SafeChange(ctx(t), e.ad, devices.Request{
		Opts:    devices.TxOptions{Plan: "P", Node: "mgmt", Scope: devices.ScopeManagement, Risk: devices.RiskLockout},
		Changes: tr.Mgmt, Health: e.ad.HealthCheck(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if !e.srv.Has(dropLine) || !slices.Contains(e.srv.SavedLines(), dropLine) {
		t.Error("lockdown not applied and saved")
	}
	if !e.srv.Has("set service https allow-client address '203.0.113.9'") {
		t.Error("https allow-client missing")
	}
}

func TestUnmanagedRuleIsNotReplaced(t *testing.T) {
	e := setup(t)
	before := e.srv.Lines()
	_, err := devices.SafeChange(ctx(t), e.ad, devices.Request{Opts: devices.TxOptions{Plan: "P", Node: "n", Risk: devices.RiskService}, Changes: rule(110, "80"), Health: ok})
	if !errors.Is(err, devices.ErrNotManaged) || !slices.Equal(e.srv.Lines(), before) {
		t.Fatalf("err=%v lines=%v", err, e.srv.Lines())
	}
}

func TestCommandInjectionRefused(t *testing.T) {
	e := setup(t)
	for _, bad := range []string{
		"set system host-name 'a'; reboot",
		"set system host-name 'a\nreboot'",
		"set system host-name '$(reboot)'",
		"set system host-name 'a",
		"commit-confirm 5",
	} {
		cs := devices.ChangeSet{Ops: []devices.Op{vyos.MakeOp("raw", "x", "", bad)}}
		tx, _ := e.ad.Begin(ctx(t), devices.TxOptions{Plan: "p", Node: "n"})
		if err := tx.Stage(ctx(t), cs); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestPreflightRefusesForeignCommitAndDrift(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	last, _ := e.ad.Snapshot(c, "good")
	e.srv.ExternalCommit("evil", []string{"set protocols static route 0.0.0.0/0 next-hop '6.6.6.6'"})
	_, err := devices.SafeChange(c, e.ad, devices.Request{Opts: devices.TxOptions{Plan: "P", Node: "n", Risk: devices.RiskService, LastGood: &last}, Changes: rule(120, "80"), Health: ok})
	if !errors.Is(err, devices.ErrPreflight) || !strings.Contains(err.Error(), "drift") {
		t.Fatalf("got %v", err)
	}
	if e.srv.Has("set firewall ipv4 forward filter rule 120 action 'accept'") {
		t.Error("change applied despite drift")
	}
}

func TestPreflightRefusesUnsavedForeignConfig(t *testing.T) {
	// Without a last-known-good, an armed leftover timer still blocks.
	e := setup(t)
	tx0, _ := e.ad.Begin(ctx(t), devices.TxOptions{Plan: "old", Node: "n", Risk: devices.RiskLockout, Deadman: time.Minute})
	_ = tx0.Stage(ctx(t), rule(121, "80"))
	if _, err := tx0.Commit(ctx(t)); err != nil {
		t.Fatal(err)
	}
	_, err := devices.SafeChange(ctx(t), e.ad, devices.Request{Opts: devices.TxOptions{Plan: "P", Node: "n", Risk: devices.RiskService}, Changes: rule(122, "80"), Health: ok})
	if !errors.Is(err, devices.ErrPreflight) || !strings.Contains(err.Error(), "already armed") {
		t.Fatalf("got %v", err)
	}
	if err := e.ad.DisarmStale(ctx(t)); err != nil || e.srv.TimerArmed("phylax-revert") {
		t.Fatalf("disarm: %v", err)
	}
	if err := e.ad.DisarmStale(ctx(t)); err != nil {
		t.Fatalf("disarm when nothing is armed: %v", err)
	}
}

func TestDriftDetection(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	last, _ := e.ad.Snapshot(c, "good")
	rep, err := e.ad.Drift(c, last)
	if err != nil || rep.Drifted || len(rep.Events) != 0 {
		t.Fatalf("clean: %+v %v", rep, err)
	}
	e.srv.ExternalCommit("evil",
		[]string{"set system login user rt authentication plaintext-password 'x'"},
		"set service ssh port '22'")
	rep, err = e.ad.Drift(c, last)
	if err != nil || !rep.Drifted {
		t.Fatalf("%+v %v", rep, err)
	}
	var diffAdd, diffDel, commit, unsaved bool
	for _, ev := range rep.Events {
		diffAdd = diffAdd || ev.Change == "diff" && ev.Detail == "added" && strings.Contains(ev.Path, "user rt")
		diffDel = diffDel || ev.Change == "diff" && ev.Detail == "removed" && strings.Contains(ev.Path, "service ssh")
		commit = commit || ev.Change == "commit" && ev.Actor == "evil" && !ev.Ours
		unsaved = unsaved || ev.Change == "oob" && strings.Contains(ev.Detail, "saved boot config")
	}
	if !diffAdd || !diffDel || !commit || !unsaved {
		t.Errorf("events: %+v", rep.Events)
	}
	// The boot file edited behind the router's back is its own signal.
	last2, _ := e.ad.Snapshot(c, "good2")
	e.srv.EditBootFile("set system task-scheduler task x executable path '/tmp/x'")
	rep, err = e.ad.Drift(c, last2)
	if err != nil || !rep.Drifted {
		t.Fatalf("%+v %v", rep, err)
	}
	found := false
	for _, ev := range rep.Events {
		found = found || ev.Change == "oob" && ev.Path == "/config/config.boot"
	}
	if !found {
		t.Errorf("boot edit not reported: %+v", rep.Events)
	}
}

func TestForeignCommitDuringTxTaints(t *testing.T) {
	e := setup(t)
	res, err := devices.SafeChange(ctx(t), e.ad, devices.Request{
		Opts: devices.TxOptions{Plan: "P", Node: "n", Risk: devices.RiskService}, Changes: rule(120, "80"),
		Health: func(context.Context) error {
			e.srv.ExternalCommit("evil", []string{"set system host-name 'pwned'"})
			return nil
		}})
	_ = err // the confirm re-check may refuse; either way taint must be visible when it succeeds
	if err == nil && len(res.Tainted) == 0 {
		t.Error("foreign commit during the window not flagged")
	}
}

func TestInfoAdminsEventsHTTP(t *testing.T) {
	e := setup(t)
	c := ctx(t)
	in, err := e.ad.Info(c)
	if err != nil || in.Version != "1.4.0" || in.Hostname != "vyos1" {
		t.Fatalf("info %+v %v", in, err)
	}
	e.srv.SetWho("evil pts/0 2026-10-22 12:00 (10.9.9.9)")
	st, err := e.ad.Admins(c)
	if err != nil || len(st.Sessions) != 1 || st.Sessions[0].From != "10.9.9.9" || !slices.Equal(st.Configured, []string{"phylax"}) {
		t.Fatalf("admins %+v %v", st, err)
	}
	evs, cur, err := e.ad.Events(c, devices.EventFilter{})
	if err != nil || len(evs) != 1 || evs[0].Actor != "vyos" {
		t.Fatalf("events %+v %v", evs, err)
	}
	e.srv.ExternalCommit("evil", []string{"set system host-name 'x'"})
	evs, _, err = e.ad.Events(c, devices.EventFilter{Since: cur})
	if err != nil || len(evs) != 1 || evs[0].Actor != "evil" {
		t.Fatalf("incremental events %+v %v", evs, err)
	}
	h := &vyos.HTTPClient{BaseURL: e.srv.HTTP.URL, Key: "k", HTTP: e.srv.HTTP.Client()}
	raw, err := h.Retrieve(c, "exists", "service", "ssh")
	if err != nil || string(raw) != "true" {
		t.Errorf("exists = %s %v", raw, err)
	}
	if _, err := h.Retrieve(c, "set"); err == nil {
		t.Error("retrieve accepted a write op")
	}
	bad := &vyos.HTTPClient{BaseURL: e.srv.HTTP.URL, Key: "wrong", HTTP: e.srv.HTTP.Client()}
	if _, err := bad.Show(c, "version"); err == nil {
		t.Error("bad key accepted")
	}
}

func TestSSHRequiresPinnedHostKey(t *testing.T) {
	e := setup(t)
	other := vyostest.New()
	defer other.Close()
	ad, _ := vyos.New(vyos.Config{
		Transport: devices.Transport{Host: "127.0.0.1"},
		SSH:       vyos.SSHConfig{Addr: e.srv.SSHAddr, User: "phylax", Auth: []ssh.AuthMethod{ssh.Password("pw")}, HostKey: ssh.FixedHostKey(other.HostKey)},
	})
	if err := ad.Probe(ctx(t)); err == nil {
		t.Fatal("connected to a router with an unpinned host key")
	}
}
