package firewall

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
)

var updateWin = flag.Bool("update-win", false, "rewrite Windows golden files")

// fakeWin is an in-memory Windows Firewall with the semantics that matter:
// rules are keyed by name, a Remove deletes every rule of that name (as COM
// does), and failures can be injected.
type fakeWin struct {
	profiles []WinProfileState
	rules    []WinRuleState
	ops      int
	failAt   int // fail the Nth mutating op (1-based); 0: never
	log      []string
}

func newFakeWin() *fakeWin {
	f := &fakeWin{}
	for _, p := range WinProfileNames {
		f.profiles = append(f.profiles, WinProfileState{Name: p, Enabled: true, DefaultInbound: "Block", DefaultOutbound: "Allow"})
	}
	return f
}

func (f *fakeWin) tick(what string) error {
	f.ops++
	f.log = append(f.log, what)
	if f.failAt != 0 && f.ops == f.failAt {
		return errors.New("injected COM failure")
	}
	return nil
}
func (f *fakeWin) Profiles() ([]WinProfileState, error) {
	return append([]WinProfileState(nil), f.profiles...), nil
}
func (f *fakeWin) SetProfile(p WinProfileState) error {
	if err := f.tick("setprofile " + p.Name); err != nil {
		return err
	}
	for i := range f.profiles {
		if f.profiles[i].Name == p.Name {
			f.profiles[i] = p
		}
	}
	return nil
}
func (f *fakeWin) Rules() ([]WinRuleState, error) {
	return append([]WinRuleState(nil), f.rules...), nil
}
func (f *fakeWin) AddRule(r WinRuleState) error {
	if err := f.tick("add " + r.Name); err != nil {
		return err
	}
	f.rules = append(f.rules, r)
	return nil
}
func (f *fakeWin) UpdateRule(r WinRuleState) error {
	if err := f.tick("update " + r.Name); err != nil {
		return err
	}
	for i := range f.rules {
		if f.rules[i].Name == r.Name {
			f.rules[i] = r
			return nil
		}
	}
	return fmt.Errorf("no rule %q", r.Name)
}
func (f *fakeWin) RemoveRule(name string) error {
	if err := f.tick("remove " + name); err != nil {
		return err
	}
	var keep []WinRuleState
	for _, r := range f.rules {
		if r.Name != name {
			keep = append(keep, r)
		}
	}
	f.rules = keep
	return nil
}
func (f *fakeWin) Close() error { return nil }

func winPolicies(t *testing.T, name string) map[string]*render.WinPolicy {
	t.Helper()
	m, err := manifest.LoadDir(refs[name], manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*render.WinPolicy{}
	for _, h := range manifest.SortedKeys(m.Hosts) {
		if !m.Hosts[h].IsWindows() {
			continue
		}
		hp, err := render.BuildHostPolicy(m, h)
		if err != nil {
			t.Fatal(err)
		}
		wp, err := render.WindowsRules(hp)
		if err != nil {
			t.Fatal(err)
		}
		out[h] = wp
	}
	return out
}

func anyWin(t *testing.T) (string, *render.WinPolicy) {
	t.Helper()
	ps := winPolicies(t, "2027")
	for _, h := range []string{"ad", "mssql", "win11-wkst"} {
		if p, ok := ps[h]; ok {
			return h, p
		}
	}
	t.Fatal("no windows host in the reference manifest")
	return "", nil
}

func TestWinTranslateGolden(t *testing.T) {
	n := 0
	for name := range refs {
		for host, wp := range winPolicies(t, name) {
			n++
			st, err := TranslateWindows(wp, WinTranslateOptions{})
			if err != nil {
				t.Fatalf("%s/%s: %v", name, host, err)
			}
			if len(st.Rules) != len(wp.Rules) {
				t.Fatalf("%s/%s: %d rules in, %d out", name, host, len(wp.Rules), len(st.Rules))
			}
			for _, p := range st.Profiles {
				if !p.Enabled || p.DefaultInbound != wp.DefaultInbound || p.DefaultOutbound != wp.DefaultOutbound {
					t.Errorf("%s/%s: profile %+v does not follow the policy", name, host, p)
				}
			}
			b, _ := jsonIndent(st)
			path := filepath.Join("testdata", "golden", name, host+".win.json")
			if *updateWin {
				os.MkdirAll(filepath.Dir(path), 0o755)
				os.WriteFile(path, b, 0o644)
				continue
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update-win)", err)
			}
			if string(want) != string(b) {
				t.Errorf("%s differs from golden", path)
			}
		}
	}
	if n == 0 {
		t.Fatal("no Windows hosts found")
	}
}

func TestWinTranslateRejectsBadPolicies(t *testing.T) {
	_, wp := anyWin(t)
	bad := func(mut func(*render.WinPolicy)) error {
		c := *wp
		c.Rules = append([]render.WinRule(nil), wp.Rules...)
		mut(&c)
		_, err := TranslateWindows(&c, WinTranslateOptions{})
		return err
	}
	if err := bad(func(p *render.WinPolicy) { p.Rules[0].Group = "Windows Remote Management" }); err == nil {
		t.Error("rule in a foreign group accepted")
	}
	if err := bad(func(p *render.WinPolicy) { p.Rules[1].Name = p.Rules[0].Name }); err == nil {
		t.Error("duplicate name accepted")
	}
	if err := bad(func(p *render.WinPolicy) { p.Rules[0].Protocol = "Banana" }); err == nil {
		t.Error("bad protocol accepted")
	}
	if err := bad(func(p *render.WinPolicy) {
		var keep []render.WinRule
		for _, r := range p.Rules {
			if r.Group != WinMgmtGroup {
				keep = append(keep, r)
			}
		}
		p.Rules, p.DefaultOutbound = keep, "Block"
	}); !errors.Is(err, ErrNoManagement) {
		t.Errorf("default-block without management rules: %v", err)
	}
	if _, err := TranslateWindows(wp, WinTranslateOptions{Mode: ModeShadow}); !errors.Is(err, ErrShadowUnsupported) {
		t.Errorf("shadow: %v", err)
	}
}

func TestNormalizers(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "*": "", "443,80": "80,443", "80, 80,443": "80,443", "1000-2000,22": "22,1000-2000", "RPC": "rpc",
	} {
		if got := NormPorts(in); got != want {
			t.Errorf("NormPorts(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"": "", "*": "", "Any": "",
		"10.0.0.0/255.255.255.0":           "10.0.0.0/24",
		"10.0.0.5":                         "10.0.0.5/32",
		"10.0.0.5/32,10.0.0.0/24":          "10.0.0.0/24,10.0.0.5/32",
		"fd00::/64":                        "fd00::/64",
		"2001:db8::1":                      "2001:db8::1/128",
		"10.0.0.1-10.0.0.9":                "10.0.0.1-10.0.0.9",
		"LocalSubnet":                      "localsubnet",
		"192.168.0.0/255.255.0.0, 1.2.3.4": "1.2.3.4/32,192.168.0.0/16",
	} {
		got, err := NormAddrs(in)
		if err != nil || got != want {
			t.Errorf("NormAddrs(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := NormAddrs("10.0.0.0/zz"); err == nil {
		t.Error("bad mask accepted")
	}
	if got := ComAddr("10.0.0.5/32,10.0.0.0/24,fd00::1/128"); got != "10.0.0.5,10.0.0.0/24,fd00::1" {
		t.Errorf("ComAddr = %q", got)
	}
	// Windows' own spelling and ours normalize to the same thing.
	a, _ := NormAddrs("10.1.0.0/255.255.0.0,10.1.1.1")
	b, _ := NormAddrs("10.1.1.1/32,10.1.0.0/16")
	if a != b {
		t.Errorf("%q != %q", a, b)
	}
}

func newWinMgr(t *testing.T, f *fakeWin, dm *deadman.Manager) *WinManager {
	return NewWindows(WinOptions{Deadman: dm, NewBackend: func() (WinBackend, error) { return f, nil }})
}

func winDeadman(t *testing.T, f *fakeWin) *deadman.Manager {
	t.Helper()
	dm, err := deadman.Open(t.TempDir(), deadman.Options{Handlers: WinHandlers(func() (WinBackend, error) { return f, nil })})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dm.Close() })
	return dm
}

func foreignRules() []WinRuleState {
	return []WinRuleState{
		{Name: "Core Networking - DNS", Group: "Core Networking", Direction: "Outbound", Action: "Allow", Protocol: "UDP", RemotePorts: "53", Profiles: "Any", Enabled: true},
		{Name: "RedTeam block", Group: "Totally Legit", Direction: "Inbound", Action: "Block", Protocol: "TCP", LocalPorts: "443", Profiles: "Any", Enabled: true},
	}
}

func TestWinApplyVerifyIdempotentForeignUntouched(t *testing.T) {
	_, wp := anyWin(t)
	f := newFakeWin()
	f.rules = foreignRules()
	m := newWinMgr(t, f, nil)
	res, err := m.Apply(context.Background(), wp, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || len(res.ForeignBlockers) != 1 || res.ForeignBlockers[0].Name != "RedTeam block" {
		t.Fatalf("result: %+v", res)
	}
	want, _ := TranslateWindows(wp, WinTranslateOptions{})
	got, all, _ := readWin(f)
	if d := DiffWinStates(want, got); len(d) != 0 {
		t.Fatalf("not applied: %v", d)
	}
	if len(all) != len(want.Rules)+2 {
		t.Fatalf("%d rules on the machine, want %d", len(all), len(want.Rules)+2)
	}
	fr := foreignRules()
	for _, r := range fr {
		found := false
		for _, a := range all {
			found = found || a == r
		}
		if !found {
			t.Errorf("foreign rule %q changed or removed", r.Name)
		}
	}
	for _, p := range f.profiles {
		if !p.Enabled || p.DefaultInbound != wp.DefaultInbound || p.DefaultOutbound != wp.DefaultOutbound {
			t.Errorf("profile %+v", p)
		}
	}
	ops := f.ops
	res2, err := m.Apply(context.Background(), wp, ApplyOptions{})
	if err != nil || res2.Changed || f.ops != ops {
		t.Fatalf("re-apply: changed=%v ops=%d->%d err=%v", res2.Changed, ops, f.ops, err)
	}
	if !contains(res.Unapplied, "denied_egress_audit") == wp.DeniedEgressAudit {
		t.Errorf("unapplied %v for audit=%v", res.Unapplied, wp.DeniedEgressAudit)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestWinApplyOrderKeepsMachineReachable(t *testing.T) {
	_, wp := anyWin(t)
	f := newFakeWin()
	// An old Phylax rule that must go, and a changed management rule.
	f.rules = append(foreignRules(), WinRuleState{Name: "Phylax Egress stale", Group: "Phylax Egress", Direction: "Outbound", Action: "Allow", Protocol: "TCP", RemotePorts: "9", Profiles: "Any", Enabled: true})
	m := newWinMgr(t, f, nil)
	if _, err := m.Apply(context.Background(), wp, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	lastAdd, firstProfile, firstRemove := -1, -1, -1
	for i, l := range f.log {
		switch {
		case strings.HasPrefix(l, "add "), strings.HasPrefix(l, "update "):
			lastAdd = i
		case strings.HasPrefix(l, "setprofile") && firstProfile < 0:
			firstProfile = i
		case strings.HasPrefix(l, "remove ") && firstRemove < 0:
			firstRemove = i
		}
	}
	if !(lastAdd < firstProfile && firstProfile < firstRemove) {
		t.Fatalf("order must be rules, profiles, removals; got add<=%d profile@%d remove@%d: %v", lastAdd, firstProfile, firstRemove, f.log)
	}
	// Management rules are added before any other.
	seenOther := false
	for _, l := range f.log {
		if !strings.HasPrefix(l, "add ") {
			continue
		}
		if strings.Contains(l, WinMgmtGroup) && seenOther {
			t.Fatalf("a management rule was added after a non-management rule: %v", f.log)
		}
		if !strings.Contains(l, WinMgmtGroup) {
			seenOther = true
		}
	}
}

func TestWinNameCollisionWithForeignRuleRefused(t *testing.T) {
	_, wp := anyWin(t)
	st, _ := TranslateWindows(wp, WinTranslateOptions{})
	f := newFakeWin()
	f.rules = []WinRuleState{{Name: st.Rules[0].Name, Group: "Someone Else", Direction: "Inbound", Action: "Allow", Protocol: "Any", Profiles: "Any", Enabled: true}}
	m := newWinMgr(t, f, nil)
	if _, err := m.Apply(context.Background(), wp, ApplyOptions{}); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("name collision not refused: %v", err)
	}
	if len(f.rules) != 1 || f.rules[0].Group != "Someone Else" {
		t.Fatalf("foreign rule touched: %+v", f.rules)
	}
}

func TestWinDeadmanRollbackRestoresExactPreviousState(t *testing.T) {
	_, wp := anyWin(t)
	f := newFakeWin()
	f.rules = foreignRules()
	dm := winDeadman(t, f)
	m := newWinMgr(t, f, dm)
	ctx := context.Background()

	// A previous Phylax state: some of our rules in odd shape.
	prev := &WinState{Profiles: []WinProfileState{
		{Name: "Domain", Enabled: true, DefaultInbound: "Allow", DefaultOutbound: "Allow"},
		{Name: "Private", Enabled: false, DefaultInbound: "Block", DefaultOutbound: "Allow"},
		{Name: "Public", Enabled: true, DefaultInbound: "Block", DefaultOutbound: "Block"},
	}}
	f.profiles = prev.Profiles
	f.rules = append(f.rules,
		WinRuleState{Name: "Phylax Mgmt old", Group: WinMgmtGroup, Direction: "Outbound", Action: "Allow", Protocol: "TCP", RemotePorts: "8443", RemoteAddresses: "10.0.0.5/32", Profiles: "Any", Enabled: true},
		WinRuleState{Name: "Phylax Service old", Group: "Phylax Service", Direction: "Inbound", Action: "Allow", Protocol: "TCP", LocalPorts: "80,443", Profiles: "Any", Enabled: false})
	before, beforeAll, _ := readWin(f)

	res, err := m.Apply(ctx, wp, ApplyOptions{DeadmanID: "win-1", Timeout: 300 * time.Millisecond})
	if err != nil || !res.DeadmanArmed {
		t.Fatalf("%+v %v", res, err)
	}
	if now, _, _ := readWin(f); len(DiffWinStates(before, now)) == 0 {
		t.Fatal("apply changed nothing")
	}
	for i := 0; i < 100; i++ {
		if e, _ := dm.Get("win-1"); e.State == deadman.StateRolledBack {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if e, _ := dm.Get("win-1"); e.State != deadman.StateRolledBack {
		t.Fatalf("entry: %+v", e)
	}
	after, afterAll, _ := readWin(f)
	if d := DiffWinStates(before, after); len(d) != 0 || before.Hash() != after.Hash() {
		t.Fatalf("rollback not exact: %v", d)
	}
	if len(afterAll) != len(beforeAll) {
		t.Fatalf("rule count %d -> %d", len(beforeAll), len(afterAll))
	}
	// Foreign rules intact.
	for _, r := range foreignRules() {
		found := false
		for _, a := range afterAll {
			found = found || a == r
		}
		if !found {
			t.Errorf("foreign rule %q lost", r.Name)
		}
	}
}

func TestWinFailedApplyRollsBack(t *testing.T) {
	_, wp := anyWin(t)
	for _, mode := range []string{"deadman", "plain"} {
		t.Run(mode, func(t *testing.T) {
			f := newFakeWin()
			f.rules = foreignRules()
			var dm *deadman.Manager
			opt := ApplyOptions{}
			if mode == "deadman" {
				dm = winDeadman(t, f)
				opt = ApplyOptions{DeadmanID: "win-f", Timeout: time.Hour}
			}
			m := newWinMgr(t, f, dm)
			before, _, _ := readWin(f)
			f.failAt = 10 // somewhere in the middle of adding rules
			_, err := m.Apply(context.Background(), wp, opt)
			f.failAt = 0
			if err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("want the COM failure, got %v", err)
			}
			after, _, _ := readWin(f)
			if d := DiffWinStates(before, after); len(d) != 0 {
				t.Fatalf("partial apply not rolled back: %v", d)
			}
			if mode == "deadman" {
				if e, _ := dm.Get("win-f"); e.State != deadman.StateRolledBack {
					t.Fatalf("journal: %+v", e)
				}
			}
		})
	}
}

func TestWinVerifyFailureRollsBack(t *testing.T) {
	_, wp := anyWin(t)
	f := newFakeWin()
	vf := &verifyBreaker{fakeWin: f}
	m := NewWindows(WinOptions{NewBackend: func() (WinBackend, error) { return vf, nil }})
	before, _, _ := readWin(f)
	_, err := m.Apply(context.Background(), wp, ApplyOptions{})
	if !errors.Is(err, ErrVerify) {
		t.Fatalf("want ErrVerify, got %v", err)
	}
	after, _, _ := readWin(f)
	if d := DiffWinStates(before, after); len(d) != 0 {
		t.Fatalf("not rolled back: %v", d)
	}
}

// verifyBreaker silently drops one added rule, as if something removed it
// right after we added it.
type verifyBreaker struct {
	*fakeWin
	dropped bool
}

func (v *verifyBreaker) AddRule(r WinRuleState) error {
	if err := v.fakeWin.AddRule(r); err != nil {
		return err
	}
	if !v.dropped && strings.Contains(r.Name, WinMgmtGroup) {
		v.dropped = true
		return v.fakeWin.RemoveRule(r.Name)
	}
	return nil
}

func TestWinDriftDetection(t *testing.T) {
	_, wp := anyWin(t)
	f := newFakeWin()
	m := newWinMgr(t, f, nil)
	ctx := context.Background()
	want, _ := TranslateWindows(wp, WinTranslateOptions{})
	if _, err := m.Apply(ctx, wp, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	d, err := m.DetectDrift(ctx, want)
	if err != nil || !d.Clean || d.Hash != d.DeclaredHash {
		t.Fatalf("%+v %v", d, err)
	}
	clean := d.Hash

	// Tamper: disable a rule, delete a rule, add a rogue rule to our group, disable a profile.
	f.rules[0].Enabled = !f.rules[0].Enabled
	gone := f.rules[1].Name
	f.rules = append(f.rules[:1], f.rules[2:]...)
	f.rules = append(f.rules, WinRuleState{Name: "Phylax Egress rogue", Group: "Phylax Egress", Direction: "Outbound", Action: "Allow", Protocol: "Any", Profiles: "Any", Enabled: true})
	f.profiles[2].Enabled = false
	d, _ = m.DetectDrift(ctx, want)
	text := strings.Join(d.Diffs, "\n")
	if d.Clean || d.Hash == clean || !strings.Contains(text, gone) || !strings.Contains(text, "rogue") || !strings.Contains(text, "profile Public") || len(d.Diffs) != 4 {
		t.Fatalf("drift: %+v", d)
	}
	// Re-apply repairs.
	if _, err := m.Apply(ctx, wp, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if d, _ := m.DetectDrift(ctx, want); !d.Clean {
		t.Fatalf("still drifted: %v", d.Diffs)
	}
}

func TestWinPanicOpen(t *testing.T) {
	_, wp := anyWin(t)
	f := newFakeWin()
	f.rules = foreignRules()
	m := newWinMgr(t, f, nil)
	ctx := context.Background()
	if _, err := m.Apply(ctx, wp, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	before, _, _ := readWin(f)
	snap, err := m.PanicOpen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range f.profiles {
		if p.DefaultInbound != "Allow" || p.DefaultOutbound != "Allow" || !p.Enabled {
			t.Errorf("profile not open: %+v", p)
		}
	}
	now, all, _ := readWin(f)
	for _, r := range now.Rules {
		if r.Action == "Block" {
			t.Errorf("our block rule survived: %s", r.Name)
		}
	}
	if len(foreignBlockers(all)) != 1 {
		t.Error("foreign block rule must be left alone and still reported")
	}
	if err := m.Restore(ctx, snap); err != nil {
		t.Fatal(err)
	}
	after, _, _ := readWin(f)
	if d := DiffWinStates(before, after); len(d) != 0 {
		t.Fatalf("restore after panic open not exact: %v", d)
	}
}
