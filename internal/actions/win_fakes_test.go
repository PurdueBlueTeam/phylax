package actions

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/firewall"
)

// ---- fake registry ----

type fakeReg struct {
	mu   sync.Mutex
	vals map[string]RegValue
	keys map[string]string // regPath -> "key" (for ValueNames)
	log  []string
}

func newFakeReg() *fakeReg { return &fakeReg{vals: map[string]RegValue{}, keys: map[string]string{}} }

func (r *fakeReg) Get(_ context.Context, key, name string) (RegValue, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.vals[regPath(key, name)]
	return v, ok, nil
}
func (r *fakeReg) Set(_ context.Context, key, name string, v RegValue) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.vals[regPath(key, name)] = v
	r.keys[regPath(key, name)] = name
	r.log = append(r.log, "set "+key+`\`+name)
	return nil
}
func (r *fakeReg) Delete(_ context.Context, key, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.vals, regPath(key, name))
	r.log = append(r.log, "delete "+key+`\`+name)
	return nil
}
func (r *fakeReg) ValueNames(_ context.Context, key string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pre := strings.ToLower(key) + `\`
	var out []string
	for k, name := range r.keys {
		if strings.HasPrefix(k, pre) && strings.EqualFold(k, regPath(key, name)) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}
func (r *fakeReg) put(key, name string, v RegValue) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.vals[regPath(key, name)] = v
	r.keys[regPath(key, name)] = name
}
func (r *fakeReg) dword(key, name string) (uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.vals[regPath(key, name)]
	return v.Num, ok
}
func (r *fakeReg) val(key, name string) (RegValue, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.vals[regPath(key, name)]
	return v, ok
}
func (r *fakeReg) nlog() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.log)
}

// ---- fake service configurer (shares unit state with fakeServices) ----

type fakeSvcCfg struct {
	mu      sync.Mutex
	cfg     map[string]*SvcConfig
	calls   []string
	running func(unit string) bool // live state from the fake service manager
}

func (f *fakeSvcCfg) Config(_ context.Context, u string) (SvcConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.cfg[strings.ToLower(u)]; ok {
		out := *c
		if f.running != nil {
			out.Running = f.running(u)
		}
		return out, nil
	}
	return SvcConfig{}, nil
}
func (f *fakeSvcCfg) SetStart(_ context.Context, u, start string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "start "+u+" "+start)
	c, ok := f.cfg[strings.ToLower(u)]
	if !ok {
		return fmt.Errorf("no service %s", u)
	}
	c.Start = start
	return nil
}

// ---- fake audit ----

type fakeAudit struct {
	mu sync.Mutex
	m  map[string]AuditSetting
}

func (f *fakeAudit) Get(_ context.Context, s string) (AuditSetting, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.m[strings.ToLower(s)], nil
}
func (f *fakeAudit) Set(_ context.Context, s string, a AuditSetting) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[strings.ToLower(s)] = a
	return nil
}

// ---- fake exec ----

type execCall struct {
	prog string
	args []string
}

type fakeExec struct {
	mu    sync.Mutex
	calls []execCall
	// reply returns stdout and exit code for a call.
	reply func(c execCall) (string, int)
}

func (f *fakeExec) Run(_ context.Context, prog string, args ...string) (string, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := execCall{prog, append([]string(nil), args...)}
	f.calls = append(f.calls, c)
	if f.reply == nil {
		return "", 0, nil
	}
	out, code := f.reply(c)
	return out, code, nil
}
func (f *fakeExec) joined() []string {
	var out []string
	for _, c := range f.calls {
		out = append(out, c.prog+" "+strings.Join(c.args, " "))
	}
	return out
}

// ---- fake events ----

type fakeEvents struct {
	n      int
	latest time.Time
}

func (f fakeEvents) Count(context.Context, string, []int, time.Time) (EventCount, error) {
	return EventCount{N: f.n, Latest: f.latest}, nil
}

// ---- fake defender ----

type fakeDefender struct {
	mu       sync.Mutex
	excl     []Exclusion
	realtime bool
	calls    []string
}

func (f *fakeDefender) Exclusions(context.Context) ([]Exclusion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Exclusion(nil), f.excl...), nil
}
func (f *fakeDefender) AddExclusion(_ context.Context, e Exclusion) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.excl = append(f.excl, e)
	f.calls = append(f.calls, "add "+e.String())
	return nil
}
func (f *fakeDefender) RemoveExclusion(_ context.Context, e Exclusion) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keep []Exclusion
	for _, x := range f.excl {
		if x != e {
			keep = append(keep, x)
		}
	}
	f.excl = keep
	f.calls = append(f.calls, "remove "+e.String())
	return nil
}
func (f *fakeDefender) RealtimeEnabled(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.realtime, nil
}
func (f *fakeDefender) SetRealtime(_ context.Context, on bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.realtime = on
	return nil
}

// ---- fake windows firewall backend ----

type fakeFW struct {
	mu       sync.Mutex
	profiles []firewall.WinProfileState
	rules    map[string]firewall.WinRuleState
}

func newFakeFW() *fakeFW {
	f := &fakeFW{rules: map[string]firewall.WinRuleState{}}
	for _, n := range firewall.WinProfileNames {
		f.profiles = append(f.profiles, firewall.WinProfileState{Name: n, Enabled: true, DefaultInbound: "Block", DefaultOutbound: "Allow"})
	}
	f.rules["Remote Desktop (foreign)"] = firewall.WinRuleState{Name: "Remote Desktop (foreign)", Group: "Remote Desktop",
		Direction: "Inbound", Action: "Allow", Protocol: "TCP", LocalPorts: "3389", Profiles: "Any", Enabled: true}
	return f
}

func (f *fakeFW) backend() (firewall.WinBackend, error) { return &fwBackend{f}, nil }

type fwBackend struct{ f *fakeFW }

func (b *fwBackend) Profiles() ([]firewall.WinProfileState, error) {
	b.f.mu.Lock()
	defer b.f.mu.Unlock()
	return append([]firewall.WinProfileState(nil), b.f.profiles...), nil
}
func (b *fwBackend) SetProfile(p firewall.WinProfileState) error {
	b.f.mu.Lock()
	defer b.f.mu.Unlock()
	for i := range b.f.profiles {
		if b.f.profiles[i].Name == p.Name {
			b.f.profiles[i] = p
		}
	}
	return nil
}
func (b *fwBackend) Rules() ([]firewall.WinRuleState, error) {
	b.f.mu.Lock()
	defer b.f.mu.Unlock()
	var out []firewall.WinRuleState
	for _, r := range b.f.rules {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
func (b *fwBackend) AddRule(r firewall.WinRuleState) error {
	b.f.mu.Lock()
	defer b.f.mu.Unlock()
	b.f.rules[r.Name] = r
	return nil
}
func (b *fwBackend) UpdateRule(r firewall.WinRuleState) error { return b.AddRule(r) }
func (b *fwBackend) RemoveRule(n string) error {
	b.f.mu.Lock()
	defer b.f.mu.Unlock()
	delete(b.f.rules, n)
	return nil
}
func (b *fwBackend) Close() error { return nil }

// ---- fake directory ----

type fakeAD struct {
	mu      sync.Mutex
	domain  string
	objs    map[string]*ADObject // by lower DN
	now     func() time.Time
	pwCalls []string
}

func newFakeAD(now func() time.Time) *fakeAD {
	return &fakeAD{domain: "DC=corp,DC=local", objs: map[string]*ADObject{}, now: now}
}

func (a *fakeAD) add(o ADObject) *ADObject {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := o
	a.objs[strings.ToLower(o.DN)] = &c
	return &c
}

func (a *fakeAD) user(sam string, enabled bool, rid string) ADObject {
	o := ADObject{DN: "CN=" + sam + ",CN=Users," + a.domain, SAM: sam, Class: "user", Enabled: enabled, SID: "S-1-5-21-1-2-3-" + rid}
	a.add(o)
	return o
}
func (a *fakeAD) group(sam string, members ...ADObject) ADObject {
	o := ADObject{DN: "CN=" + sam + ",CN=Users," + a.domain, SAM: sam, Class: "group", Enabled: true}
	for _, m := range members {
		o.Members = append(o.Members, m.DN)
	}
	a.add(o)
	return o
}
func (a *fakeAD) addMemberFix(group string, m ADObject) {
	g := a.objs[strings.ToLower(group)]
	g.Members = append(g.Members, m.DN)
}

func (a *fakeAD) DomainDN(context.Context) (string, error) { return a.domain, nil }
func (a *fakeAD) Find(_ context.Context, sam string) (ADObject, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, o := range a.objs {
		if strings.EqualFold(o.SAM, sam) {
			return *o, true, nil
		}
	}
	return ADObject{}, false, nil
}
func (a *fakeAD) Get(_ context.Context, dn string) (ADObject, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	o, ok := a.objs[strings.ToLower(dn)]
	if !ok {
		return ADObject{}, false, nil
	}
	return *o, true, nil
}
func (a *fakeAD) AdminCountSet(context.Context) ([]ADObject, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []ADObject
	for _, o := range a.objs {
		if o.AdminCount == 1 {
			out = append(out, *o)
		}
	}
	return out, nil
}
func (a *fakeAD) SetEnabled(_ context.Context, dn string, e bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.objs[strings.ToLower(dn)].Enabled = e
	return nil
}
func (a *fakeAD) SetAdminCount(_ context.Context, dn string, n int) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.objs[strings.ToLower(dn)].AdminCount = n
	return nil
}
func (a *fakeAD) SetPassword(_ context.Context, dn, pw string, must bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pwCalls = append(a.pwCalls, dn)
	a.objs[strings.ToLower(dn)].PwdLastSet = a.now()
	return nil
}
func (a *fakeAD) AddMember(_ context.Context, g, m string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	o := a.objs[strings.ToLower(g)]
	for _, x := range o.Members {
		if strings.EqualFold(x, m) {
			return nil
		}
	}
	o.Members = append(o.Members, m)
	return nil
}
func (a *fakeAD) RemoveMember(_ context.Context, g, m string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	o := a.objs[strings.ToLower(g)]
	var keep []string
	for _, x := range o.Members {
		if !strings.EqualFold(x, m) {
			keep = append(keep, x)
		}
	}
	o.Members = keep
	return nil
}

// winFixture is the account fixture plus the Windows fakes.
type winFixture struct {
	*fixture
	reg  *fakeReg
	svc  *fakeSvcCfg
	aud  *fakeAudit
	exe  *fakeExec
	def  *fakeDefender
	fw   *fakeFW
	ad   *fakeAD
	evts *fakeEvents
}

func newWinFixture(t *testing.T) *winFixture {
	t.Helper()
	f := &winFixture{fixture: newFixture(t),
		reg: newFakeReg(), svc: &fakeSvcCfg{cfg: map[string]*SvcConfig{}}, aud: &fakeAudit{m: map[string]AuditSetting{}},
		exe: &fakeExec{}, def: &fakeDefender{realtime: true}, fw: newFakeFW(), evts: &fakeEvents{}}
	f.ad = newFakeAD(f.env.Now)
	f.svc.running = func(u string) bool {
		st, _ := f.env.Services.State(context.Background(), u)
		return st.Active
	}
	f.env.Win = WinEnv{Reg: f.reg, Svc: f.svc, Audit: f.aud, Exec: f.exe, Events: f.evts, Defender: f.def,
		Firewall: f.fw.backend, AD: f.ad, DepotDir: `C:\ProgramData\phylax\depot`}
	return f
}

// setOS sets the build identity the Zerologon logic reads.
func (f *winFixture) setOS(build string, ubr uint64, product string) {
	f.reg.put(ntCurrentVer, "CurrentBuildNumber", RegValue{Type: "sz", Str: build})
	f.reg.put(ntCurrentVer, "UBR", RegValue{Type: "dword", Num: ubr})
	f.reg.put(productOptions, "ProductType", RegValue{Type: "sz", Str: product})
}
