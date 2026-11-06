package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/creds"
	"github.com/PurdueBlueTeam/phylax/internal/devices"
	"github.com/PurdueBlueTeam/phylax/internal/devices/palo"
	"github.com/PurdueBlueTeam/phylax/internal/devices/palo/palotest"
	"github.com/PurdueBlueTeam/phylax/internal/devices/palo/xmlapi"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

const (
	palPW     = "PALO-PW-SECRET-7731"
	splPW     = "SPLUNK-PW-SECRET-4402"
	hecToken  = "11111111-2222-3333-4444-555555555555"
	paloCfg   = `<config version="11.0.0"><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase><security><rules/></rulebase></entry></vsys><deviceconfig><system><hostname>pa1</hostname><permitted-ip><entry name="0.0.0.0/0"/></permitted-ip></system></deviceconfig></entry></devices></config>`
	splunkNew = "phylax_idx"
)

// miniSplunk is a splunkd management API with just what splunk.hec_setup uses.
type miniSplunk struct {
	mu      sync.Mutex
	indexes map[string]bool
	tokens  map[string]string
	hecOff  bool
}

func (s *miniSplunk) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, p, _ := r.BasicAuth(); u != "admin" || p != splPW {
		http.Error(w, "unauthorized", 401)
		return
	}
	_ = r.ParseForm()
	ent := func(name string, c map[string]any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"entry": []any{map[string]any{"name": name, "content": c}}})
	}
	const hec = "/servicesNS/nobody/splunk_httpinput/data/inputs/http"
	path := r.URL.Path
	switch {
	case path == "/services/data/indexes" && r.Method == http.MethodPost:
		s.indexes[r.PostForm.Get("name")] = true
		ent(r.PostForm.Get("name"), nil)
	case strings.HasPrefix(path, "/services/data/indexes/"):
		n := strings.TrimPrefix(path, "/services/data/indexes/")
		if !s.indexes[n] {
			http.Error(w, "nf", 404)
			return
		}
		ent(n, nil)
	case path == hec+"/http":
		if r.Method == http.MethodPost {
			s.hecOff = r.PostForm.Get("disabled") == "1"
		}
		ent("http", map[string]any{"disabled": s.hecOff})
	case path == hec && r.Method == http.MethodPost:
		s.tokens[r.PostForm.Get("name")] = r.PostForm.Get("index")
		ent(r.PostForm.Get("name"), nil)
	case strings.HasPrefix(path, hec+"/"):
		n := strings.TrimPrefix(path, hec+"/")
		idx, ok := s.tokens[n]
		if !ok {
			http.Error(w, "nf", 404)
			return
		}
		ent(n, map[string]any{"index": idx, "disabled": false, "token": hecToken})
	default:
		http.Error(w, "unknown "+path, 404)
	}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type devFixture struct {
	c      *Controller
	dir    *Directory
	vlt    *vault.Vault
	pa     *palotest.Server
	spl    *miniSplunk
	data   string
	logs   *bytes.Buffer
	inflt  atomic.Int32
	maxInf atomic.Int32
}

func newDevFixture(t *testing.T) *devFixture {
	t.Helper()
	f := &devFixture{data: filepath.Join(t.TempDir(), "data"), logs: &bytes.Buffer{}}
	f.pa = palotest.New()
	t.Cleanup(f.pa.Close)
	f.pa.SeedRunning(paloCfg)
	f.pa.AddAdmin("phylax", palPW)
	f.spl = &miniSplunk{indexes: map[string]bool{"main": true}, tokens: map[string]string{}, hecOff: true}
	ssrv := httptest.NewTLSServer(f.spl)
	t.Cleanup(ssrv.Close)

	v, err := vault.Create(filepath.Join(t.TempDir(), "vault.age"), []byte("pass"), vault.Options{WorkFactor: 10})
	if err != nil {
		t.Fatal(err)
	}
	f.vlt = v
	if _, err := v.Put(creds.VaultKey("palo1", "phylax"), vault.NewSecretString(palPW), "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put(creds.VaultKey("debian-splunk", "admin"), vault.NewSecretString(splPW), "test"); err != nil {
		t.Fatal(err)
	}

	cfg := Config{AgentListen: "127.0.0.1:0", DataDir: f.data}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	lg := slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c, err := New(context.Background(), cfg, Options{Logger: lg})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	f.c = c

	m := &manifest.Manifest{
		Devices: map[string]manifest.Device{"palo1": {Vendor: "panos", Mgmt: "palo1.lab"}},
		Hosts:   map[string]manifest.Host{"debian-splunk": {IP: "10.0.0.9"}},
	}
	counting := &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		n := f.inflt.Add(1)
		for {
			mx := f.maxInf.Load()
			if n <= mx || f.maxInf.CompareAndSwap(mx, n) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond) // widen any overlap
		defer f.inflt.Add(-1)
		return f.pa.Client().Transport.RoundTrip(r)
	})}
	dir, err := c.EnableDeviceExec(DeviceExecOptions{DirectoryOptions: DirectoryOptions{
		Manifest: func() *manifest.Manifest { return m }, Vault: v,
		TunePalo: func(_ string, cfg *palo.Config) {
			cfg.Transport = devices.Transport{HTTP: counting, Host: f.pa.URL}
			cfg.FreshHTTP = func() *http.Client { return counting }
			cfg.PollInterval, cfg.JobTimeout = 5*time.Millisecond, 10*time.Second
		},
		SplunkBase: func(string) string { return ssrv.URL }, SplunkHTTP: ssrv.Client()}})
	if err != nil {
		t.Fatal(err)
	}
	f.dir = dir
	return f
}

func (f *devFixture) paloACL() []string {
	st, _ := xmlapi.ParseXPath(palotest.PermittedIPPath)
	var out []string
	if n := f.pa.Running().Select(st); n != nil {
		for _, e := range n.Children {
			out = append(out, e.Attr("name"))
		}
	}
	return out
}

func (f *devFixture) run(t *testing.T, p plan.Plan, approveNodes ...string) PlanStatus {
	t.Helper()
	ctx := context.Background()
	if err := f.c.CreatePlan(ctx, p, "tester"); err != nil {
		t.Fatal(err)
	}
	dr, err := f.c.DryRun(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !dr.Approvable {
		t.Fatalf("dry run not approvable: %+v", dr)
	}
	if err := f.c.ApprovePlan(ctx, p.ID, "tester"); err != nil {
		t.Fatal(err)
	}
	for _, n := range approveNodes {
		if err := f.c.ApproveNode(ctx, p.ID, n, "tester", "ok"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.c.Apply(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	st, err := f.c.Wait(wctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func nodeState(st PlanStatus, id string) NodeStatus { return st.Nodes[id] }

func TestDeviceAndSplunkNodesEndToEnd(t *testing.T) {
	f := newDevFixture(t)
	ctx := context.Background()
	mk := func(id string) plan.Plan {
		return plan.Plan{ID: id, OnFailure: plan.StopDependents, Nodes: []plan.Node{
			{ID: "acl", Action: "palo.permitted_ips", Target: "palo1", Params: map[string]any{"add": "127.0.0.1"}, Risk: plan.RiskLockout},
			{ID: "hec", Action: "splunk.hec_setup", Target: "debian-splunk", Params: map[string]any{"index": splunkNew, "token_name": "phylax-hec"}, Risk: plan.RiskService}}}
	}

	// Without the Network role's console acknowledgement the Palo node is
	// refused (PAN-OS has no commit-confirm); the Splunk node is unaffected.
	st := f.run(t, mk("gate-no-ack"), "acl")
	if st.State != PlanFailed {
		t.Fatalf("state %s, want failed: %+v", st.State, st)
	}
	if n := nodeState(st, "acl"); n.State != plan.StateFailed || !strings.Contains(strings.ToLower(n.Reason), "console") {
		t.Fatalf("acl node %+v", n)
	}
	if acl := f.paloACL(); len(acl) != 1 || acl[0] != "0.0.0.0/0" {
		t.Fatalf("the device changed without an ack: %v", acl)
	}
	if st := nodeState(st, "hec"); st.State != plan.StateVerified {
		t.Fatalf("splunk node %+v", st)
	}

	// With the acknowledgement (audited, per plan node) both run to the end.
	if err := f.c.CreatePlan(ctx, mk("gate-ack"), "tester"); err != nil {
		t.Fatal(err)
	}
	if err := f.c.AckConsole(ctx, "gate-ack", "hec", "net-op"); err == nil {
		t.Fatal("ack accepted for a Splunk node")
	}
	if err := f.c.AckConsole(ctx, "gate-ack", "acl", " "); err == nil {
		t.Fatal("ack accepted without an operator")
	}
	if err := f.c.AckConsole(ctx, "gate-ack", "nope", "net-op"); err == nil {
		t.Fatal("ack accepted for an unknown node")
	}
	if err := f.c.AckConsole(ctx, "gate-ack", "acl", "net-op"); err != nil {
		t.Fatal(err)
	}
	// The previous plan's ack does not carry over: this is its own plan node.
	dr, err := f.c.DryRun(ctx, "gate-ack")
	if err != nil || !dr.Approvable {
		t.Fatalf("dry run: %v %+v", err, dr)
	}
	if err := f.c.ApprovePlan(ctx, "gate-ack", "tester"); err != nil {
		t.Fatal(err)
	}
	if err := f.c.ApproveNode(ctx, "gate-ack", "acl", "tester", ""); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Apply(ctx, "gate-ack"); err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	st, err = f.c.Wait(wctx, "gate-ack")
	if err != nil {
		t.Fatal(err)
	}
	if st.State != PlanSucceeded {
		t.Fatalf("state %s: %+v", st.State, st)
	}
	if acl := f.paloACL(); len(acl) != 2 {
		t.Fatalf("ACL %v, want 0.0.0.0/0 + 127.0.0.1/32", acl)
	}
	f.spl.mu.Lock()
	idx, tok := f.spl.indexes[splunkNew], f.spl.tokens["phylax-hec"]
	f.spl.mu.Unlock()
	if !idx || tok != splunkNew {
		t.Fatalf("splunk state: index=%v token->%q", idx, tok)
	}

	// The audit log carries the acknowledgement with the operator.
	rows, _ := f.c.Store().Audit(ctx, 50)
	var found bool
	for _, r := range rows {
		if r.Action == ackAction && r.Actor == "net-op" && strings.Contains(r.Detail, "plan=gate-ack node=acl device=palo1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no audit row for the ack: %+v", rows)
	}

	// The new HEC token went to the vault, nowhere else.
	got, _, err := f.vlt.Get("out/gate-no-ack/hec/token")
	if err != nil || got.Reveal() != hecToken {
		t.Fatalf("token not in the vault: %v", err)
	}
	f.assertNoSecrets(t, palPW, splPW, hecToken, "key-phylax")
}

// assertNoSecrets greps the whole data directory (SQLite database and WAL
// included), the stored plan JSON and the controller log.
func (f *devFixture) assertNoSecrets(t *testing.T, secrets ...string) {
	t.Helper()
	_ = f.c.Store().Close() // checkpoint the WAL into the main file
	var files []string
	filepath.Walk(f.data, func(p string, i os.FileInfo, err error) error {
		if err == nil && !i.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	if len(files) == 0 {
		t.Fatal("no data files")
	}
	for _, p := range files {
		b, _ := os.ReadFile(p)
		for _, s := range secrets {
			if bytes.Contains(b, []byte(s)) {
				t.Errorf("secret %q found in %s", s[:6]+"...", p)
			}
		}
	}
	for _, s := range secrets {
		if strings.Contains(f.logs.String(), s) {
			t.Errorf("secret %q found in the controller log", s[:6]+"...")
		}
	}
	if !bytes.Contains(readAll(t, files, "phylax.db"), []byte("gate-ack")) {
		t.Error("sanity: the database was not inspected (plan id missing)")
	}
}

func readAll(t *testing.T, files []string, base string) []byte {
	var out []byte
	for _, p := range files {
		if strings.HasPrefix(filepath.Base(p), base) {
			b, _ := os.ReadFile(p)
			out = append(out, b...)
		}
	}
	return out
}

// Concurrent nodes on one device run one at a time.
func TestDeviceLockSerialisesNodes(t *testing.T) {
	f := newDevFixture(t)
	out := t.TempDir()
	var nodes []plan.Node
	for i := 0; i < 5; i++ {
		id := "snap" + string(rune('a'+i))
		nodes = append(nodes, plan.Node{ID: id, Action: "palo.snapshot", Target: "palo1",
			Params: map[string]any{"out": filepath.Join(out, id+".xml")}})
	}
	st := f.run(t, plan.Plan{ID: "lock", Nodes: nodes})
	if st.State != PlanSucceeded {
		t.Fatalf("state %s: %+v", st.State, st)
	}
	if mx := f.maxInf.Load(); mx != 1 {
		t.Fatalf("max concurrent device requests = %d, want 1 (per-device lock)", mx)
	}
	for _, n := range nodes {
		if _, err := os.Stat(n.Params["out"].(string)); err != nil {
			t.Fatal(err)
		}
	}
}

// The adapter is pooled while the vault credential is unchanged and rebuilt
// when it rotates; a locked vault stops execution cleanly.
func TestDirectoryPoolAndRotation(t *testing.T) {
	f := newDevFixture(t)
	ctx := context.Background()
	a1, err := f.dir.Palo(ctx, "palo1")
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := f.dir.Palo(ctx, "palo1")
	if a1 != a2 {
		t.Fatal("adapter not pooled")
	}
	f.pa.AddAdmin("phylax", "NEW-PW-98765")
	if _, err := f.vlt.Put(creds.VaultKey("palo1", "phylax"), vault.NewSecretString("NEW-PW-98765"), "rotate"); err != nil {
		t.Fatal(err)
	}
	a3, err := f.dir.Palo(ctx, "palo1")
	if err != nil || a3 == a1 {
		t.Fatalf("adapter not rebuilt after rotation: %v", err)
	}
	if _, err := f.dir.Palo(ctx, "nope"); err == nil {
		t.Fatal("unknown device accepted")
	}
	if _, err := f.dir.VyOS(ctx, "palo1"); err == nil {
		t.Fatal("vendor mismatch accepted")
	}
	// Lock honours the context.
	rel, err := f.dir.Lock(ctx, "palo1")
	if err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := f.dir.Lock(cctx, "palo1"); err == nil {
		t.Fatal("second lock acquired")
	}
	rel()
	f.vlt.Lock()
	if _, err := f.dir.Palo(ctx, "palo1"); err == nil || strings.Contains(err.Error(), "NEW-PW") {
		t.Fatalf("locked vault: %v", err)
	}
}

// A failing credential must not leak through error text.
func TestWrongCredentialErrorIsRedacted(t *testing.T) {
	f := newDevFixture(t)
	if _, err := f.vlt.Put(creds.VaultKey("palo1", "phylax"), vault.NewSecretString("WRONG-PW-55555"), "bad"); err != nil {
		t.Fatal(err)
	}
	_, err := f.dir.Palo(context.Background(), "palo1")
	if err == nil {
		t.Fatal("keygen with a wrong password succeeded")
	}
	if strings.Contains(err.Error(), "WRONG-PW-55555") {
		t.Fatalf("password in error: %v", err)
	}
}

// The CLI writes the acknowledgement straight into the store; the running
// controller finds it there, for that plan node only.
func TestAckConsoleFromCLIStore(t *testing.T) {
	f := newDevFixture(t)
	ctx := context.Background()
	p := plan.Plan{ID: "cli-ack", Nodes: []plan.Node{
		{ID: "acl", Action: "palo.permitted_ips", Target: "palo1", Params: map[string]any{"add": "127.0.0.1"}, Risk: plan.RiskLockout}}}
	if err := f.c.CreatePlan(ctx, p, "tester"); err != nil {
		t.Fatal(err)
	}
	x := f.c.dx
	if x.acked(ctx, "cli-ack", "acl") {
		t.Fatal("acked before anyone acknowledged")
	}
	if err := AckConsoleStored(ctx, f.c.Store(), "cli-ack", "acl", ""); err == nil {
		t.Fatal("anonymous ack accepted")
	}
	if err := AckConsoleStored(ctx, f.c.Store(), "no-such", "acl", "op"); err == nil {
		t.Fatal("ack for an unknown plan accepted")
	}
	if err := AckConsoleStored(ctx, f.c.Store(), "cli-ack", "acl", "op"); err != nil {
		t.Fatal(err)
	}
	if !x.acked(ctx, "cli-ack", "acl") || x.acked(ctx, "cli-ack", "other") || x.acked(ctx, "other", "acl") {
		t.Fatal("ack scope wrong")
	}
}

// Every registered action is routed by its Spec: API-only actions (palo, vyos,
// splunk REST) run on the controller, everything else (including the Splunk
// host filesystem action splunk.sidecar_off) on the target's agent.
func TestActionRoutingTable(t *testing.T) {
	want := map[string]bool{
		"palo.permitted_ips": true, "palo.snapshot": true, "vyos.snapshot": true, "palo.commit": true, "palo.apply": true, "vyos.apply": true,
		"splunk.rest": true, "splunk.password": true, "splunk.hec_setup": true,
	}
	reg := actions.Core()
	c := &Controller{reg: reg}
	for _, name := range reg.Names() {
		a, _ := reg.Get(name)
		if got := c.isLocalAction(name); got != want[name] || a.Spec().OnController() != want[name] {
			t.Errorf("%s: controller-run=%v, want %v", name, got, want[name])
		}
		ack := strings.HasPrefix(name, "palo.") || strings.HasPrefix(name, "vyos.")
		if needsConsoleAck(reg, name) != ack {
			t.Errorf("%s: console ack=%v, want %v", name, !ack, ack)
		}
	}
	for n := range want {
		if _, err := reg.Get(n); err != nil {
			t.Errorf("table names unregistered action %s", n)
		}
	}
	if c.isLocalAction("splunk.sidecar_off") {
		t.Fatal("splunk.sidecar_off must run on the agent")
	}
}

func TestSidecarOffDispatchedToAgent(t *testing.T) {
	f := newDevFixture(t) // device exec enabled
	if f.c.dx == nil {
		t.Fatal("device exec not enabled")
	}
	if f.c.isLocalNode(plan.Node{ID: "s", Action: "splunk.sidecar_off", Target: "debian-splunk"}) {
		t.Fatal("splunk.sidecar_off routed to the controller")
	}
	if !f.c.isLocalNode(plan.Node{ID: "h", Action: "splunk.hec_setup", Target: "debian-splunk"}) {
		t.Fatal("splunk.hec_setup not routed to the controller")
	}
}
