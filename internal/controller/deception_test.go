package controller

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/honeytokens"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

// honeyManifest is the real example manifest plus a domain controller with the
// AD honeytoken kinds.
func honeyManifest(t *testing.T) *manifest.Manifest {
	t.Helper()
	m := realManifest(t)
	h := m.Hosts["ad"]
	h.Roles = append(h.Roles, manifest.RoleDecoys)
	m.Hosts["ad"] = h
	m.Decoys["ad"] = manifest.HostDecoys{Domain: "corp.example",
		Listeners:   []manifest.DecoyListener{{Kind: "smb", Port: 4450}},
		Honeytokens: []manifest.Honeytoken{{Kind: "ad_spn"}, {Kind: "ad_asrep"}, {Kind: "ad_admin"}}}
	return m
}

func newHoneyController(t *testing.T, dir string, v *vault.Vault) *Controller {
	t.Helper()
	cfg := Config{AgentListen: "127.0.0.1:0", DataDir: dir}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	opt := Options{}
	if v != nil {
		opt.Vault = v
	}
	c, err := New(context.Background(), cfg, opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func newVault(t *testing.T) *vault.Vault {
	t.Helper()
	v, err := vault.Create(filepath.Join(t.TempDir(), "vault.age"), []byte("pass"), vault.Options{WorkFactor: 10})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func setup(t *testing.T) (*Controller, *vault.Vault, string) {
	t.Helper()
	dir, v := t.TempDir(), newVault(t)
	c := newHoneyController(t, dir, v)
	if err := c.SetConfigInputs(context.Background(), ConfigInputs{Manifest: honeyManifest(t), Rules: realRules(t)}); err != nil {
		t.Fatal(err)
	}
	return c, v, dir
}

func allSecrets(t *testing.T, c *Controller) []string {
	t.Helper()
	var out []string
	for _, tk := range c.honeyTokens() {
		if tk.Secret != "" {
			out = append(out, tk.Secret)
		}
	}
	for _, s := range c.HoneytokenSteps() {
		for _, ref := range s.SecretRefs {
			v, ok := c.vaultGet(ref)
			if !ok || v == "" {
				t.Fatalf("vault lacks %s", ref)
			}
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		t.Fatal("no secrets generated; the test checks nothing")
	}
	return out
}

func TestHoneytokensGeneratePersistEncryptAndReload(t *testing.T) {
	ctx := context.Background()
	c, v, dir := setup(t)
	hosts, err := c.GenerateHoneytokens(ctx)
	if err != nil || len(hosts) < 3 {
		t.Fatalf("generated for %v: %v", hosts, err)
	}
	secrets := allSecrets(t, c)
	seeds := c.HoneytokenSeeds()
	if len(seeds["honeytoken.accounts"]) == 0 || len(seeds["honeytoken.spns"]) == 0 || len(seeds["honeytoken.paths"]) == 0 {
		t.Fatalf("seeds: %v", seeds)
	}

	// Nothing secret in the store: the metadata record and the whole db file.
	rec, err := c.Store().MetaGet(ctx, honeyMetaKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if leaks(rec, s) {
			t.Fatalf("store record holds a secret: %.8s...", s)
		}
	}
	if raw, _ := readFile(c.Store().Path()); raw != "" {
		for _, s := range secrets {
			if leaks(raw, s) {
				t.Fatalf("database file holds a secret")
			}
		}
	}

	// Idempotent: a second call generates nothing and the registry is unchanged.
	if again, err := c.GenerateHoneytokens(ctx); err != nil || len(again) != 0 {
		t.Fatalf("second generation: %v %v", again, err)
	}
	before := c.honeyTokens()

	// Restart: same tokens, secrets back from the vault.
	c.Close()
	c2 := newHoneyController(t, dir, v)
	after := c2.honeyTokens()
	if len(after) != len(before) {
		t.Fatalf("%d tokens after restart, had %d", len(after), len(before))
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("token %d changed across restart:\n%+v\n%+v", i, before[i], after[i])
		}
	}
	if len(c2.HoneytokenSteps()) != len(c.HoneytokenSteps()) {
		t.Error("steps lost across restart")
	}
}

func TestHoneytokensWithoutVaultRefusedAndLockedVaultDegrades(t *testing.T) {
	ctx := context.Background()
	c := newHoneyController(t, t.TempDir(), nil)
	if err := c.SetConfigInputs(ctx, ConfigInputs{Manifest: honeyManifest(t)}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GenerateHoneytokens(ctx); err == nil {
		t.Fatal("generated secrets with nowhere encrypted to keep them")
	}

	c, v, dir := setup(t)
	if _, err := c.GenerateHoneytokens(ctx); err != nil {
		t.Fatal(err)
	}
	c.Close()
	v.Lock()
	c2 := newHoneyController(t, dir, v)
	if !hasAlert(c2, "", "honeytokens.secrets_unavailable") {
		t.Error("a locked vault must alert")
	}
	blind := 0
	for _, tk := range c2.honeyTokens() {
		if tk.Secret == "" && tokenHasSecret(tk) {
			blind++
		}
	}
	if blind == 0 {
		t.Fatal("secrets present although the vault is locked")
	}
	if len(c2.HoneytokenSeeds()["honeytoken.accounts"]) == 0 {
		t.Error("seeds need no secret and must survive a locked vault")
	}
	if err := v.Unlock([]byte("pass")); err != nil {
		t.Fatal(err)
	}
	if err := c2.ReloadHoneytokenSecrets(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tk := range c2.honeyTokens() {
		if tk.Secret == "" && tokenHasSecret(tk) {
			t.Fatalf("secret of %s not restored", tk.ID)
		}
	}
}

func TestAgentConfigCarriesDeceptionAndSeeds(t *testing.T) {
	ctx := context.Background()
	c, _, _ := setup(t)
	w0, _ := c.AgentConfigFor(ctx, "rocky-ecom")
	if _, err := c.GenerateHoneytokens(ctx); err != nil {
		t.Fatal(err)
	}
	w1, err := c.AgentConfigFor(ctx, "rocky-ecom")
	if err != nil || w1.Version == w0.Version {
		t.Fatalf("config did not change with the registry: %v %v", w1, err)
	}
	ver := &plan.ConfigVerifier{Key: c.PlanPublicKey(), HostID: "rocky-ecom", Store: plan.FileSeqStore{Path: filepath.Join(t.TempDir(), "s")}}
	cfg, err := ver.Verify(w1)
	if err != nil {
		t.Fatal(err)
	}
	d := cfg.Modules.Deception
	if d == nil || len(d.Listeners) == 0 || len(d.Tokens) == 0 || len(d.WatchPaths) == 0 {
		t.Fatalf("deception section: %+v", d)
	}
	scoredOK := false
	for _, p := range d.ScoredPorts {
		for _, l := range d.Listeners {
			if l.Port == p {
				t.Errorf("decoy listener %s on scored port %d", l.Kind, p)
			}
		}
		scoredOK = true
	}
	if !scoredOK {
		t.Error("scored ports missing from the section: the agent backstop would be blind")
	}
	// Decoy matching needs the secrets; the signature covers them.
	haveSecret := false
	for _, tk := range d.Tokens {
		haveSecret = haveSecret || tk.Secret != ""
	}
	if !haveSecret {
		t.Error("decoy host config lacks token secrets")
	}
	// Shell history files are not watched (the shell itself opens them).
	for _, p := range d.WatchPaths {
		if strings.HasSuffix(p, ".bash_history") {
			t.Errorf("watching %s alerts on its legitimate owner", p)
		}
	}
	// Seeds reach the detect section of every host, a non-decoy host included,
	// and it has no deception section.
	seeds := map[string]plan.ProfileSeed{}
	for _, s := range cfg.Modules.Detect.Seeds {
		seeds[s.Profile] = s
	}
	for _, p := range []string{"honeytoken.accounts", "honeytoken.spns", "honeytoken.paths"} {
		if len(seeds[p].Values) == 0 {
			t.Errorf("seed %s missing", p)
		}
	}
	wo, _ := c.AgentConfigFor(ctx, "ubuntu-wkst")
	ov := &plan.ConfigVerifier{Key: c.PlanPublicKey(), HostID: "ubuntu-wkst", Store: plan.FileSeqStore{Path: filepath.Join(t.TempDir(), "s")}}
	oc, err := ov.Verify(wo)
	if err != nil {
		t.Fatal(err)
	}
	if oc.Modules.Deception != nil {
		t.Error("a host without the decoys role got a deception section")
	}
	found := false
	for _, s := range oc.Modules.Detect.Seeds {
		found = found || s.Profile == "honeytoken.accounts"
	}
	if !found {
		t.Error("honeytoken seeds missing on a plain host")
	}
	// AD tokens are attributed to the DC and seeded as accounts and SPNs.
	var dc *plan.AgentConfig
	if w, _ := c.AgentConfigFor(ctx, "ad"); w != nil {
		dc, _ = (&plan.ConfigVerifier{Key: c.PlanPublicKey(), HostID: "ad", Store: plan.FileSeqStore{Path: filepath.Join(t.TempDir(), "s")}}).Verify(w)
	}
	if dc == nil || dc.Modules.Deception == nil || len(dc.Modules.Deception.Listeners) != 1 || dc.Modules.Deception.Listeners[0].Kind != "smb" {
		t.Fatalf("dc deception: %+v", dc)
	}
}

func TestDeceptionPlanHoldsNoSecretAndResolvesFromVault(t *testing.T) {
	ctx := context.Background()
	c, _, _ := setup(t)
	p, err := c.DeceptionPlan(ctx, "deception-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(c.catalog()); err != nil {
		t.Fatalf("plan does not validate against the action catalog: %v", err)
	}
	raw, _ := json.Marshal(p)
	for _, s := range allSecrets(t, c) {
		if leaks(string(raw), s) {
			t.Fatalf("plan JSON holds a secret value")
		}
	}
	plants, ads, checks := 0, 0, 0
	for _, n := range p.Nodes {
		switch n.Action {
		case "file.plant":
			plants++
			if n.Params["only_if_absent"] != true {
				t.Errorf("%s may replace an existing file", n.ID)
			}
			blob, err := c.stepSecrets(n)
			if err != nil {
				t.Fatalf("%s: %v", n.ID, err)
			}
			var m map[string]string
			_ = json.Unmarshal(blob, &m)
			if len(m["content"]) == 0 {
				t.Errorf("%s: no content secret resolved", n.ID)
			}
			if _, has := n.Params["content"]; has {
				t.Errorf("%s: content in the plan", n.ID)
			}
		case "ad.honey_account":
			ads++
			if _, has := n.Params["password"]; has || n.Target != "ad" {
				t.Errorf("ad node %s: %+v", n.ID, n)
			}
			blob, err := c.stepSecrets(n)
			if err != nil || !strings.Contains(string(blob), `"password"`) {
				t.Errorf("ad secrets %s: %s %v", n.ID, blob, err)
			}
		case "deception.decoy_check":
			checks++
		}
	}
	if plants < 4 || ads != 3 || checks < 3 {
		t.Fatalf("plants=%d ads=%d checks=%d", plants, ads, checks)
	}
}

func TestStepSecretsRefuseForeignVaultEntries(t *testing.T) {
	c, v, _ := setup(t)
	if _, err := v.Put("breakglass/root", vault.NewSecretString("hunter2"), ""); err != nil {
		t.Fatal(err)
	}
	node := func(ref string) plan.Node {
		return plan.Node{ID: "n", Action: "file.plant", Target: "h", Params: map[string]any{"path": "/x",
			"secret_params": []any{"content"}, "secret_refs": map[string]any{"content": ref}}}
	}
	for _, ref := range []string{"breakglass/root", "honeytoken/../breakglass/root", "", "honeytoken/missing/content"} {
		if b, err := c.stepSecrets(node(ref)); err == nil {
			t.Errorf("ref %q resolved: %s", ref, b)
		}
	}
	// Only the action's own secret parameter names.
	n := node("honeytoken/x/content")
	n.Params["secret_params"] = []any{"path"}
	if _, err := c.stepSecrets(n); err == nil {
		t.Error("arbitrary secret parameter accepted")
	}
	// An action that takes no secrets gets none, whatever the params say.
	n2 := plan.Node{ID: "n", Action: "file.write", Params: map[string]any{"secret_params": []any{"content"}}}
	if b, err := c.stepSecrets(n2); err != nil || b != nil {
		t.Errorf("file.write got secrets: %s %v", b, err)
	}
}

func TestHoneyAlertAttribution(t *testing.T) {
	ctx := context.Background()
	c, _, _ := setup(t)
	if _, err := c.GenerateHoneytokens(ctx); err != nil {
		t.Fatal(err)
	}
	var acct, spn string
	for _, tk := range c.honeyTokens() {
		if tk.Kind == honeytokens.KindADASREP {
			acct = tk.User
		}
		if tk.Kind == honeytokens.KindADSPN {
			spn = tk.SPN
		}
	}
	if acct == "" || spn == "" {
		t.Fatal("no AD tokens")
	}
	f := &evFeeder{t: t, c: c, seq: map[string]uint64{}, prev: map[string]string{}}
	t0 := time.Date(2027, 3, 6, 15, 0, 0, 0, time.UTC)
	// D15d as the rule emits it: entities carry the account only.
	al := f.add("ad", t0, "detect.alert", map[string]any{"rule": "D15d.honeytoken-auth", "title": "Logon attempt for a honey account", "severity": "critical", "tier": 1,
		"message": "x", "entities": map[string]any{"account": `CORP\` + acct, "source": "10.0.0.77", "service": "windows"},
		"evidence": []any{}})
	// D15e: only the evidence event names the SPN.
	al2 := f.add("ad", t0.Add(time.Second), "detect.alert", map[string]any{"rule": "D15e.honey-kerberos", "title": "Kerberos ticket for a honey SPN", "severity": "critical", "tier": 1,
		"message": "x", "entities": map[string]any{"source": "10.0.0.77"},
		"evidence": []any{map[string]any{"kind": "sec_event", "time": t0.Format(time.RFC3339Nano), "fields": map[string]any{"event_id": 4769, "service_name": spn}}}})
	// An ordinary alert is left alone.
	al3 := f.add("ad", t0.Add(2*time.Second), "detect.alert", map[string]any{"rule": "X1.other", "title": "Other", "severity": "high", "tier": 1,
		"message": "x", "entities": map[string]any{"account": "azul"}, "evidence": []any{}})
	c.recordAgentAlerts(ctx, []event.Event{al, al2, al3}, al3.Seq)
	rows, err := c.Store().Alerts(ctx, "open", 10)
	if err != nil || len(rows) != 3 {
		t.Fatalf("%+v %v", rows, err)
	}
	for _, r := range rows {
		var k alertKeys
		if err := json.Unmarshal([]byte(r.Keys), &k); err != nil {
			t.Fatal(err)
		}
		switch {
		case strings.HasPrefix(r.Rule, "D15"):
			if k.Entities["token_origin"] != "ad" || k.Entities["honeytoken"] == "" {
				t.Errorf("%s: not attributed: %v", r.Rule, k.Entities)
			}
		default:
			if k.Entities["token_origin"] != "" {
				t.Errorf("%s: attributed wrongly: %v", r.Rule, k.Entities)
			}
		}
	}
}

// leaks reports whether hay holds s verbatim or JSON-escaped.
func leaks(hay, s string) bool {
	esc, _ := json.Marshal(s)
	return strings.Contains(hay, s) || strings.Contains(hay, strings.Trim(string(esc), `"`))
}
