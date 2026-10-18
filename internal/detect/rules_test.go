package detect

import (
	"os"
	"path/filepath"
	"testing"
)

type alertrec struct {
	alerts []Alert
}

func (r *alertrec) Alert(a Alert) { r.alerts = append(r.alerts, a) }

func loadRules(t *testing.T, dir string) (*Engine, *alertrec) {
	t.Helper()
	r := &alertrec{}
	e := New(r)
	if err := e.Load(dir); err != nil {
		t.Fatal(err)
	}
	return e, r
}

// rulesDir finds the repo's rules directory (rules/ at the repo root).
func rulesDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.Abs(filepath.Join("..", "rules"))
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
		t.Fatalf("rules dir not found at %s", d)
	}
	return d
}

// TestRulesLoadAndHaveTests: every rule parses, has a unique id and a
// test reference (the CI requirement, enforced in Load).
func TestRulesLoadAndHaveTests(t *testing.T) {
	e, _ := loadRules(t, rulesDir(t))
	rules := e.Rules()
	if len(rules) == 0 {
		t.Fatal("no rules loaded")
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.ID] {
			t.Errorf("duplicate rule id %s", r.ID)
		}
		seen[r.ID] = true
		if r.Test == "" {
			t.Errorf("rule %s has no test reference", r.ID)
		}
		if r.Severity == "" || r.Tier < 0 || r.Tier > 2 {
			t.Errorf("rule %s: bad severity/tier", r.ID)
		}
	}
}

func fired(r *alertrec, id string) bool {
	for _, a := range r.alerts {
		if a.Rule == id {
			return true
		}
	}
	return false
}

func TestD1(t *testing.T) {
	e, r := loadRules(t, rulesDir(t))
	e.Handle("process_start", map[string]any{"pid": 10, "comm": "bash", "pservice": "web"})
	if !fired(r, "D1.service-spawns-shell") {
		t.Error("D1 should fire: service tree spawns bash")
	}
	e.Handle("process_start", map[string]any{"pid": 11, "comm": "bash"})
	e.Handle("process_start", map[string]any{"pid": 12, "comm": "nginx", "pservice": "web"})
	if len(r.alerts) != 1 {
		t.Errorf("D1 overfired: %v", r.alerts)
	}
}

func TestD2(t *testing.T) {
	e, r := loadRules(t, rulesDir(t))
	e.Handle("file_change", map[string]any{"path": "/var/www/html/x.php", "op": "created", "kind": "content"})
	if !fired(r, "D2.content-tamper") {
		t.Error("D2 should fire: untagged webroot script")
	}
	r.alerts = nil
	e.Handle("file_change", map[string]any{"path": "/var/www/html/x.php", "op": "created", "kind": "content", "tag": "plan-1"})
	if fired(r, "D2.content-tamper") {
		t.Error("D2 must not fire for our own (tagged) change")
	}
}

func TestD3(t *testing.T) {
	e, r := loadRules(t, rulesDir(t))
	e.Handle("listener_new", map[string]any{"laddr": "0.0.0.0", "lport": 4444})
	if !fired(r, "D3.new-listener") {
		t.Error("D3 should fire: undeclared listener")
	}
	r.alerts = nil
	e.Handle("listener_new", map[string]any{"laddr": "0.0.0.0", "lport": 80, "service": "web"})
	if fired(r, "D3.new-listener") {
		t.Error("D3 must not fire for a declared service listener")
	}
}

func TestD4(t *testing.T) {
	e, r := loadRules(t, rulesDir(t))
	e.Handle("connection_new", map[string]any{"state": "ESTABLISHED", "service": "web", "raddr": "203.0.113.7"})
	if !fired(r, "D4.unexpected-outbound") {
		t.Error("D4 should fire: service outbound to external peer")
	}
	r.alerts = nil
	e.Handle("connection_new", map[string]any{"state": "ESTABLISHED", "service": "web", "raddr": "127.0.0.1"})
	if fired(r, "D4.unexpected-outbound") {
		t.Error("D4 must not fire for loopback")
	}
}

func TestD5(t *testing.T) {
	e, r := loadRules(t, rulesDir(t))
	e.Handle("hidden_exec", map[string]any{"pid": 7, "exe": "/tmp/.x (deleted)"})
	if !fired(r, "D5.hidden-exec") {
		t.Error("D5 should fire: deleted executable")
	}
}

func TestD5b(t *testing.T) {
	e, r := loadRules(t, rulesDir(t))
	e.Handle("ld_preload", map[string]any{"pid": 9, "preload": "/lib/rootkit.so"})
	if !fired(r, "D5b.ld-preload") {
		t.Error("D5b should fire: LD_PRELOAD set")
	}
}

func TestD6(t *testing.T) {
	e, r := loadRules(t, rulesDir(t))
	e.Handle("file_change", map[string]any{"path": "/etc/cron.d/x", "op": "created", "kind": "persistence"})
	if !fired(r, "D6.persistence-created") {
		t.Error("D6 should fire: untagged persistence write")
	}
	r.alerts = nil
	e.Handle("file_change", map[string]any{"path": "/etc/cron.d/x", "op": "created", "kind": "persistence", "tag": "plan-1"})
	if fired(r, "D6.persistence-created") {
		t.Error("D6 must not fire for our own cron")
	}
}

func TestD7(t *testing.T) {
	e, r := loadRules(t, rulesDir(t))
	e.Handle("file_change", map[string]any{"path": "/etc/shadow", "op": "modified", "kind": "config"})
	if !fired(r, "D7.account-change") {
		t.Error("D7 should fire: shadow modified untagged")
	}
}

func TestD10(t *testing.T) {
	e, r := loadRules(t, rulesDir(t))
	e.Handle("log_cleared", map[string]any{"file": "auth.log", "op": "truncated"})
	if !fired(r, "D10.defense-evasion") {
		t.Error("D10 should fire: log cleared")
	}
}

func TestD10b(t *testing.T) {
	e, r := loadRules(t, rulesDir(t))
	e.Handle("firewall_change", map[string]any{"what": "table deleted"})
	if !fired(r, "D10b.firewall-tamper") {
		t.Error("D10b should fire: untagged firewall change")
	}
}

func TestD11(t *testing.T) {
	e, r := loadRules(t, rulesDir(t))
	e.Handle("hidden_pid", map[string]any{"pid": 4242, "comm": "miner"})
	if !fired(r, "D11.rootkit") {
		t.Error("D11 should fire: hidden pid")
	}
}

func TestD12(t *testing.T) {
	e, r := loadRules(t, rulesDir(t))
	e.Handle("denied_egress", map[string]any{"raddr": "198.51.100.1", "rport": 8443, "pid": 5})
	if !fired(r, "D12.denied-egress") {
		t.Error("D12 should fire: denied egress")
	}
}

func TestD13(t *testing.T) {
	e, r := loadRules(t, rulesDir(t))
	e.Handle("sinkhole_catch", map[string]any{"raddr": "198.51.100.1", "rport": 8443, "pid": 5, "bytes": 512})
	if !fired(r, "D13.sinkhole-catch") {
		t.Error("D13 should fire: sinkhole catch")
	}
}

// TestCountWindow: a count rule fires only once the threshold is met.
func TestCountWindow(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "c.yml"), []byte(`
id: C.test
when:
  event: tick
  count:
    window: 1m
    gte: 3
severity: info
tier: 1
test: C.test
`), 0o644)
	e, r := loadRules(t, dir)
	e.Handle("tick", map[string]any{"pid": 1})
	e.Handle("tick", map[string]any{"pid": 1})
	if len(r.alerts) != 0 {
		t.Fatal("should not fire below threshold")
	}
	e.Handle("tick", map[string]any{"pid": 1})
	if !fired(r, "C.test") {
		t.Fatal("should fire at threshold")
	}
}

// TestCooldown: the same rule+key does not re-alert inside the cooldown.
func TestCooldown(t *testing.T) {
	e, r := loadRules(t, rulesDir(t))
	e.Handle("log_cleared", map[string]any{"file": "auth.log"})
	e.Handle("log_cleared", map[string]any{"file": "auth.log"})
	if len(r.alerts) != 1 {
		t.Fatalf("want 1 alert (cooldown), got %d", len(r.alerts))
	}
	e.Handle("log_cleared", map[string]any{"file": "syslog"})
	if len(r.alerts) != 2 {
		t.Fatalf("different key should alert, got %d", len(r.alerts))
	}
}

// TestD8 (T07): a DCSync-shaped 4662 from a non-DC account fires;
// the same from a DC does not.
func TestD8(t *testing.T) {
	e, r := loadRules(t, rulesDir(t))
	e.Handle("sec_event", map[string]any{
		"event_id": 4662, "account": "svc-backup", "rights": "DS-Replication-Get-Changes",
	})
	if !fired(r, "D8.credential-theft") {
		t.Error("D8 should fire: DCSync from non-DC account")
	}
	// separate engine: the dedupe key would otherwise mask the negative
	e2, r2 := loadRules(t, rulesDir(t))
	e2.Handle("sec_event", map[string]any{
		"event_id": 4662, "account": "DC-1", "rights": "DS-Replication-Get-Changes",
	})
	if fired(r2, "D8.credential-theft") {
		t.Error("D8 should not fire: replication rights from a DC")
	}
}

// TestD9: an admin logon type 3 from an undeclared source fires.
func TestD9(t *testing.T) {
	e, r := loadRules(t, rulesDir(t))
	e.Handle("sec_event", map[string]any{"event_id": 4624, "logon_type": 3, "source": "10.9.9.9"})
	if !fired(r, "D9.lateral-movement") {
		t.Error("D9 should fire: remote admin logon from undeclared source")
	}
}

// TestD14 (T13, local leg): an untagged device config commit fires.
func TestD14(t *testing.T) {
	e, r := loadRules(t, rulesDir(t))
	e.Handle("device_config", map[string]any{"device": "palo-1", "change": "commit"})
	if !fired(r, "D14.device-tamper") {
		t.Error("D14 should fire: untagged device commit")
	}
}

// TestNotIn: sanity for the not_in spec (used by D8's DC exclusion).
func TestNotIn(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "n.yml"), []byte(`
id: N.test
when:
  event: e
  all:
    - x: {not_in: [a, b]}
severity: info
tier: 1
test: N.test
`), 0o644)
	e, r := loadRules(t, dir)
	e.Handle("e", map[string]any{"x": "a"})
	if fired(r, "N.test") {
		t.Error("not_in should reject listed value")
	}
	e.Handle("e", map[string]any{"x": "c"})
	if !fired(r, "N.test") {
		t.Error("not_in should accept unlisted value")
	}
}

func TestD8Debug(t *testing.T) {
	e, r := loadRules(t, rulesDir(t))
	e.Handle("sec_event", map[string]any{
		"event_id": 4662, "account": "DC-1", "rights": "DS-Replication-Get-Changes",
	})
	for _, a := range r.alerts {
		t.Logf("FIRE: rule=%s key=%s", a.Rule, a.Key)
	}
}

// TestNotSpec: sanity for the {not: {re: ...}} spec.
func TestNotSpec(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "n.yml"), []byte(`
id: N.not
when:
  event: e
  all:
    - x: {not: {re: "^(a|b)$"}}
severity: info
tier: 1
test: N.not
`), 0o644)
	e, r := loadRules(t, dir)
	e.Handle("e", map[string]any{"x": "c"})
	if !fired(r, "N.not") {
		t.Error("not:{re} should accept non-matching value")
	}
}

// TestD11LDPreload (T12 local leg): an LD_PRELOAD injection fires D11;
// a kernel taint change fires too.
func TestD11LDPreload(t *testing.T) {
	e, r := loadRules(t, rulesDir(t))
	e.Handle("ld_preload", map[string]any{"pid": 777, "preload": "/tmp/evil.so"})
	if !fired(r, "D11.ld-preload") {
		t.Error("D11 should fire: LD_PRELOAD injection")
	}
	e.Handle("kernel_taint", map[string]any{"old": "", "new": "G"})
	if !fired(r, "D11.kernel-taint") {
		t.Error("D11 should fire: kernel taint change")
	}
}
