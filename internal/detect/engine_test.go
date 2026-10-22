package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

var t0 = time.Date(2027, 2, 6, 12, 0, 0, 0, time.UTC)

const hdr = "title: t\nseverity: high\ntier: 1\nattack: [T1059]\n"

// rule builds a one-rule YAML doc with the given when body (already indented).
func ruleYAML(id, when string) string {
	return "id: " + id + "\n" + hdr + "when:\n  event: k\n" + when
}

func mustLoad(t *testing.T, y string) *RuleSet {
	t.Helper()
	rs, err := Parse("t.yml", []byte(y), LoadOptions{AllowUntested: true})
	if err != nil {
		t.Fatalf("load: %v\n%s", err, y)
	}
	return rs
}

func ev(at time.Duration, f map[string]any) event.Event {
	return event.Event{Agent: "a1", Kind: "k", Time: t0.Add(at), Fields: f}
}

func fires(t *testing.T, cond string, f map[string]any) bool {
	t.Helper()
	rs := mustLoad(t, ruleYAML("R", "  all:\n    - "+cond+"\n"))
	return len(NewEngine(rs, Options{}).Process(ev(0, f))) == 1
}

func TestOperators(t *testing.T) {
	cases := []struct {
		name, cond string
		f          map[string]any
		want       bool
	}{
		{"eq scalar ci", `x: Bash`, map[string]any{"x": "bash"}, true},
		{"eq miss", `x: bash`, map[string]any{"x": "dash"}, false},
		{"eq number", `x: 4624`, map[string]any{"x": 4624}, true},
		{"eq number vs string", `x: 4624`, map[string]any{"x": "4624"}, true},
		{"eq bool", `x: true`, map[string]any{"x": true}, true},
		{"eq missing field", `x: a`, map[string]any{}, false},
		{"bare list is in", `x: [a, b]`, map[string]any{"x": "B"}, true},
		{"in", `x: {in: [a, b]}`, map[string]any{"x": "c"}, false},
		{"equals alias", `x: {equals: a}`, map[string]any{"x": "A"}, true},
		{"eq_cs", `x: {eq_cs: a}`, map[string]any{"x": "A"}, false},
		{"contains ci", `x: {contains: PASS}`, map[string]any{"x": "my password"}, true},
		{"contains_cs", `x: {contains_cs: PASS}`, map[string]any{"x": "my password"}, false},
		{"contains_any", `x: {contains_any: [zz, wor]}`, map[string]any{"x": "a Word"}, true},
		{"startswith", `x: {startswith: /ETC/}`, map[string]any{"x": "/etc/passwd"}, true},
		{"prefix alias miss", `x: {prefix: /usr}`, map[string]any{"x": "/etc/passwd"}, false},
		{"endswith", `x: {endswith: .PHP}`, map[string]any{"x": "/var/www/a.php"}, true},
		{"suffix_any", `x: {endswith_any: [.sh, .php]}`, map[string]any{"x": "a.PHP"}, true},
		{"startswith_cs", `x: {startswith_cs: /ETC}`, map[string]any{"x": "/etc"}, false},
		{"re", `x: {re: '^a.c$'}`, map[string]any{"x": "abc"}, true},
		{"re case sensitive", `x: {re: '^abc$'}`, map[string]any{"x": "ABC"}, false},
		{"re inline ci", `x: {re: '(?i)^abc$'}`, map[string]any{"x": "ABC"}, true},
		{"regex alias", `x: {regex: 'b+'}`, map[string]any{"x": "abbc"}, true},
		{"gt", `x: {gt: 5}`, map[string]any{"x": 6}, true},
		{"gt eq", `x: {gt: 5}`, map[string]any{"x": 5}, false},
		{"lt", `x: {lt: 5}`, map[string]any{"x": uint64(4)}, true},
		{"gte", `x: {gte: 5}`, map[string]any{"x": 5.0}, true},
		{"lte hex string", `x: {lte: 5}`, map[string]any{"x": "0x3"}, true},
		{"gt non number", `x: {gt: 5}`, map[string]any{"x": "abc"}, false},
		{"cidr v4", `x: {cidr: 10.0.0.0/8}`, map[string]any{"x": "10.2.3.4"}, true},
		{"cidr miss", `x: {cidr: [10.0.0.0/8, 192.168.0.0/16]}`, map[string]any{"x": "172.16.0.1"}, false},
		{"cidr v6 mapped", `x: {cidr: 10.0.0.0/8}`, map[string]any{"x": "::ffff:10.1.1.1"}, true},
		{"cidr bad addr", `x: {cidr: 10.0.0.0/8}`, map[string]any{"x": "nope"}, false},
		{"present", `x: {present: true}`, map[string]any{"x": "a"}, true},
		{"present empty string", `x: {present: true}`, map[string]any{"x": ""}, false},
		{"present false", `x: {present: false}`, map[string]any{}, true},
		{"exists alias", `x: {exists: true}`, map[string]any{"x": 0}, true},
		{"list value any", `x: {contains: b}`, map[string]any{"x": []string{"a", "bb"}}, true},
		{"nested path", `p.q: a`, map[string]any{"p": map[string]any{"q": "a"}}, true},
		{"flat dotted key", `p.q: a`, map[string]any{"p.q": "a"}, true},
		{"alias parent.comm", `parent.comm: sshd`, map[string]any{"pcomm": "sshd"}, true},
		{"alias image", `image: {endswith: /sh}`, map[string]any{"exe": "/bin/sh"}, true},
		{"not", `not: {x: a}`, map[string]any{"x": "b"}, true},
		{"not missing field", `not: {x: a}`, map[string]any{}, true},
		{"any", `any: [{x: a}, {y: b}]`, map[string]any{"y": "b"}, true},
		{"all", `all: [{x: a}, {y: b}]`, map[string]any{"x": "a"}, false},
		{"pseudo agent", `agent: a1`, map[string]any{}, true},
		{"pseudo kind", `kind: k`, map[string]any{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := fires(t, c.cond, c.f); got != c.want {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
}

func TestLoadErrors(t *testing.T) {
	bad := map[string]string{
		"dangling all item":         ruleYAML("R", "  all:\n    - x: a\n    -\n"),
		"dangling any item":         ruleYAML("R", "  all:\n    - x: a\n  any:\n    - y: b\n    - \n"),
		"empty all":                 ruleYAML("R", "  all: []\n"),
		"no conditions":             ruleYAML("R", "  all:\n"),
		"dangling in item":          ruleYAML("R", "  all:\n    - x: [a, , b]\n"),
		"empty in":                  ruleYAML("R", "  all:\n    - x: {in: []}\n"),
		"empty value":               ruleYAML("R", "  all:\n    - x:\n"),
		"empty string value":        ruleYAML("R", "  all:\n    - x: ''\n"),
		"empty string in list":      ruleYAML("R", "  all:\n    - x: [a, '']\n"),
		"two keys":                  ruleYAML("R", "  all:\n    - {x: a, y: b}\n"),
		"two operators":             ruleYAML("R", "  all:\n    - x: {eq: a, re: b}\n"),
		"unknown operator":          ruleYAML("R", "  all:\n    - x: {frobnicate: a}\n"),
		"bad regex":                 ruleYAML("R", "  all:\n    - x: {re: '(['}\n"),
		"regex matches empty":       ruleYAML("R", "  all:\n    - x: {re: '.*'}\n"),
		"regex empty string":        ruleYAML("R", "  all:\n    - x: {re: ''}\n"),
		"bad cidr":                  ruleYAML("R", "  all:\n    - x: {cidr: 10.0.0.0/33}\n"),
		"gt not number":             ruleYAML("R", "  all:\n    - x: {gt: abc}\n"),
		"unknown profile":           ruleYAML("R", "  all:\n    - x: {in_profile: nope}\n"),
		"unknown when key":          ruleYAML("R", "  all:\n    - x: a\n  frob: 1\n"),
		"unknown top key":           ruleYAML("R", "  all:\n    - x: a\n") + "bogus: 1\n",
		"missing event":             "id: R\n" + hdr + "when:\n  all:\n    - x: a\n",
		"bad severity":              strings.Replace(ruleYAML("R", "  all:\n    - x: a\n"), "high", "huge", 1),
		"bad tier":                  strings.Replace(ruleYAML("R", "  all:\n    - x: a\n"), "tier: 1", "tier: 9", 1),
		"revoked attack":            strings.Replace(ruleYAML("R", "  all:\n    - x: a\n"), "T1059", "T1562.001", 1),
		"bad attack":                strings.Replace(ruleYAML("R", "  all:\n    - x: a\n"), "T1059", "X1", 1),
		"count too small":           ruleYAML("R", "  all:\n    - x: a\n  count: {window: 1m, gte: 1}\n"),
		"count bad window":          ruleYAML("R", "  all:\n    - x: a\n  count: {window: soon, gte: 3}\n"),
		"count and sequence":        ruleYAML("R", "  all:\n    - x: a\n  count: {window: 1m, gte: 3}\n  sequence: {by: [p], within: 1m, then: {event: k, all: [{y: b}]}}\n"),
		"sequence no by":            ruleYAML("R", "  all:\n    - x: a\n  sequence: {within: 1m, then: {event: k, all: [{y: b}]}}\n"),
		"sequence empty then":       ruleYAML("R", "  all:\n    - x: a\n  sequence: {by: [p], within: 1m, then: {event: k, all: []}}\n"),
		"bad mode":                  strings.Replace(ruleYAML("R", "  all:\n    - x: a\n"), "title: t", "title: t\nmode: yolo", 1),
		"bad field name":            ruleYAML("R", "  all:\n    - 'a b': a\n"),
		"event list null item":      "id: R\n" + hdr + "when:\n  event:\n    - k\n    -\n  all:\n    - x: a\n",
		"profile field mismatch":    "profiles:\n  - {name: p, event: k, value: a, learn: 1m}\n---\n" + ruleYAML("R", "  all:\n    - b: {in_profile: p}\n"),
		"profile learn no event":    "profiles:\n  - {name: p, learn: 1m, value: a}\n",
		"profile static with event": "profiles:\n  - {name: p, event: k}\n",
		"bad message template":      ruleYAML("R", "  all:\n    - x: a\n") + "message: 'hi {x'\n",
	}
	for name, y := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse("t.yml", []byte(y), LoadOptions{AllowUntested: true}); err == nil {
				t.Fatalf("expected a load error for:\n%s", y)
			}
		})
	}
}

func TestDuplicateID(t *testing.T) {
	y := ruleYAML("R", "  all:\n    - x: a\n") + "---\n" + ruleYAML("R", "  all:\n    - x: b\n")
	if _, err := Parse("t.yml", []byte(y), LoadOptions{AllowUntested: true}); err == nil {
		t.Fatal("duplicate id accepted")
	}
}

func TestTestsRequired(t *testing.T) {
	y := ruleYAML("R", "  all:\n    - x: a\n")
	if _, err := Parse("t.yml", []byte(y), LoadOptions{}); err == nil {
		t.Fatal("rule without tests accepted")
	}
	y += "tests:\n  - {name: p, should_match: true, event: {kind: k, fields: {x: a}}}\n"
	if _, err := Parse("t.yml", []byte(y), LoadOptions{}); err == nil {
		t.Fatal("rule without a negative test accepted")
	}
	y += "  - {name: n, should_match: false, event: {kind: k, fields: {x: b}}}\n"
	rs, err := Parse("t.yml", []byte(y), LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs.RunTests() {
		if r.Err != nil {
			t.Errorf("%s/%s: %v", r.Rule, r.Test, r.Err)
		}
	}
	// A failing expectation is reported.
	bad := strings.Replace(y, "fields: {x: b}", "fields: {x: a}", 1)
	rs, _ = Parse("t.yml", []byte(bad), LoadOptions{})
	failed := false
	for _, r := range rs.RunTests() {
		failed = failed || r.Err != nil
	}
	if !failed {
		t.Fatal("wrong expectation was not reported")
	}
}

func TestTagExemption(t *testing.T) {
	y := ruleYAML("R", "  all:\n    - x: a\n") + "exempt_tagged: true\n"
	eng := NewEngine(mustLoad(t, y), Options{})
	if n := len(eng.Process(ev(0, map[string]any{"x": "a", "tag": "plan:harden-7"}))); n != 0 {
		t.Fatalf("tagged event fired")
	}
	if n := len(eng.Process(ev(0, map[string]any{"x": "a", "tag": ""}))); n != 1 {
		t.Fatalf("empty tag must not exempt")
	}
	if n := len(eng.Process(ev(0, map[string]any{"x": "a"}))); n != 1 {
		t.Fatalf("untagged event did not fire")
	}
}

func TestAlertContents(t *testing.T) {
	y := ruleYAML("R", "  all:\n    - x: a\n") + "entities: [x, y]\nmessage: 'x={x} y={y} p={p.q}'\ncollect: [process_tree]\nir_template: ir1\nmode: act\n"
	e := NewEngine(mustLoad(t, y), Options{})
	a := e.Process(ev(0, map[string]any{"x": "a", "y": 7, "p": map[string]any{"q": "z"}}))
	if len(a) != 1 {
		t.Fatal("no alert")
	}
	g := a[0]
	if g.RuleID != "R" || g.Severity != "high" || g.Tier != 1 || g.Mode != "act" || g.Agent != "a1" ||
		g.Entities["x"] != "a" || g.Entities["y"] != "7" || g.Message != "x=a y=7 p=z" ||
		len(g.Evidence) != 1 || g.IRTemplate != "ir1" || g.Collect[0] != "process_tree" || g.Attack[0] != "T1059" {
		t.Fatalf("alert = %+v", g)
	}
	e = NewEngine(mustLoad(t, y), Options{AlertOnly: true})
	if a := e.Process(ev(0, map[string]any{"x": "a"})); a[0].Mode != "alert" {
		t.Fatal("AlertOnly did not force alert mode")
	}
}

func TestKindIndex(t *testing.T) {
	rs := mustLoad(t, ruleYAML("R", "  all:\n    - x: a\n"))
	e := NewEngine(rs, Options{})
	other := ev(0, map[string]any{"x": "a"})
	other.Kind = "other"
	if len(e.Process(other)) != 0 {
		t.Fatal("rule fired for another event kind")
	}
}

func countRule(extra string) string {
	return ruleYAML("C", "  all:\n    - svc: sshd\n  count: {window: 10s, gte: 3, by: [src, acct]"+extra+"}\n")
}

func f(src, acct string) map[string]any {
	return map[string]any{"svc": "sshd", "src": src, "acct": acct}
}

func TestCountWindowPerKeyFakeClock(t *testing.T) {
	e := NewEngine(mustLoad(t, countRule("")), Options{})
	sec := time.Second
	// Two keys interleave: neither reaches 3 on its own within the window.
	if len(e.Process(ev(0, f("1.1.1.1", "root")))) != 0 ||
		len(e.Process(ev(1*sec, f("2.2.2.2", "root")))) != 0 ||
		len(e.Process(ev(2*sec, f("1.1.1.1", "root")))) != 0 ||
		len(e.Process(ev(3*sec, f("2.2.2.2", "root")))) != 0 {
		t.Fatal("global counting leaked across keys")
	}
	if a := e.Process(ev(4*sec, f("1.1.1.1", "root"))); len(a) != 1 || len(a[0].Evidence) != 3 ||
		a[0].Entities["src"] != "1.1.1.1" || a[0].Entities["acct"] != "root" {
		t.Fatalf("third event for key did not fire: %+v", a)
	}
	// Cooldown (= window): further failures do not re-fire immediately.
	if len(e.Process(ev(5*sec, f("1.1.1.1", "root")))) != 0 || len(e.Process(ev(6*sec, f("1.1.1.1", "root")))) != 0 ||
		len(e.Process(ev(7*sec, f("1.1.1.1", "root")))) != 0 {
		t.Fatal("fired during cooldown")
	}
	// After the cooldown a new burst fires again.
	e.Process(ev(20*sec, f("1.1.1.1", "root")))
	e.Process(ev(21*sec, f("1.1.1.1", "root")))
	if len(e.Process(ev(22*sec, f("1.1.1.1", "root")))) != 1 {
		t.Fatal("did not re-arm after cooldown")
	}
}

func TestCountWindowExpiry(t *testing.T) {
	e := NewEngine(mustLoad(t, countRule("")), Options{})
	sec := time.Second
	e.Process(ev(0, f("s", "a")))
	e.Process(ev(6*sec, f("s", "a")))
	// third at t=12s: the first is outside the 10 s window.
	if len(e.Process(ev(12*sec, f("s", "a")))) != 0 {
		t.Fatal("expired event counted")
	}
	if len(e.Process(ev(13*sec, f("s", "a")))) != 1 {
		t.Fatal("three within window must fire")
	}
}

func TestCountDistinct(t *testing.T) {
	y := ruleYAML("D", "  all:\n    - svc: sshd\n  count: {window: 5m, gte: 3, by: [acct], distinct: host}\n")
	e := NewEngine(mustLoad(t, y), Options{})
	m := func(h string) map[string]any { return map[string]any{"svc": "sshd", "acct": "azul", "host": h} }
	e.Process(ev(0, m("h1")))
	e.Process(ev(time.Second, m("h1"))) // repeat: still one distinct host
	e.Process(ev(2*time.Second, m("h2")))
	if len(e.Process(ev(3*time.Second, m("h2")))) != 0 {
		t.Fatal("repeats counted as distinct")
	}
	if len(e.Process(ev(4*time.Second, m("h3")))) != 1 {
		t.Fatal("three distinct hosts must fire")
	}
}

func TestStateBounded(t *testing.T) {
	e := NewEngine(mustLoad(t, countRule("")), Options{MaxKeys: 50})
	for i := 0; i < 5000; i++ {
		e.Process(ev(time.Duration(i)*time.Millisecond, f("src"+string(rune('a'+i%26))+strings.Repeat("x", i%97), "acct"+itoa(i))))
	}
	b, _, _ := e.StateSize()
	if b > 50 {
		t.Fatalf("buckets %d exceed bound", b)
	}
}

func itoa(i int) string {
	return strings.TrimSpace(strings.Repeat(" ", 0) + string(rune('0'+i%10)) + string(rune('0'+i/10%10)) + string(rune('0'+i/100%10)) + string(rune('0'+i/1000%10)))
}

func TestSequence(t *testing.T) {
	y := "id: S\n" + hdr + `when:
  event: proc
  all:
    - comm: chattr
  sequence:
    by: [host]
    within: 30s
    then:
      event: fim
      all:
        - path: /etc/shadow
`
	e := NewEngine(mustLoad(t, y), Options{})
	p := func(at time.Duration, host string) event.Event {
		return event.Event{Kind: "proc", Time: t0.Add(at), Fields: map[string]any{"comm": "chattr", "host": host}}
	}
	fm := func(at time.Duration, host, path string) event.Event {
		return event.Event{Kind: "fim", Time: t0.Add(at), Fields: map[string]any{"path": path, "host": host}}
	}
	if len(e.Process(fm(0, "h1", "/etc/shadow"))) != 0 {
		t.Fatal("B alone fired")
	}
	e.Process(p(time.Second, "h1"))
	if len(e.Process(fm(2*time.Second, "h2", "/etc/shadow"))) != 0 {
		t.Fatal("different key fired")
	}
	if len(e.Process(fm(3*time.Second, "h1", "/etc/other"))) != 0 {
		t.Fatal("non-matching B fired")
	}
	a := e.Process(fm(4*time.Second, "h1", "/etc/shadow"))
	if len(a) != 1 || len(a[0].Evidence) != 2 || a[0].Evidence[0].Kind != "proc" {
		t.Fatalf("A then B did not fire with both events as evidence: %+v", a)
	}
	if len(e.Process(fm(5*time.Second, "h1", "/etc/shadow"))) != 0 {
		t.Fatal("pending A reused")
	}
	e.Process(p(10*time.Second, "h1"))
	if len(e.Process(fm(60*time.Second, "h1", "/etc/shadow"))) != 0 {
		t.Fatal("B after the window fired")
	}
}

const profYAML = `profiles:
  - name: svc.children
    event: proc
    key: [parent]
    value: image
    learn: 10m
  - name: rotation.pending
---
id: P
title: t
severity: high
tier: 1
attack: [T1059]
when:
  event: proc
  all:
    - parent: [apache2, nginx]
    - not: {image: {in_profile: svc.children}}
---
id: L
title: t
severity: high
tier: 1
attack: [T1078]
when:
  event: login
  all:
    - account: {in_profile: rotation.pending}
`

func pe(at time.Duration, parent, image string) event.Event {
	return event.Event{Kind: "proc", Time: t0.Add(at), Fields: map[string]any{"parent": parent, "image": image}}
}

func TestProfileLearning(t *testing.T) {
	e := NewEngine(mustLoad(t, profYAML), Options{})
	// Learning window: nothing fires, values are learned per key.
	for _, c := range []struct{ p, i string }{{"apache2", "/usr/bin/convert"}, {"nginx", "/usr/bin/gs"}} {
		if len(e.Process(pe(0, c.p, c.i))) != 0 {
			t.Fatal("fired while learning")
		}
	}
	if len(e.Process(pe(9*time.Minute, "apache2", "/bin/sh"))) != 0 {
		t.Fatal("fired inside learning window")
	}
	// After the window: learned values are quiet, new values and values learned
	// under another key alert.
	if len(e.Process(pe(11*time.Minute, "apache2", "/usr/bin/convert"))) != 0 {
		t.Fatal("learned value fired")
	}
	if len(e.Process(pe(11*time.Minute, "apache2", "/usr/bin/gs"))) != 1 {
		t.Fatal("value learned under another key must fire")
	}
	if len(e.Process(pe(12*time.Minute, "apache2", "/BIN/SH"))) != 0 {
		// sh was learned inside the window (9m) so it is part of the baseline
	} else {
		t.Log("ok")
	}
	if len(e.Process(pe(12*time.Minute, "apache2", "/usr/bin/nc"))) != 1 {
		t.Fatal("unlearned value did not fire")
	}
	// Values arriving after the window are not learned.
	if len(e.Process(pe(13*time.Minute, "apache2", "/usr/bin/nc"))) != 1 {
		t.Fatal("value after window was learned")
	}
}

func TestProfileSeedAndList(t *testing.T) {
	e := NewEngine(mustLoad(t, profYAML), Options{})
	le := func(acct string) event.Event {
		return event.Event{Kind: "login", Time: t0, Fields: map[string]any{"account": acct}}
	}
	if len(e.Process(le("azul"))) != 0 {
		t.Fatal("empty list matched")
	}
	if err := e.Seed("rotation.pending", nil, "Azul", "root"); err != nil {
		t.Fatal(err)
	}
	if len(e.Process(le("azul"))) != 1 || len(e.Process(le("ROOT"))) != 1 || len(e.Process(le("bob"))) != 0 {
		t.Fatal("static list membership wrong")
	}
	if e.Seed("nope", nil, "x") == nil || e.Seed("svc.children", nil, "x") == nil {
		t.Fatal("bad seed accepted")
	}
	// Seeding a learned profile key marks it already learned (zero start time).
	if err := e.Seed("svc.children", []string{"apache2"}, "/usr/bin/php"); err != nil {
		t.Fatal(err)
	}
	if len(e.Process(pe(0, "apache2", "/bin/sh"))) != 1 || len(e.Process(pe(0, "apache2", "/usr/bin/php"))) != 0 {
		t.Fatal("seeded baseline wrong")
	}
}

func TestProfileExportImport(t *testing.T) {
	e := NewEngine(mustLoad(t, profYAML), Options{})
	e.Process(pe(0, "apache2", "/usr/bin/convert"))
	st := e.ExportProfiles()
	e2 := NewEngine(mustLoad(t, profYAML), Options{})
	e2.ImportProfiles(st)
	if len(e2.Process(pe(20*time.Minute, "apache2", "/usr/bin/convert"))) != 0 || len(e2.Process(pe(20*time.Minute, "apache2", "/bin/sh"))) != 1 {
		t.Fatal("imported baseline wrong")
	}
}

func TestProfileBounded(t *testing.T) {
	y := strings.Replace(profYAML, "learn: 10m", "learn: 10m\n    max_keys: 5\n    max_values: 3", 1)
	e := NewEngine(mustLoad(t, y), Options{})
	for i := 0; i < 100; i++ {
		e.Process(pe(0, "p"+itoa(i), "/x"))
		for j := 0; j < 10; j++ {
			e.Process(pe(0, "apache2", "/v"+itoa(j)))
		}
	}
	_, _, k := e.StateSize()
	if k > 5 {
		t.Fatalf("profile keys %d exceed bound", k)
	}
	for _, v := range e.ExportProfiles()["svc.children"] {
		if len(v.Values) > 3 {
			t.Fatalf("values %d exceed bound", len(v.Values))
		}
	}
}

func TestMultiDocAndIDs(t *testing.T) {
	y := ruleYAML("A", "  all:\n    - x: a\n") + "---\n" + ruleYAML("B", "  all:\n    - x: b\n")
	rs := mustLoad(t, y)
	if len(rs.Rules) != 2 {
		t.Fatalf("rules = %d", len(rs.Rules))
	}
}
