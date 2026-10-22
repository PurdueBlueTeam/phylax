package deps

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

var t0 = time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// mailListeners: postfix master (pid 100) listens on 25; its smtpd worker is pid 101, child of 100.
var mailL = []Listener{{Proto: "tcp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 25, PID: 100, Comm: "master", Exe: "/usr/lib/postfix/sbin/master", Service: "email-mail"}}

func parent(pid int) int {
	switch pid {
	case 101, 102:
		return 100
	case 103:
		return 102 // grandchild
	}
	return 1
}

func in(op Op, remote string) ConnEvent {
	return ConnEvent{Op: op, Dir: "inbound", Proto: "tcp", Local: ap("10.0.0.15:25"), Remote: ap(remote), CommunityID: "1:in-" + remote}
}
func out(pid int, remote string) ConnEvent {
	return ConnEvent{Op: Opened, Dir: "outbound", Proto: "tcp", Local: ap("10.0.0.15:40000"), Remote: ap(remote), PID: pid, CommunityID: "1:out-" + remote}
}

func edges(evs []event.Event, kind string) []event.Event {
	var o []event.Event
	for _, e := range evs {
		if e.Kind == kind {
			o = append(o, e)
		}
	}
	return o
}

func TestRequestDrivenVersusBackground(t *testing.T) {
	c := NewCollector(Config{Report: time.Minute})
	now := t0
	// Request-driven: LDAP lookup by a worker while an SMTP client is connected.
	c.Observe(now, mailL, []ConnEvent{in(Opened, "203.0.113.50:5555")}, parent)
	now = now.Add(2 * time.Second)
	evs := c.Observe(now, mailL, []ConnEvent{out(101, "10.0.0.5:389")}, parent)
	// Background: cron-like refresh to the DC's Kerberos by the master, no inbound.
	c.Observe(now, mailL, []ConnEvent{in(Closed, "203.0.113.50:5555")}, parent)
	now = now.Add(2 * time.Second)
	evs = append(evs, c.Observe(now, mailL, []ConnEvent{out(100, "10.0.0.5:88")}, parent)...)
	es := edges(evs, KindEdge)
	if len(es) != 2 {
		t.Fatalf("want 2 new edges, got %d: %+v", len(es), evs)
	}
	ldap, krb := es[0].Fields, es[1].Fields
	if ldap["strength"] != StrengthStrong || ldap["request_count"] != 1 || ldap["new"] != true || ldap["service"] != "email-mail" {
		t.Errorf("ldap edge: %v", ldap)
	}
	if krb["strength"] != StrengthWeak || krb["background_count"] != 1 {
		t.Errorf("kerberos edge: %v", krb)
	}
	if ldap["public"] != false || ldap["learning"] != true {
		t.Errorf("flags: %v", ldap)
	}
}

func TestProcessTreeAndUnrelatedProcess(t *testing.T) {
	c := NewCollector(Config{})
	evs := c.Observe(t0, mailL, []ConnEvent{out(103, "10.0.0.5:389"), out(999, "10.0.0.9:443")}, parent)
	es := edges(evs, KindEdge)
	if len(es) != 1 || es[0].Fields["dst_addr"] != "10.0.0.5" {
		t.Fatalf("grandchild should attribute, unrelated pid should not: %+v", es)
	}
}

func TestPeriodicAndPeriodicReport(t *testing.T) {
	c := NewCollector(Config{Report: 10 * time.Minute})
	now := t0
	var last event.Event
	for i := 0; i < 6; i++ {
		now = now.Add(5 * time.Minute)
		for _, e := range edges(c.Observe(now, mailL, []ConnEvent{out(100, "10.0.0.5:88")}, parent), KindEdge) {
			last = e
		}
	}
	if last.Fields["periodic"] != true || last.Fields["new"] != false || last.Fields["background_count"].(int) < 4 {
		t.Fatalf("expected periodic re-report: %v", last.Fields)
	}
}

func TestReplacedPostfixForwardingOutside(t *testing.T) {
	c := NewCollector(Config{Learn: 15 * time.Minute})
	now := t0
	c.Observe(now, mailL, []ConnEvent{in(Opened, "10.0.0.99:1")}, parent)
	c.Observe(now.Add(time.Second), mailL, []ConnEvent{out(101, "10.0.0.5:389")}, parent)
	now = t0.Add(time.Hour) // baseline over
	evs := c.Observe(now, mailL, nil, parent)
	evs = append(evs, c.Observe(now.Add(time.Second), mailL, []ConnEvent{out(101, "203.0.113.9:25")}, parent)...)
	var es []event.Event
	for _, e := range edges(evs, KindEdge) {
		if e.Fields["new"] == true {
			es = append(es, e)
		}
	}
	if len(es) != 1 {
		t.Fatalf("got %+v", evs)
	}
	f := es[0].Fields
	if f["new"] != true || f["learning"] != false || f["public"] != true || f["dst_port"] != 25 {
		t.Fatalf("fields %v", f)
	}
}

func TestGoneAndBounds(t *testing.T) {
	c := NewCollector(Config{GoneAfter: 10 * time.Minute, GoneMin: 2, MaxEdges: 2})
	c.Observe(t0, mailL, []ConnEvent{out(100, "10.0.0.5:389")}, parent)
	c.Observe(t0.Add(time.Second), mailL, []ConnEvent{out(100, "10.0.0.5:389"), out(100, "10.0.0.6:1"), out(100, "10.0.0.7:1")}, parent)
	if c.Dropped() != 1 {
		t.Fatalf("dropped %d", c.Dropped())
	}
	evs := c.Observe(t0.Add(20*time.Minute), mailL, nil, parent)
	g := edges(evs, KindEdgeGone)
	if len(g) != 1 || g[0].Fields["dst_addr"] != "10.0.0.5" {
		t.Fatalf("gone: %+v", evs)
	}
	if again := edges(c.Observe(t0.Add(21*time.Minute), mailL, nil, parent), KindEdgeGone); len(again) != 0 {
		t.Fatal("gone repeated")
	}
}

func TestDNSName(t *testing.T) {
	d := NewDNSCache(0, 0)
	d.Note("dc.corp.local", []netip.Addr{netip.MustParseAddr("10.0.0.5")}, t0.Add(-time.Second))
	c := NewCollector(Config{DNS: d})
	es := edges(c.Observe(t0, mailL, []ConnEvent{out(100, "10.0.0.5:389")}, parent), KindEdge)
	if es[0].Fields["dst_name"] != "dc.corp.local" {
		t.Fatalf("%v", es[0].Fields)
	}
}

// --- controller side ---

func ref(t *testing.T) *manifest.Manifest {
	t.Helper()
	m, err := manifest.LoadDir("../../manifest/2027", manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func ev(kind string, at time.Time, f map[string]any) event.Event {
	return event.Event{Time: at, Kind: kind, Fields: f}
}

// edge from ecom-http (rocky-ecom 172.20.240.10) to mssql 1433, request driven.
func ecomEdge(at time.Time) event.Event {
	return ev(KindEdge, at, map[string]any{
		"service": "ecom-http", "svc_key": "tcp/80", "svc_proto": "tcp", "svc_port": 80, "proto": "tcp",
		"dst_addr": "172.20.240.120", "dst_port": 1433, "count": 20, "request_count": 18, "background_count": 2,
		"first_seen_ms": int(t0.UnixMilli()), "last_seen_ms": int(at.UnixMilli()), "learning": true, "new": true,
		"src_addr": "172.20.240.10", "community_ids": []any{"1:abc"}, "public": false,
	})
}

func mssqlPeer(at time.Time) event.Event {
	return ev(KindPeer, at, map[string]any{
		"service": "mssql-sql", "svc_key": "tcp/1433", "proto": "tcp", "peer_addr": "172.20.240.10", "port": 1433,
		"count": 20, "community_ids": []any{"1:abc"},
	})
}

func TestCrossHostJoinAndConfidence(t *testing.T) {
	m := ref(t)
	g := NewGraph()
	g.LoadManifest(m)
	g.Ingest("rocky-ecom", ecomEdge(t0))
	es := g.Edges()
	if len(es) != 1 {
		t.Fatalf("%+v", es)
	}
	e := es[0]
	if e.To.Host != "mssql" || e.To.Service != "mssql-sql" || e.Strength != StrengthStrong || e.Confirmed {
		t.Fatalf("before join: %+v", e)
	}
	before := e.Confidence
	g.Ingest("mssql", mssqlPeer(t0))
	e = g.Edges()[0]
	if !e.Confirmed || e.Confidence <= before || e.Level != ConfHigh {
		t.Fatalf("after join: %+v", e)
	}
	joined := strings.Join(e.Evidence, "|")
	if !strings.Contains(joined, "Community ID") {
		t.Errorf("evidence: %v", e.Evidence)
	}
	// Per-service views, both directions.
	var from, to *ServiceView
	vs := g.Services()
	for i := range vs {
		switch vs[i].Service {
		case "ecom-http":
			from = &vs[i]
		case "mssql-sql":
			to = &vs[i]
		}
	}
	if from == nil || len(from.DependsOn) != 1 || to == nil || len(to.DependedBy) != 1 || !to.Scored {
		t.Fatalf("views %+v %+v", from, to)
	}
}

func TestLoopbackIsSameHost(t *testing.T) {
	g := NewGraph()
	g.LoadManifest(ref(t))
	f := ecomEdge(t0).Fields
	f["dst_addr"], f["dst_port"] = "127.0.0.1", 3306
	g.Ingest("rocky-ecom", ev(KindEdge, t0, f))
	if e := g.Edges()[0]; e.To.Host != "rocky-ecom" {
		t.Fatalf("%+v", e.To)
	}
}

func TestGoneThenBack(t *testing.T) {
	g := NewGraph()
	g.LoadManifest(ref(t))
	g.Ingest("rocky-ecom", ecomEdge(t0))
	gone := ecomEdge(t0.Add(time.Hour))
	gone.Kind = KindEdgeGone
	g.Ingest("rocky-ecom", gone)
	if !g.Edges()[0].Gone {
		t.Fatal("not gone")
	}
	g.Ingest("rocky-ecom", ecomEdge(t0.Add(2*time.Hour)))
	if g.Edges()[0].Gone {
		t.Fatal("still gone")
	}
}

func TestProposeDiffApplyAndLint(t *testing.T) {
	m := ref(t)
	g := NewGraph()
	g.LoadManifest(m)
	g.Ingest("rocky-ecom", ecomEdge(t0))
	g.Ingest("mssql", mssqlPeer(t0))
	// An already-declared dependency (mail -> ad ldap) must not be proposed.
	g.Ingest("ubuntu-email", ev(KindEdge, t0, map[string]any{
		"service": "email-mail", "svc_key": "tcp/25", "svc_proto": "tcp", "svc_port": 25, "proto": "tcp",
		"dst_addr": "172.20.240.100", "dst_port": 389, "count": 9, "request_count": 9, "src_addr": "172.20.240.15", "learning": true,
	}))

	// Lint before: the current manifest would cut ecom -> mssql.
	fs := CheckManifest(g, m)
	var cut *manifest.Finding
	for i := range fs {
		if fs[i].ID == RuleCutDependency {
			cut = &fs[i]
		}
	}
	if cut == nil || cut.Severity != manifest.SevError || cut.Subject != "service ecom-http" {
		t.Fatalf("lint should refuse: %v", fs)
	}
	if !manifest.HasErrors(fs) {
		t.Fatal("HasErrors false")
	}

	ps := Propose(g, m, ProposeOptions{})
	if len(ps) != 1 || ps[0].Service != "ecom-http" || len(ps[0].Add) != 1 {
		t.Fatalf("proposals %+v", ps)
	}
	d := ps[0].Add[0]
	if d.To != "mssql" || len(d.Ports) != 1 || d.Ports[0] != 1433 || d.Service != "mssql-sql" || d.Egress != "mssql-sql" {
		t.Fatalf("dep %+v", d)
	}
	diff := Diff(ps)
	for _, want := range []string{"@@ service ecom-http", "+      - { egress: mssql-sql, to: mssql, ports: [1433], service: mssql-sql }", "evidence"} {
		if !strings.Contains(diff, want) {
			t.Errorf("diff lacks %q:\n%s", want, diff)
		}
	}
	// The original is untouched; the applied copy validates and lints clean of DEP001.
	if len(m.Services["ecom-http"].DependsOn) != 0 {
		t.Fatal("Apply mutated the input")
	}
	n := Apply(m, ps)
	if err := n.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, f := range CheckManifest(g, n) {
		if f.ID == RuleCutDependency {
			t.Fatalf("still cut: %v", f)
		}
	}
	if again := Propose(g, n, ProposeOptions{}); len(again) != 0 {
		t.Fatalf("proposal not idempotent: %+v", again)
	}
}

func TestLintExternalAndDisabledTarget(t *testing.T) {
	m := ref(t)
	g := NewGraph()
	g.LoadManifest(m)
	f := ecomEdge(t0).Fields
	f["dst_addr"], f["dst_port"] = "203.0.113.9", 25
	g.Ingest("rocky-ecom", ev(KindEdge, t0, f))
	var ext bool
	for _, x := range CheckManifest(g, m) {
		ext = ext || x.ID == RuleExternalDependency && x.Severity == manifest.SevWarn
	}
	if !ext {
		t.Fatal("no external warning")
	}
	if p := Propose(g, m, ProposeOptions{}); len(p) != 0 {
		t.Fatalf("external edge must not be proposed: %+v", p)
	}

	g2 := NewGraph()
	g2.LoadManifest(m)
	g2.Ingest("rocky-ecom", ecomEdge(t0))
	g2.Ingest("mssql", mssqlPeer(t0))
	s := m.Services["mssql-sql"]
	s.State = "stopped"
	m.Services["mssql-sql"] = s
	var down bool
	for _, x := range CheckManifest(g2, m) {
		down = down || x.ID == RuleDependencyDown
	}
	if !down {
		t.Fatal("stopping a depended-on service was not refused")
	}
	if ds := g2.Dependents("mssql", "mssql-sql"); len(ds) != 1 || ds[0].From.Service != "ecom-http" {
		t.Fatalf("dependents %+v", ds)
	}
}
