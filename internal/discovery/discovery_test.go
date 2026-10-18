package discovery

import (
	"encoding/base64"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	checks "github.com/PurdueBlueTeam/phylax/internal/checks"
)

// recSink records discovery output for assertions.
type recSink struct {
	mu        sync.Mutex
	proposals []Proposal
	stales    []Proposal
	accounts  []AccountMark
	blocked   []Blocked
	alerts    []map[string]any
}

func (r *recSink) Proposal(p Proposal) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.proposals = append(r.proposals, p)
}

func (r *recSink) Stale(p Proposal) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stales = append(r.stales, p)
}

func (r *recSink) Account(a AccountMark) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.accounts = append(r.accounts, a)
}

func (r *recSink) Blocked(b Blocked) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blocked = append(r.blocked, b)
}

func (r *recSink) Alert(rule string, event map[string]any, key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.alerts = append(r.alerts, event)
}

// ip16 encodes an IPv4 address the way the agent's [16]byte src field
// arrives through JSON.
func ip16(a, b, c, d int) string {
	var x [16]byte
	x[12], x[13], x[14], x[15] = byte(a), byte(b), byte(c), byte(d)
	return base64.StdEncoding.EncodeToString(x[:])
}

// clock is a fake, test-advanced time.
type clock struct{ t time.Time }

func (c *clock) Now() time.Time { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func splitIP(src string) (int, int, int, int) {
	parts := strings.Split(src, ".")
	if len(parts) != 4 {
		panic("bad test ip " + src)
	}
	out := make([]int, 4)
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil {
			panic("bad test ip " + src)
		}
		out[i] = v
	}
	return out[0], out[1], out[2], out[3]
}

func httpEvent(src string, dport int, method, path string) map[string]any {
	a, b, c, d := splitIP(src)
	return map[string]any{
		"src": ip16(a, b, c, d), "dport": dport,
		"method": method, "path": path, "resp": float64(200),
	}
}

func pop3Event(src string, dport int, user string) map[string]any {
	a, b, c, d := splitIP(src)
	return map[string]any{
		"proto": "pop3", "src": ip16(a, b, c, d), "dport": dport,
		"cmd": "RETR", "user": user,
	}
}

func dnsEvent(src string, dport int, name, qtype string) map[string]any {
	a, b, c, d := splitIP(src)
	return map[string]any{
		"src": ip16(a, b, c, d), "dport": dport,
		"names": []any{name}, "qtypes": []any{qtype},
	}
}

func ftpEvent(src string, dport int, cmd, user string) map[string]any {
	a, b, c, d := splitIP(src)
	return map[string]any{
		"proto": "ftp", "src": ip16(a, b, c, d), "dport": dport,
		"cmd": cmd, "user": user,
	}
}

const (
	web  = 8081
	mail = 110
	dns  = 5353
	ftp  = 2121
)

// TestDiscoveryLifecycle exercises the full recognition -> observation ->
// proposal -> stale -> blocked cycle on a fake clock (the local leg of
// lab test T15: the recognition heuristics against known scorer traffic).
func TestDiscoveryLifecycle(t *testing.T) {
	sink := &recSink{}
	clk := &clock{t: time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)}
	m := New(sink, Config{US: []string{"127.0.0.1"}, RoundDuration: time.Minute, Now: clk.Now})
	m.SetServices([]Service{
		{Name: "web", Port: web, Scored: true},
		{Name: "mail", Port: mail, Scored: true},
		{Name: "dns", Port: dns, Scored: true},
		{Name: "ftp", Port: ftp, Scored: true},
	})
	m.SetActive([]checks.Check{
		{ID: "c-web", Service: "web", Type: "http",
			Params: map[string]any{"url": "http://10.0.0.5:8081/health"}},
		{ID: "c-web-old", Service: "web", Type: "http",
			Params: map[string]any{"url": "http://10.0.0.5:8081/old"}},
		{ID: "c-mail", Service: "mail", Type: "smtp",
			Params: map[string]any{"smtp_host": "10.0.0.6"}},
		{ID: "c-dns", Service: "dns", Type: "dns",
			Params: map[string]any{"server": "10.0.0.7", "name": "svc.phylax.test", "qtype": "A"}},
		// no ftp check: the scorer's ftp check must come back as a proposal
	})

	// The scorer sweeps all four services each round, on a rhythm.
	// /old is part of the sweep for the first two rounds, then dropped.
	scorerRound := func(round int) {
		base := clk.t
		m.HandleEvent("http", httpEvent("10.5.5.5", web, "GET", "/health"))
		clk.advance(5 * time.Second)
		m.HandleEvent("http", httpEvent("10.5.5.5", web, "GET", "/product/4711"))
		clk.advance(5 * time.Second)
		if round <= 2 {
			m.HandleEvent("http", httpEvent("10.5.5.5", web, "GET", "/old"))
			clk.advance(5 * time.Second)
		}
		m.HandleEvent("exchange", pop3Event("10.5.5.5", mail, "popuser"))
		clk.advance(5 * time.Second)
		m.HandleEvent("dns", dnsEvent("10.5.5.5", dns, "svc.phylax.test", "A"))
		clk.advance(5 * time.Second)
		m.HandleEvent("exchange", ftpEvent("10.5.5.5", ftp, "LIST", "ftpuser"))
		clk.advance(5 * time.Second)
		clk.t = base.Add(50 * time.Second)
	}

	// one-round-only sweeper: sweeps everything, then stops (no rhythm)
	m.HandleEvent("http", httpEvent("10.9.9.9", web, "GET", "/health"))
	m.HandleEvent("http", httpEvent("10.9.9.9", mail, "GET", "/"))
	// steady background client: one service only (no sweep)
	m.HandleEvent("http", httpEvent("192.168.7.7", web, "GET", "/"))
	clk.advance(20 * time.Second)

	// round 1
	scorerRound(1)
	m.roundTick()
	sink.mu.Lock()
	if len(sink.proposals) != 0 {
		sink.mu.Unlock()
		t.Fatalf("proposals before confirmation: %d", len(sink.proposals))
	}
	sink.mu.Unlock()
	if srcs := m.ScorerSources(); len(srcs) != 0 {
		t.Fatalf("scorer confirmed after one round: %v", srcs)
	}

	// round 2: the rhythm holds -> confirmed
	scorerRound(2)
	m.roundTick()
	if srcs := m.ScorerSources(); len(srcs) != 1 || srcs[0] != "10.5.5.5" {
		t.Fatalf("scorer sources: %v", srcs)
	}
	sink.mu.Lock()
	kinds := map[string]int{}
	var ftpProp *Proposal
	for _, p := range sink.proposals {
		kinds[p.Kind+"|"+p.Observed.Service]++
		if p.Observed.Service == "ftp" {
			q := p
			ftpProp = &q
		}
	}
	sink.mu.Unlock()
	if ftpProp == nil || ftpProp.Observed.Service != "ftp" || ftpProp.Check.Type != "ftp" {
		t.Fatalf("expected a new proposal for the ftp check, got: %v", sink.proposals)
	}
	if kinds["new|ftp"] != 1 || kinds["new|web"] != 1 {
		t.Fatalf("proposals: %v", kinds)
	}
	// covered checks (web /health, /old, mail, dns) and the one-round
	// sweeper and the single-service client must not produce proposals
	for k := range kinds {
		if k != "new|ftp" && k != "new|web" {
			t.Fatalf("unexpected proposal kind: %v", kinds)
		}
	}
	if len(sink.accounts) == 0 || sink.accounts[0].Account != "popuser" || sink.accounts[0].Source != "10.5.5.5" {
		t.Fatalf("scored accounts: %v", sink.accounts)
	}
	// the /product/4711 sweep is templated: one observed check, not one
	// per product ID
	found := false
	for _, o := range m.Observed() {
		if o.Service == "web" && o.Template == "GET /product/:id" {
			found = true
		}
	}
	if !found {
		t.Fatalf("templated product check missing: %v", m.Observed())
	}

	// T14 leg: the scorer adds a check mid-run -> a new proposal
	clk.advance(10 * time.Second)
	m.HandleEvent("http", httpEvent("10.5.5.5", web, "GET", "/newpage"))
	sink.mu.Lock()
	gotNew := false
	for _, p := range sink.proposals {
		if p.Observed.Service == "web" && p.Observed.Template == "GET /newpage" {
			gotNew = true
		}
	}
	sink.mu.Unlock()
	if !gotNew {
		t.Fatalf("mid-run check not proposed: %v", sink.proposals)
	}

	// blocked: the next round reaches the other services but not mail
	base := clk.t
	m.HandleEvent("http", httpEvent("10.5.5.5", web, "GET", "/health"))
	clk.advance(5 * time.Second)
	m.HandleEvent("dns", dnsEvent("10.5.5.5", dns, "svc.phylax.test", "A"))
	clk.advance(5 * time.Second)
	m.HandleEvent("exchange", ftpEvent("10.5.5.5", ftp, "LIST", "ftpuser"))
	clk.t = base.Add(50 * time.Second)
	m.roundTick()
	sink.mu.Lock()
	blockedMail := false
	for _, b := range sink.blocked {
		if b.Service == "mail" {
			blockedMail = true
		}
	}
	sink.mu.Unlock()
	if !blockedMail {
		t.Fatalf("expected blocked mail, got: %v", sink.blocked)
	}
}

// stale: /old was swept in rounds 1-2, then dropped. It must be flagged
// stale within 5 rounds of dropping.
func TestDiscoveryStale(t *testing.T) {
	sink := &recSink{}
	clk := &clock{t: time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)}
	m := New(sink, Config{US: nil, RoundDuration: time.Minute, Now: clk.Now})
	m.SetServices([]Service{
		{Name: "web", Port: web, Scored: true},
		{Name: "dns", Port: dns, Scored: true},
	})
	m.SetActive([]checks.Check{
		{ID: "c-old", Service: "web", Type: "http",
			Params: map[string]any{"url": "http://10.0.0.5:8081/old"}},
		{ID: "c-dns", Service: "dns", Type: "dns",
			Params: map[string]any{"server": "10.0.0.7", "name": "svc.phylax.test", "qtype": "A"}},
	})

	// rounds 1-2: /old is checked (one full round each)
	for round := 1; round <= 2; round++ {
		m.HandleEvent("http", httpEvent("10.5.5.5", web, "GET", "/old"))
		clk.advance(5 * time.Second)
		m.HandleEvent("dns", dnsEvent("10.5.5.5", dns, "svc.phylax.test", "A"))
		clk.advance(55 * time.Second)
		m.roundTick()
	}
	// rounds 3-7: /old is dropped, the dns check continues
	for round := 3; round <= 7; round++ {
		m.HandleEvent("dns", dnsEvent("10.5.5.5", dns, "svc.phylax.test", "A"))
		clk.advance(59 * time.Second)
		m.roundTick()
		sink.mu.Lock()
		n := len(sink.stales)
		sink.mu.Unlock()
		if round <= 6 && n != 0 {
			t.Fatalf("stale fired too early in round %d: %v", round, sink.stales)
		}
		if round == 7 && n != 1 {
			t.Fatalf("stale not flagged after 5 quiet rounds: %v", sink.stales)
		}
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.stales) != 1 || sink.stales[0].Check.ID != "c-old" || sink.stales[0].Kind != "stale" {
		t.Fatalf("stale: %v", sink.stales)
	}
}

// TestRecognitionNoRhythm: a source that sweeps one round and then stops
// is not the scorer (source IP is a hint, never a rule).
func TestRecognitionNoRhythm(t *testing.T) {
	sink := &recSink{}
	clk := &clock{t: time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)}
	m := New(sink, Config{US: nil, RoundDuration: time.Minute, Now: clk.Now})
	m.SetServices([]Service{
		{Name: "web", Port: web, Scored: true},
		{Name: "mail", Port: mail, Scored: true},
	})

	// sweep once, then silence
	m.HandleEvent("http", httpEvent("10.9.9.9", web, "GET", "/"))
	m.HandleEvent("http", httpEvent("10.9.9.9", mail, "GET", "/"))
	clk.advance(30 * time.Second)
	m.roundTick()
	clk.advance(60 * time.Second)
	m.roundTick()
	if srcs := m.ScorerSources(); len(srcs) != 0 {
		t.Fatalf("one-round sweeper confirmed as scorer: %v", srcs)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.proposals) != 0 {
		t.Fatalf("proposals from a non-scorer: %v", sink.proposals)
	}
}

// TestProposalsResolve: accepting a proposal covers the template (the
// controller upserts the check); rejecting suppresses re-proposals.
func TestProposalsResolve(t *testing.T) {
	sink := &recSink{}
	clk := &clock{t: time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)}
	m := New(sink, Config{US: nil, RoundDuration: time.Minute, Now: clk.Now})
	m.SetServices([]Service{
		{Name: "web", Port: web, Scored: true},
		{Name: "mail", Port: mail, Scored: true},
	})
	m.SetActive(nil)

	sweep := func() {
		m.HandleEvent("http", httpEvent("10.5.5.5", web, "GET", "/"))
		clk.advance(5 * time.Second)
		m.HandleEvent("http", httpEvent("10.5.5.5", mail, "GET", "/"))
		clk.advance(5 * time.Second)
	}
	sweep()
	m.roundTick()
	sweep()
	m.roundTick()

	sink.mu.Lock()
	var id string
	for _, p := range sink.proposals {
		if p.Observed.Service == "web" && p.Observed.Template == "GET /" {
			id = p.ID
		}
	}
	sink.mu.Unlock()
	if id == "" {
		t.Fatalf("no proposal to resolve: %v", sink.proposals)
	}

	// reject: repeats of the template must not re-propose
	m.Resolve(id, false)
	sink.mu.Lock()
	before := len(sink.proposals)
	sink.mu.Unlock()
	clk.advance(5 * time.Second)
	m.HandleEvent("http", httpEvent("10.5.5.5", web, "GET", "/"))
	sink.mu.Lock()
	for _, p := range sink.proposals[before:] {
		if p.Observed.Service == "web" {
			t.Fatalf("rejected template re-proposed: %v", p)
		}
	}
	sink.mu.Unlock()

	// accept: the controller upserts the check -> covered
	m.Resolve(id, true)
	m.SetActive([]checks.Check{{
		ID: "p1", Service: "web", Type: "http",
		Params: map[string]any{"url": "http://10.0.0.5:8081/"},
	}})
	sink.mu.Lock()
	before = len(sink.proposals)
	sink.mu.Unlock()
	clk.advance(5 * time.Second)
	m.HandleEvent("http", httpEvent("10.5.5.5", web, "GET", "/"))
	sink.mu.Lock()
	for _, p := range sink.proposals[before:] {
		if p.Observed.Service == "web" {
			t.Fatalf("covered template re-proposed: %v", p)
		}
	}
	sink.mu.Unlock()
}
