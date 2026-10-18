package discovery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/checks"
	"github.com/PurdueBlueTeam/phylax/internal/sim/scorer"
	"github.com/PurdueBlueTeam/phylax/internal/sim/servicetest"
)

// TestT15AgainstSimulator is the local leg of lab test T15: run the scorer
// simulator (the ground-truth producer) against real in-test services, feed
// the services' request log to discovery in the shape the capture module's
// parsers emit (U-10: AF_PACKET does not deliver on this host, so the
// service-side log stands in for capture), and check discovery's output
// against the simulator's ground truth:
//
//   - 100% of the simulator's checks are proposed (new),
//   - 0 false proposals (every proposal matches a ground-truth check),
//   - a check dropped mid-run is flagged stale within 5 rounds,
//   - a check added mid-run is proposed within one round (T14's bar).
//
// The 2-hour window of the lab test is scaled to 9 one-minute rounds.
func TestT15AgainstSimulator(t *testing.T) {
	sv := servicetest.New(t, servicetest.Config{})

	// service map, as declared in the manifest: the ports the scorer hits
	web := portOf(t, sv.HTTP.Listener.Addr().String())
	pop3 := portOf(t, sv.POP3)
	dnsPort := portOf(t, sv.DNS)
	ftpPort := portOf(t, sv.FTP)

	full := []scorer.Check{
		{ID: "web-health", Kind: "http", Target: sv.HTTP.Listener.Addr().String(), Path: "/health"},
		{ID: "web-product", Kind: "http", Target: sv.HTTP.Listener.Addr().String(), Path: "/product/4711"},
		{ID: "mail", Kind: "smtp_pop3", Target: sv.SMTP, Path: sv.POP3,
			Pop3Users: []string{"popuser1", "popuser2", "popuser3"}},
		{ID: "dns-svc", Kind: "dns", Target: sv.DNS, Path: "svc.phylax.test"},
		{ID: "ftp-list", Kind: "ftp", Target: sv.FTP, User: "ftpuser"},
	}
	dropFTP := []scorer.Check{full[0], full[1], full[2], full[3]}
	newPage := []scorer.Check{
		full[0],
		{ID: "web-newpage", Kind: "http", Target: sv.HTTP.Listener.Addr().String(), Path: "/newpage"},
		full[2], full[3],
	}
	// 9 rounds: 1-3 full, 4-5 without ftp (dropped), 6-9 with /newpage
	// added mid-run (repeating the last plan)
	plan := [][]scorer.Check{full, full, full, dropFTP, dropFTP, newPage, newPage, newPage, newPage}

	truthPath := filepath.Join(t.TempDir(), "truth.jsonl")

	// discovery over a fake clock: one round per simulator round
	sink := &recSink{}
	clk := &clock{t: time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)}
	m := New(sink, Config{US: nil, RoundDuration: time.Minute, Now: clk.Now})
	m.SetServices([]Service{
		{Name: "web", Port: web, Scored: true},
		{Name: "mail", Port: pop3, Scored: true},
		{Name: "dns", Port: dnsPort, Scored: true},
		{Name: "ftp", Port: ftpPort, Scored: true},
	})
	m.SetActive(nil) // the active list starts empty: everything is "new"

	base := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	cfg := scorer.Config{
		Plan: plan, Interval: 20 * time.Millisecond, Out: truthPath,
		RoundDone: func(r int) {
			now := base.Add(time.Duration(r) * time.Minute)
			clk.t = now.Add(-10 * time.Second)
			for _, req := range sv.DrainRequests() {
				if typ, data := reqEvent(req); typ != "" {
					m.HandleEvent(typ, data)
				}
			}
			clk.t = now
			m.roundTick()
			// after round 3 the operator has accepted the proposals:
			// the checks enter the active list. From here on the stale
			// flag can fire (docs: an active check with no scorer
			// counterpart for 5 rounds).
			if r == 3 {
				m.SetActive(activeList(t, web))
			}
			if r == len(plan) {
				cancel()
			}
		},
	}
	done := make(chan error, 1)
	go func() {
		_, err := scorer.Run(ctx, cfg)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("scorer run: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("scorer run did not finish")
	}

	// the ground truth: what the simulator ran
	truth, err := os.ReadFile(truthPath)
	if err != nil {
		t.Fatal(err)
	}
	truthChecks := map[string]bool{} // check id -> true
	for _, l := range strings.Split(string(truth), "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		var tr struct {
			Check string `json:"check"`
		}
		if err := json.Unmarshal([]byte(l), &tr); err != nil {
			t.Fatalf("truth line %q: %v", l, err)
		}
		truthChecks[tr.Check] = true
	}

	// 100% of the simulator's checks are proposed
	sink.mu.Lock()
	proposed := map[string]bool{}
	for _, p := range sink.proposals {
		if p.Kind == "new" {
			proposed[p.Observed.Service+"|"+p.Observed.Template] = true
		}
	}
	stales := append([]Proposal(nil), sink.stales...)
	sink.mu.Unlock()

	expect := map[string]string{
		"web-health":  "web|GET /health",
		"web-product": "web|GET /product/:id",
		"mail":        "mail|mail",
		"dns-svc":     "dns|dns svc.phylax.test A",
		"ftp-list":    "ftp|ftp",
		"web-newpage": "web|GET /newpage",
	}
	for id, want := range expect {
		if !truthChecks[id] {
			t.Fatalf("ground truth missing check %s (simulator did not run it?)", id)
		}
		if !proposed[want] {
			t.Errorf("100%%: check %s (%s) not proposed; proposals: %v", id, want, proposed)
		}
	}
	// 0 false proposals: every proposed (service, template) belongs to the
	// ground-truth set
	for k := range proposed {
		if !knownTemplate(k) {
			t.Errorf("false proposal: %s", k)
		}
	}
	// the product rotation is one templated check, not one per ID
	for k := range proposed {
		if strings.HasPrefix(k, "web|GET /product/") && k != "web|GET /product/:id" {
			t.Errorf("un-templated product proposal: %s", k)
		}
	}

	// mid-run addition (T14): /newpage proposed within one round of the
	// scorer starting it (round 6)
	var newPageTS time.Time
	sink.mu.Lock()
	for _, p := range sink.proposals {
		if p.Observed.Template == "GET /newpage" {
			newPageTS = p.TS
		}
	}
	sink.mu.Unlock()
	if newPageTS.IsZero() {
		t.Fatal("mid-run check /newpage not proposed")
	}
	if newPageTS.After(base.Add(6 * time.Minute)) {
		t.Errorf("/newpage proposed late: %s (want by end of round 6)", newPageTS)
	}

	// dropped check: ftp flagged stale within 5 rounds of dropping (last
	// seen round 3; rounds 4-8 quiet; the round-8 tick is the 5th)
	var ftpStale bool
	for _, s := range stales {
		if s.Check.Service == "ftp" {
			ftpStale = true
			if s.TS.After(base.Add(8 * time.Minute)) {
				t.Errorf("ftp stale flagged late: %s (want by round 8)", s.TS)
			}
		}
	}
	if !ftpStale {
		t.Errorf("dropped ftp check not flagged stale: %v", stales)
	}
	// still-run checks are not stale
	for _, s := range stales {
		if s.Check.Service != "ftp" {
			t.Errorf("live check flagged stale: %v", s)
		}
	}

	// the rotating POP3 users are one observed check (bucket "mail"), not
	// one per user
	mailObs := 0
	for _, o := range m.Observed() {
		if o.Service == "mail" {
			mailObs++
		}
	}
	if mailObs != 1 {
		t.Errorf("rotating POP3 users: %d mail observations, want 1", mailObs)
	}
}

// reqEvent converts one service-side request into the event the capture
// module's parsers would emit for it (the U-10 stand-in for capture).
func reqEvent(r servicetest.Req) (typ string, data map[string]any) {
	switch r.Kind {
	case "http":
		return "http", map[string]any{
			"src": ip16str(r.Src), "dport": r.Port,
			"method": r.Extra["method"], "path": r.Extra["path"], "resp": float64(200),
		}
	case "pop3":
		return "exchange", map[string]any{
			"proto": "pop3", "src": ip16str(r.Src), "dport": r.Port,
			"cmd": r.Extra["cmd"], "user": r.Extra["user"],
		}
	case "smtp":
		return "exchange", map[string]any{
			"proto": "smtp", "src": ip16str(r.Src), "dport": r.Port,
			"cmd": r.Extra["cmd"],
		}
	case "dns":
		names, _ := r.Extra["names"].([]any)
		qts, _ := r.Extra["qtypes"].([]any)
		if len(names) == 0 {
			return "", nil
		}
		return "dns", map[string]any{
			"src": ip16str(r.Src), "dport": r.Port, "names": names, "qtypes": qts,
		}
	case "ftp":
		return "exchange", map[string]any{
			"proto": "ftp", "src": ip16str(r.Src), "dport": r.Port,
			"cmd": r.Extra["cmd"], "user": r.Extra["user"],
		}
	}
	// tftp, ntp: not decoded by the phase-1 parsers (docs) — not events
	return "", nil
}

// ip16str encodes a dotted quad the way the agent's [16]byte src field
// arrives through JSON (v4 in the last four bytes).
func ip16str(ip string) string {
	p := net.ParseIP(ip).To4()
	if p == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(p)
}

// knownTemplate is the ground-truth (service, template) set for this E2E.
func knownTemplate(k string) bool {
	switch k {
	case "web|GET /health", "web|GET /product/:id", "web|GET /newpage",
		"mail|mail", "dns|dns svc.phylax.test A", "ftp|ftp":
		return true
	}
	return false
}

func portOf(t *testing.T, addr string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if _, err := fmt.Sscanf(p, "%d", &n); err != nil {
		t.Fatal(err)
	}
	return n
}

// activeList is the active check set the operator accepts after round 3:
// the five checks the simulator ran in rounds 1-3, as the controller
// would upsert them (from the accepted proposals' pre-filled checks).
func activeList(t *testing.T, web int) []checks.Check {
	t.Helper()
	base := "http://127.0.0.1:" + strconv.Itoa(web)
	return []checks.Check{
		{ID: "c-web-health", Service: "web", Type: "http",
			Params: map[string]any{"url": base + "/health"}},
		{ID: "c-web-product", Service: "web", Type: "http",
			Params: map[string]any{"url": base + "/product/4711"}},
		{ID: "c-mail", Service: "mail", Type: "smtp",
			Params: map[string]any{"mail_user": "popuser1"}},
		{ID: "c-dns", Service: "dns", Type: "dns",
			Params: map[string]any{"name": "svc.phylax.test"}},
		{ID: "c-ftp", Service: "ftp", Type: "ftp",
			Params: map[string]any{"user": "ftpuser"}},
	}
}
