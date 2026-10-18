package controller

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// TestRedTagging: attack-like detections tag their source as
// attack-like (docs: Traffic labels — "scans, exploit payloads,
// webshell requests, decoy hits"); other alerts do not. Red is a
// sub-tag of other, not a label of its own.
func TestRedTagging(t *testing.T) {
	c := newMonController(t)
	now := time.Now().UTC()

	// webshell request: D1 with a connection trigger carrying raddr
	c.observeEvent("ubuntu-ecom", ev("alert", map[string]any{
		"rule": "D1.service-spawns-shell", "severity": "critical", "tier": 0,
		"event": map[string]any{"kind": "connection_new", "raddr": "203.0.113.7",
			"rport": float64(51234), "comm": "apache2"},
	}, now))
	// a decoy hit (D15) tags too
	c.observeEvent("ubuntu-mail", ev("alert", map[string]any{
		"rule": "D15.decoy-hit", "severity": "critical", "tier": 1,
		"event": map[string]any{"src": "198.51.100.9"},
	}, now))
	// an alert without attack-like semantics must not tag
	c.observeEvent("ubuntu-ecom", ev("alert", map[string]any{
		"rule": "D3.new-listener", "severity": "info", "tier": 1,
		"event": map[string]any{"raddr": "192.0.2.44"},
	}, now))

	if got := c.Classify("203.0.113.7"); got != "other" {
		t.Fatalf("red source must classify as other, got %q", got)
	}
	if !c.labs.IsRed("203.0.113.7") {
		t.Fatal("webshell source not tagged red")
	}
	if !c.labs.IsRed("198.51.100.9") {
		t.Fatal("decoy-hit source not tagged red")
	}
	if c.labs.IsRed("192.0.2.44") {
		t.Fatal("non-attack source tagged red")
	}
	if got := c.RedSources(); len(got) != 2 || got[0] != "198.51.100.9" || got[1] != "203.0.113.7" {
		t.Fatalf("RedSources: %v", got)
	}
}

func b64ip(t *testing.T, ip string) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(net.ParseIP(ip).To4())
}

// TestTrafficView: the traffic view labels each flow's source (us /
// scorer / other), flags attack-like sources and marks flows to scored
// services.
func TestTrafficView(t *testing.T) {
	c := newMonController(t)
	now := time.Now().UTC()
	c.SetScorerSources([]string{"10.5.5.5"})
	c.markRed("203.0.113.7")

	srcs := []string{"127.0.0.1", "10.5.5.5", "203.0.113.7"}
	for i, src := range srcs {
		b, _ := json.Marshal(map[string]any{
			"src": b64ip(t, src), "dst": b64ip(t, "10.0.0.5"),
			"sport": float64(40000 + i), "dport": float64(80), "proto": float64(6),
			"result": "established", "scan": false,
		})
		if _, err := c.Store().RecordEvent("h"+string(rune('a'+i)), store.Event{
			Seq: uint64(i + 1), TS: now.Add(time.Duration(i) * time.Second).UTC().Format(time.RFC3339Nano),
			Type: "flow", Data: b,
		}); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/traffic", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	w := httptest.NewRecorder()
	c.bootstrapMux().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("traffic: %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		Flows []map[string]any `json:"flows"`
		Red   []string         `json:"red_sources"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Flows) != 3 {
		t.Fatalf("flows: %v", out.Flows)
	}
	bySrc := map[string]map[string]any{}
	for _, f := range out.Flows {
		bySrc[f["src"].(string)] = f
	}
	wantLabel := map[string]string{"127.0.0.1": "us", "10.5.5.5": "scorer", "203.0.113.7": "other"}
	for src, want := range wantLabel {
		f, ok := bySrc[src]
		if !ok {
			t.Fatalf("flow for %s missing: %v", src, out.Flows)
		}
		if f["label"] != want {
			t.Fatalf("label for %s: %v, want %s", src, f["label"], want)
		}
		if f["scored"] != true {
			t.Fatalf("flow to scored port not marked: %v", f)
		}
	}
	if bySrc["203.0.113.7"]["red"] != true || bySrc["10.5.5.5"]["red"] != false {
		t.Fatalf("red flags: %v", out.Flows)
	}
	if len(out.Red) != 1 || out.Red[0] != "203.0.113.7" {
		t.Fatalf("red_sources: %v", out.Red)
	}

	// non-loopback is refused
	req2 := httptest.NewRequest(http.MethodGet, "/traffic", nil)
	req2.RemoteAddr = "10.1.1.1:54321"
	w2 := httptest.NewRecorder()
	c.bootstrapMux().ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("non-loopback traffic: %d", w2.Code)
	}
}

func TestIsLoopback(t *testing.T) {
	for _, s := range []string{"127.0.0.1:4321", "[::1]:4321", "127.3.4.5:1"} {
		if !isLoopback(s) {
			t.Fatalf("isLoopback(%q) = false", s)
		}
	}
	if isLoopback("10.1.1.1:4321") {
		t.Fatal("isLoopback(10.1.1.1) = true")
	}
}
