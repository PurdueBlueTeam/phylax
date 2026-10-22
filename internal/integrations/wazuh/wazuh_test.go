package wazuh

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fake struct {
	version string
	agents  []Agent
	auths   atomic.Int32
	expire  atomic.Bool // next authenticated call returns 401 once
	alerts  []map[string]any
	lastQ   atomic.Value
}

func (f *fake) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/security/user/authenticate", func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		if u != "wazuh-wui" || p != "pw" {
			http.Error(w, "no", 401)
			return
		}
		n := f.auths.Add(1)
		w.Write([]byte("tok" + string(rune('0'+n))))
	})
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer tok") || f.expire.CompareAndSwap(true, false) {
				http.Error(w, "expired", 401)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("/manager/info", authed(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"affected_items": []any{map[string]any{"version": f.version}}}})
	}))
	mux.HandleFunc("/agents", authed(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"affected_items": f.agents, "total_affected_items": len(f.agents)}})
	}))
	mux.HandleFunc("/wazuh-alerts-*/_search", func(w http.ResponseWriter, r *http.Request) {
		if u, p, _ := r.BasicAuth(); u != "idx" || p != "ipw" {
			http.Error(w, "no", 401)
			return
		}
		var q map[string]any
		json.NewDecoder(r.Body).Decode(&q)
		f.lastQ.Store(q)
		var hits []any
		gte := q["query"].(map[string]any)["bool"].(map[string]any)["filter"].([]any)[0].(map[string]any)["range"].(map[string]any)["timestamp"].(map[string]any)["gte"].(string)
		since, _ := time.Parse("2006-01-02T15:04:05.000Z", gte)
		for _, a := range f.alerts {
			ts, _ := time.Parse("2006-01-02T15:04:05.000-0700", a["_source"].(map[string]any)["timestamp"].(string))
			if !ts.Before(since) { // like the real range filter
				hits = append(hits, a)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"hits": hits}})
	})
	return mux
}

func newClient(t *testing.T, f *fake) *Client {
	srv := httptest.NewTLSServer(f.handler())
	t.Cleanup(srv.Close)
	c, err := New(Config{APIURL: srv.URL, User: "wazuh-wui", Password: "pw", IndexerURL: srv.URL, IdxUser: "idx", IdxPassword: "ipw",
		HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestHealthOK(t *testing.T) {
	f := &fake{version: "v4.14.9", agents: []Agent{
		{ID: "000", Name: "mgr", Version: "Wazuh v4.14.9", Status: "active"},
		{ID: "001", Name: "a", Version: "Wazuh v4.14.9", Status: "active"},
		{ID: "002", Name: "b", Version: "Wazuh v4.14.8", Status: "disconnected"},
		{ID: "003", Name: "c", Status: "never_connected"},
	}}
	c := newClient(t, f)
	h, err := c.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.ManagerVersion != (Version{4, 14, 9}) || h.Active != 2 || len(h.Disconnected) != 1 || h.Disconnected[0] != "b" || len(h.NeverConnected) != 1 {
		t.Fatalf("%+v", h)
	}
}

func TestVersionPins(t *testing.T) {
	for _, v := range []string{"v4.7.3", "v4.14.3", "v4.14.8"} {
		c := newClient(t, &fake{version: v})
		if _, err := c.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("manager %s accepted: %v", v, err)
		}
	}
	// Newer manager and 4.14.10 vs 4.14.9 numeric (not lexical) comparison.
	c := newClient(t, &fake{version: "v4.14.10", agents: []Agent{{ID: "1", Name: "ok", Version: "Wazuh v4.14.9"}}})
	if _, err := c.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	c = newClient(t, &fake{version: "v4.14.9", agents: []Agent{{ID: "1", Name: "new", Version: "Wazuh v4.14.10"}}})
	if _, err := c.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "new(4.14.10)") {
		t.Fatalf("agent newer than manager accepted: %v", err)
	}
}

func TestReauthOn401(t *testing.T) {
	f := &fake{version: "v4.14.9"}
	c := newClient(t, f)
	if _, err := c.ManagerVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.expire.Store(true)
	if _, err := c.ManagerVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.auths.Load() != 2 {
		t.Fatalf("auths=%d", f.auths.Load())
	}
}

func TestBadCredentials(t *testing.T) {
	f := &fake{version: "v4.14.9"}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()
	c, _ := New(Config{APIURL: srv.URL, User: "x", Password: "y", HTTPClient: srv.Client()})
	if _, err := c.ManagerVersion(context.Background()); err == nil {
		t.Fatal("bad creds accepted")
	}
}

func TestTLSVerifyDefault(t *testing.T) {
	srv := httptest.NewTLSServer((&fake{version: "v4.14.9"}).handler())
	defer srv.Close()
	c, _ := New(Config{APIURL: srv.URL, User: "wazuh-wui", Password: "pw", Timeout: 2 * time.Second})
	if _, err := c.ManagerVersion(context.Background()); err == nil {
		t.Fatal("self-signed cert accepted with verification on")
	}
	c, _ = New(Config{APIURL: srv.URL, User: "wazuh-wui", Password: "pw", InsecureTLS: true})
	if _, err := c.ManagerVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func alertDoc(id, ts string, level int) map[string]any {
	return map[string]any{"_id": id, "_source": map[string]any{
		"timestamp": ts, "rule": map[string]any{"id": "550", "level": level, "description": "Integrity checksum changed"},
		"agent": map[string]any{"id": "001", "name": "a", "ip": "10.0.0.5"}, "location": "syscheck", "full_log": "x"}}
}

func TestAlertsAndPoller(t *testing.T) {
	f := &fake{version: "v4.14.9", alerts: []map[string]any{
		alertDoc("A1", "2026-10-22T10:00:00.000+0000", 7),
		alertDoc("A2", "2026-10-22T10:00:05.000+0000", 10),
	}}
	c := newClient(t, f)
	p := NewPoller(c, time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC), 5)
	evs, err := p.Poll(context.Background())
	if err != nil || len(evs) != 2 {
		t.Fatalf("%v %v", evs, err)
	}
	e := evs[1]
	if e.Kind != EventKind || e.Fields["rule_id"] != "550" || e.Fields["level"] != 10 || !e.Time.Equal(time.Date(2026, 10, 22, 10, 0, 5, 0, time.UTC)) {
		t.Fatalf("%+v", e)
	}
	// The same alert set again (overlapping boundary) yields nothing new.
	if evs, _ = p.Poll(context.Background()); len(evs) != 0 {
		t.Fatalf("duplicates: %v", evs)
	}
	f.alerts = append(f.alerts, alertDoc("A3", "2026-10-22T10:00:05.000+0000", 12))
	if evs, _ = p.Poll(context.Background()); len(evs) != 1 || evs[0].Fields["alert_id"] != "A3" {
		t.Fatalf("same-timestamp alert lost: %v", evs)
	}
	q, _ := json.Marshal(f.lastQ.Load())
	if !strings.Contains(string(q), `"rule.level"`) || !strings.Contains(string(q), "2026-10-22T10:00:05.000Z") {
		t.Fatalf("query: %s", q)
	}
}

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]Version{"v4.14.9": {4, 14, 9}, "Wazuh v4.14.10": {4, 14, 10}, "4.14.9-rc1": {4, 14, 9}} {
		if got, err := ParseVersion(in); err != nil || got != want {
			t.Fatalf("%q: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "x", "4", "4.a.1", "1.2.3.4"} {
		if _, err := ParseVersion(in); err == nil {
			t.Fatalf("%q accepted", in)
		}
	}
}
