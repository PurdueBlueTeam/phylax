package actions

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSplunk is a tiny splunkd management API: users, indexes, HEC tokens.
type fakeSplunk struct {
	mu         sync.Mutex
	users      map[string]string // name -> password
	indexes    map[string]bool
	tokens     map[string]string // name -> index
	hecOff     bool
	log        []string
	searchHits int
}

func newFakeSplunk() *fakeSplunk {
	return &fakeSplunk{users: map[string]string{"admin": "changeme", "scored": "scoredpw"},
		indexes: map[string]bool{"main": true}, hecOff: true, tokens: map[string]string{}}
}

func entry(name string, c map[string]any) map[string]any {
	return map[string]any{"entry": []any{map[string]any{"name": name, "content": c}}}
}

func (s *fakeSplunk) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, p, _ := r.BasicAuth()
	if pw, ok := s.users[u]; !ok || pw != p {
		http.Error(w, "unauthorized", 401)
		return
	}
	_ = r.ParseForm()
	s.log = append(s.log, r.Method+" "+r.URL.Path)
	path := r.URL.Path
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch {
	case strings.Contains(path, "/search/"):
		s.searchHits++
		http.Error(w, "no", 403)
	case path == "/services/authentication/current-context":
		reply(entry("context", map[string]any{"username": u}))
	case strings.HasPrefix(path, "/services/authentication/users/"):
		name := strings.TrimPrefix(path, "/services/authentication/users/")
		if _, ok := s.users[name]; !ok {
			http.Error(w, "not found", 404)
			return
		}
		if r.Method == http.MethodPost {
			s.users[name] = r.PostForm.Get("password")
		}
		reply(entry(name, map[string]any{"email": "x@y"}))
	case path == "/services/data/indexes" && r.Method == http.MethodPost:
		s.indexes[r.PostForm.Get("name")] = true
		reply(entry(r.PostForm.Get("name"), nil))
	case strings.HasPrefix(path, "/services/data/indexes/"):
		name := strings.TrimPrefix(path, "/services/data/indexes/")
		if !s.indexes[name] {
			http.Error(w, "not found", 404)
			return
		}
		if r.Method == http.MethodDelete {
			delete(s.indexes, name)
		}
		reply(entry(name, nil))
	case path == "/servicesNS/nobody/splunk_httpinput/data/inputs/http/http":
		if r.Method == http.MethodPost {
			s.hecOff = r.PostForm.Get("disabled") == "1"
		}
		reply(entry("http", map[string]any{"disabled": s.hecOff}))
	case path == "/servicesNS/nobody/splunk_httpinput/data/inputs/http" && r.Method == http.MethodPost:
		s.tokens[r.PostForm.Get("name")] = r.PostForm.Get("index")
		reply(entry(r.PostForm.Get("name"), nil))
	case strings.HasPrefix(path, "/servicesNS/nobody/splunk_httpinput/data/inputs/http/"):
		name := strings.TrimPrefix(path, "/servicesNS/nobody/splunk_httpinput/data/inputs/http/")
		idx, ok := s.tokens[name]
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		if r.Method == http.MethodDelete {
			delete(s.tokens, name)
		}
		reply(entry(name, map[string]any{"index": idx, "disabled": false, "token": "11111111-2222-3333-4444-555555555555"}))
	case path == "/services/apps/local":
		reply(entry("splunk_secure_gateway", map[string]any{"version": "1.0", "password": "leak-me"}))
	default:
		http.Error(w, "unknown "+path, 404)
	}
}

type fakeSplunkDir struct{ api SplunkAPI }

func (d fakeSplunkDir) Client(context.Context, string) (SplunkAPI, error) { return d.api, nil }

func splunkFixture(t *testing.T) (*fixture, *fakeSplunk) {
	t.Helper()
	fs := newFakeSplunk()
	srv := httptest.NewTLSServer(fs)
	t.Cleanup(srv.Close)
	f := newFixture(t)
	f.env.Host = "debian-splunk"
	f.env.Win.Splunk = fakeSplunkDir{&HTTPSplunk{Base: srv.URL, User: "admin", Password: "changeme", HTTP: srv.Client()}}
	return f, fs
}

func TestSplunkRESTReadOnlyAndRedacted(t *testing.T) {
	f, fs := splunkFixture(t)
	o := f.ok(t, "splunk.rest", map[string]any{"path": "/services/apps/local"})
	if o.Output["names"] != "splunk_secure_gateway" || strings.Contains(o.Output["body"], "leak-me") || !strings.Contains(o.Output["body"], "<redacted>") {
		t.Fatalf("output %v", o.Output)
	}
	for _, p := range []string{"/services/search/jobs", "/services/search/jobs/export", "/services/saved/searches", "/etc/passwd", "/services/../x", "services/apps", "/services/apps/local?x=1"} {
		if _, err := f.run(t, "splunk.rest", map[string]any{"path": p}); err == nil {
			t.Errorf("path %q accepted", p)
		}
	}
	if fs.searchHits != 0 {
		t.Fatal("a search endpoint was called")
	}
	for _, l := range fs.log {
		if !strings.HasPrefix(l, "GET ") {
			t.Fatalf("splunk.rest sent %q", l)
		}
	}
}

func TestSplunkPassword(t *testing.T) {
	f, fs := splunkFixture(t)
	f.env.Guard = StaticGuard{Accounts: []string{"scored"}}
	if _, err := f.run(t, "splunk.password", map[string]any{"user": "admin"}); err == nil {
		t.Fatal("changed a password without one being supplied")
	}
	if _, err := f.run(t, "splunk.password", map[string]any{"user": "admin", "password": "short"}); err == nil {
		t.Fatal("short password accepted")
	}
	// the scored user is protected: only in a PCR transaction
	if _, err := f.run(t, "splunk.password", map[string]any{"user": "scored", "password": "new-long-password"}); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("scored user: %v", err)
	}
	o := f.ok(t, "splunk.password", map[string]any{"user": "admin", "password": "n3w-Admin-pass"}, func(r *Request) { r.DryRun = true })
	if strings.Contains(o.Plan.Diff, "n3w") || fs.users["admin"] != "changeme" {
		t.Fatalf("dry run: %+v", o.Plan)
	}
	// admin changes its own password; the verify uses a fresh login with the new one
	f.ok(t, "splunk.password", map[string]any{"user": "admin", "password": "n3w-Admin-pass"})
	if fs.users["admin"] != "n3w-Admin-pass" {
		t.Fatal("password not changed")
	}
	if fs.users["scored"] != "scoredpw" {
		t.Fatal("the scored user was touched")
	}
	// already in place: a no-op (no apply)
	f.env.Win.Splunk = fakeSplunkDir{f.env.Win.Splunk.(fakeSplunkDir).api.As("admin", "n3w-Admin-pass")}
	if o := f.ok(t, "splunk.password", map[string]any{"user": "admin", "password": "n3w-Admin-pass"}); o.Changed {
		t.Fatal("not idempotent")
	}
	f.ok(t, "splunk.password", map[string]any{"user": "scored", "password": "pcr-generated-pw"}, func(r *Request) { r.PCR = true })
}

func TestSplunkHECSetup(t *testing.T) {
	f, fs := splunkFixture(t)
	p := map[string]any{"index": "phylax", "token_name": "phylax-hec"}
	o := f.ok(t, "splunk.hec_setup", p, func(r *Request) { r.DryRun = true })
	if !strings.Contains(o.Plan.Diff, "+ index phylax") || !strings.Contains(o.Plan.Diff, "HEC input enabled") {
		t.Fatalf("diff %q", o.Plan.Diff)
	}
	if fs.indexes["phylax"] || len(fs.tokens) != 0 {
		t.Fatal("dry run changed splunk")
	}
	o = f.ok(t, "splunk.hec_setup", p, func(r *Request) { r.Deadman = time.Minute })
	if !fs.indexes["phylax"] || fs.tokens["phylax-hec"] != "phylax" || fs.hecOff {
		t.Fatalf("not set up: %+v", fs)
	}
	if o.Output["secret.token"] == "" {
		t.Fatalf("no token in output: %v", o.Output)
	}
	// rollback removes what this run created, not the pre-existing main index
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if fs.indexes["phylax"] || len(fs.tokens) != 0 || !fs.hecOff || !fs.indexes["main"] {
		t.Fatalf("rollback: %+v", fs)
	}
	// second time round: idempotent
	f.ok(t, "splunk.hec_setup", p)
	if o := f.ok(t, "splunk.hec_setup", p); o.Changed {
		t.Fatal("not idempotent")
	}
	if fs.searchHits != 0 {
		t.Fatal("searches touched")
	}
}

func TestSplunkHECRefusals(t *testing.T) {
	f, fs := splunkFixture(t)
	for _, idx := range []string{"main", "_internal", "_audit", "summary", "Phylax", "a b", "../x"} {
		if _, err := f.run(t, "splunk.hec_setup", map[string]any{"index": idx, "token_name": "t"}); err == nil {
			t.Errorf("index %q accepted", idx)
		}
	}
	// an existing token bound elsewhere is never rebound
	fs.tokens["phylax-hec"] = "main"
	fs.indexes["phylax"] = true
	if _, err := f.run(t, "splunk.hec_setup", map[string]any{"index": "phylax", "token_name": "phylax-hec"}); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("rebind: %v", err)
	}
	if fs.tokens["phylax-hec"] != "main" {
		t.Fatal("token rebound")
	}
}

func TestSplunkSidecarOff(t *testing.T) {
	f := newFixture(t)
	conf := "opt/splunk/etc/system/local/server.conf"
	f.write(t, conf, "# local\n[general]\nserverName = splunk1\n\n[postgres]\ndisabled = false\nport = 5435\n\n[sslConfig]\nsslVersions = tls1.2\n", 0o600)
	o := f.ok(t, "splunk.sidecar_off", map[string]any{}, func(r *Request) { r.DryRun = true })
	if !strings.Contains(o.Plan.Diff, "-disabled = false") || !strings.Contains(o.Plan.Diff, "+disabled = true") {
		t.Fatalf("diff %q", o.Plan.Diff)
	}
	o = f.ok(t, "splunk.sidecar_off", map[string]any{}, func(r *Request) { r.Deadman = time.Minute })
	want := "# local\n[general]\nserverName = splunk1\n\n[postgres]\ndisabled = true\nport = 5435\n\n[sslConfig]\nsslVersions = tls1.2\n"
	if got := f.read(t, conf); got != want {
		t.Fatalf("server.conf:\n%q", got)
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.read(t, conf), "disabled = false") {
		t.Fatal("rollback did not restore")
	}
	f.ok(t, "splunk.sidecar_off", map[string]any{})
	if o := f.ok(t, "splunk.sidecar_off", map[string]any{}); o.Changed {
		t.Fatal("not idempotent")
	}
}

func TestSplunkSidecarOffCreatesStanzaAndKeepsCRLF(t *testing.T) {
	f := newFixture(t)
	conf := "opt/splunk/etc/system/local/server.conf"
	f.ok(t, "splunk.sidecar_off", map[string]any{}) // no file at all
	if got := f.read(t, conf); got != "[postgres]\ndisabled = true\n" {
		t.Fatalf("created file %q", got)
	}
	f.write(t, "win/Splunk/etc/system/local/server.conf", "[general]\r\nserverName = w\r\n", 0o644)
	f.ok(t, "splunk.sidecar_off", map[string]any{"home": `C:\win\Splunk`})
	if got := f.read(t, "win/Splunk/etc/system/local/server.conf"); got != "[general]\r\nserverName = w\r\n\r\n[postgres]\r\ndisabled = true\r\n" {
		t.Fatalf("crlf file %q", got)
	}
}

func TestIniSet(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "[s]\nk = v\n"},
		{"[a]\nx=1\n", "[a]\nx=1\n\n[s]\nk = v\n"},
		{"[s]\nk = old\n[a]\nx=1\n", "[s]\nk = v\n[a]\nx=1\n"},
		{"[s]\n# k = commented\nz=1\n", "[s]\n# k = commented\nz=1\nk = v\n"},
		{"[a]\nk=keep\n[s]\nz=1\n\n[b]\n", "[a]\nk=keep\n[s]\nz=1\nk = v\n\n[b]\n"},
	} {
		if got := iniSet(tc.in, "s", "k", "v"); got != tc.want {
			t.Errorf("iniSet(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSplunkUnsupportedWithoutDirectory(t *testing.T) {
	f := newFixture(t)
	if _, err := f.run(t, "splunk.rest", map[string]any{"path": "/services/apps/local"}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got %v", err)
	}
}
