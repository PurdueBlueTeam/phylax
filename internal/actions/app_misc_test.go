package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/integrations/wazuh"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
)

// ---- firewall.allow ----

type fakeNftFW struct {
	mu       sync.Mutex
	policy   *render.HostPolicy
	drop     bool // Apply silently installs nothing (verification must catch it)
	applied  int
	restored int
}

func newFakeNftFW() *fakeNftFW {
	return &fakeNftFW{policy: &render.HostPolicy{Host: "rocky-web", DefaultIn: render.Drop, DefaultOut: render.Drop,
		Rules: []render.Rule{{Group: render.GroupMgmt, Kind: render.KindAgentLink, Dir: render.Out, Action: render.Accept, Proto: "tcp", RemotePorts: []uint16{9443}}}}}
}
func (f *fakeNftFW) Policy(context.Context) (*render.HostPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *f.policy
	cp.Rules = append([]render.Rule(nil), f.policy.Rules...)
	return &cp, nil
}
func (f *fakeNftFW) Apply(_ context.Context, hp *render.HostPolicy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied++
	if !f.drop {
		f.policy = hp
	}
	return nil
}
func (f *fakeNftFW) Snapshot(context.Context) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return json.Marshal(f.policy)
}
func (f *fakeNftFW) Restore(_ context.Context, raw json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restored++
	var hp render.HostPolicy
	if err := json.Unmarshal(raw, &hp); err != nil {
		return err
	}
	f.policy = &hp
	return nil
}
func (f *fakeNftFW) nrules() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.policy.Rules) }

func TestFirewallAllow(t *testing.T) {
	f := newFixture(t)
	fw := newFakeNftFW()
	f.linux(t).Firewall = fw
	p := map[string]any{"ports": "1514,1515,55000,443", "proto": "tcp", "from": "10.0.0.0/24", "name": "wazuh"}
	o, err := f.run(t, "firewall.allow", p, func(r *Request) { r.DryRun = true })
	if err != nil || !strings.Contains(o.Plan.Diff, "+ accept in tcp 443,1514,1515,55000 from 10.0.0.0/24 (phylax:allow:wazuh)") || fw.nrules() != 1 {
		t.Fatalf("dry run: %+v %v", o.Plan, err)
	}
	o = f.ok(t, "firewall.allow", p, func(r *Request) { r.Deadman = 60e9 })
	if fw.nrules() != 2 || o.DeadmanID == "" {
		t.Fatalf("rules=%d deadman=%q", fw.nrules(), o.DeadmanID)
	}
	if o := f.ok(t, "firewall.allow", p); !o.Plan.Done {
		t.Fatal("idempotent run not Done")
	}
	// the same name updates the rule in place instead of adding another
	p2 := map[string]any{"ports": "1514,55000", "from": "10.0.0.5, 10.0.0.6", "name": "wazuh"}
	o2, _ := f.run(t, "firewall.allow", p2, func(r *Request) { r.DryRun = true })
	if !strings.Contains(o2.Plan.Diff, "- accept in tcp 443,1514") || !strings.Contains(o2.Plan.Diff, "+ accept in tcp 1514,55000 from 10.0.0.5/32,10.0.0.6/32") {
		t.Fatalf("update diff: %s", o2.Plan.Diff)
	}
	f.ok(t, "firewall.allow", p2, func(r *Request) { r.Deadman = NoDeadman })
	if fw.nrules() != 2 {
		t.Fatalf("update added a rule: %d", fw.nrules())
	}
	// rollback restores the declared policy exactly
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if fw.nrules() != 1 || fw.restored != 1 {
		t.Fatalf("after rollback: rules=%d restored=%d", fw.nrules(), fw.restored)
	}
	for _, bad := range []map[string]any{
		{"ports": "0", "from": "any"}, {"ports": "99999", "from": "any"}, {"ports": "80", "from": "10.0.0.0/33"},
		{"ports": "80", "from": "any,10.0.0.1"}, {"ports": "80", "from": "host.example"}, {"ports": "", "from": "any"},
		{"ports": "80", "from": "any", "proto": "icmp"}, {"ports": "80-70", "from": "any"},
	} {
		if _, err := f.run(t, "firewall.allow", bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	o = f.ok(t, "firewall.allow", map[string]any{"ports": "8088", "from": "any", "name": "hec"}, func(r *Request) { r.Deadman = NoDeadman })
	if !strings.Contains(strings.Join(o.Plan.Notes, " "), "every address") {
		t.Fatalf("open source should be called out: %v", o.Plan.Notes)
	}
	f2 := newFixture(t) // no firewall configured
	if _, err := f2.run(t, "firewall.allow", p); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("no backend: %v", err)
	}
}

func TestFirewallAllowVerifyFailureFiresDeadman(t *testing.T) {
	f := newFixture(t)
	fw := newFakeNftFW()
	fw.drop = true
	f.linux(t).Firewall = fw
	_, err := f.run(t, "firewall.allow", map[string]any{"ports": "443", "from": "any"})
	if err == nil || !strings.Contains(err.Error(), "missing from the declared policy") {
		t.Fatalf("got %v", err)
	}
	waitFor(t, "rollback after the failed verify", func() bool { fw.mu.Lock(); defer fw.mu.Unlock(); return fw.restored == 1 })
}

// ---- web ----

func TestWebRemoveDirQuarantinesAndRestores(t *testing.T) {
	f := newFixture(t)
	f.write(t, "var/www/html/install/index.php", "<?php installer", 0o644)
	f.write(t, "var/www/html/index.php", "<?php home", 0o644)
	o := f.ok(t, "web.remove_dir", map[string]any{"path": "/var/www/html/install"}, func(r *Request) { r.Deadman = 60e9 })
	if _, err := os.Stat(f.path("var/www/html/install")); err == nil {
		t.Fatal("directory still present")
	}
	if f.read(t, "var/www/html/index.php") != "<?php home" {
		t.Fatal("storefront content touched")
	}
	if _, err := os.Stat(filepath.Join(f.env.QuarantineDir, o.Output["id"], "index.php")); err != nil {
		t.Fatalf("payload not quarantined: %v", err)
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil || f.read(t, "var/www/html/install/index.php") != "<?php installer" {
		t.Fatalf("rollback: %v", err)
	}
	for _, bad := range []string{"/var/www/html", "/var/www", "/", "/var/www/html/../../etc", "/etc", "/var/www/html/"} {
		if _, err := f.run(t, "web.remove_dir", map[string]any{"path": bad}); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := f.run(t, "web.remove_dir", map[string]any{"path": "/var/www/html/index.php"}, func(r *Request) { r.DryRun = true }); err == nil {
		t.Fatal("a file is not a directory")
	}
	f.env.Guard = StaticGuard{Paths: []string{"/var/www/html/install"}}
	if err := f.refused(t, "web.remove_dir", map[string]any{"path": "/var/www/html/install"}); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("scored: %v", err)
	}
}

const ocAdminConfig = "<?php\ndefine('HTTP_SERVER', 'http://10.0.0.30/admin/');\ndefine('HTTP_CATALOG', 'http://10.0.0.30/');\ndefine('DIR_APPLICATION', '/var/www/html/admin/');\ndefine('DIR_SYSTEM', '/var/www/html/system/');\n"

func TestWebRenameDirFixesReferencesAndRollsBack(t *testing.T) {
	f := newFixture(t)
	f.write(t, "var/www/html/admin/config.php", ocAdminConfig, 0o640)
	f.write(t, "var/www/html/admin/index.php", "<?php admin", 0o644)
	p := map[string]any{"path": "/var/www/html/admin", "to": "/var/www/html/adm-phylax"}
	o, err := f.run(t, "web.rename_dir", p, func(r *Request) { r.DryRun = true })
	if err != nil || !strings.Contains(o.Plan.Diff, "update 2 reference line(s)") {
		t.Fatalf("dry run: %+v %v", o.Plan, err)
	}
	o = f.ok(t, "web.rename_dir", p, func(r *Request) { r.Deadman = 60e9 })
	want := "<?php\ndefine('HTTP_SERVER', 'http://10.0.0.30/adm-phylax/');\ndefine('HTTP_CATALOG', 'http://10.0.0.30/');\ndefine('DIR_APPLICATION', '/var/www/html/adm-phylax/');\ndefine('DIR_SYSTEM', '/var/www/html/system/');\n"
	if got := f.read(t, "var/www/html/adm-phylax/config.php"); got != want {
		t.Fatalf("config:\n%s", got)
	}
	if _, err := os.Stat(f.path("var/www/html/admin")); err == nil {
		t.Fatal("old name present")
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if f.read(t, "var/www/html/admin/config.php") != ocAdminConfig || f.read(t, "var/www/html/admin/index.php") != "<?php admin" {
		t.Fatal("rollback must restore the directory and the original config")
	}
	if _, err := os.Stat(f.path("var/www/html/adm-phylax")); err == nil {
		t.Fatal("new name still present after rollback")
	}
	// already renamed: Done
	f.ok(t, "web.rename_dir", p, func(r *Request) { r.Deadman = NoDeadman })
	if o := f.ok(t, "web.rename_dir", p); !o.Plan.Done {
		t.Fatal("second run not Done")
	}
	for _, bad := range []map[string]any{
		{"path": "/var/www/html/admin", "to": "/var/www/other/admin"}, {"path": "/var/www/html/a", "to": "/var/www/html/a"},
		{"path": "/var/www/html", "to": "/var/www/html2"},
	} {
		if _, err := f.run(t, "web.rename_dir", bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	f.env.Guard = StaticGuard{Paths: []string{"/var/www/html/adm-phylax"}}
	if err := f.refused(t, "web.rename_dir", map[string]any{"path": "/var/www/html/adm-phylax", "to": "/var/www/html/x1"}); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("scored: %v", err)
	}
}

func sumLine(t *testing.T, root, rel string) string {
	t.Helper()
	h, err := hashFile(filepath.Join(root, rel), "sha256")
	if err != nil {
		t.Fatal(err)
	}
	return h + "  " + rel + "\n"
}

func TestOpenCartAudit(t *testing.T) {
	f := newFixture(t)
	doc := "var/www/html/"
	f.write(t, doc+"index.php", "<?php // vendor index", 0o644)
	f.write(t, doc+"catalog/controller/home.php", "<?php // vendor home", 0o644)
	f.write(t, doc+"config.php", "<?php // site", 0o666) // world-writable
	f.write(t, doc+"install/index.php", "<?php", 0o644)
	f.write(t, doc+"image/catalog/logo.png", "png", 0o644)
	f.write(t, doc+"image/cache/shell.php", "<?php eval($_POST[x]);", 0o644)
	f.write(t, doc+"extension/payment_x/x.php", "<?php", 0o644)
	f.write(t, doc+"extension/evil/e.php", "<?php", 0o644)
	vendor := sumLine(t, f.path(doc), "index.php") + sumLine(t, f.path(doc), "catalog/controller/home.php") +
		strings.Repeat("a", 64) + "  catalog/controller/gone.php\n"
	f.write(t, "var/lib/phylax/oc.sha256", vendor, 0o644)
	// tamper after the manifest was made, add an unknown file
	f.write(t, doc+"catalog/controller/home.php", "<?php system($_GET[c]);", 0o644)
	f.write(t, doc+"catalog/model/x.php", "<?php", 0o644)
	m := newFakeMySQL(t, "auth_socket", "")
	m.handler = func(sql string) ([]string, [][]string, uint64, error, bool) {
		switch {
		case strings.Contains(sql, "`oc_user`"):
			return []string{"user_id", "username", "email", "status", "date_added"},
				[][]string{{"1", "admin", "a@x", "1", "2026-01-01"}, {"2", "support", "s@x", "1", "2026-10-21"}}, 0, nil, true
		case strings.Contains(sql, "`oc_extension`"):
			return []string{"type", "code"}, [][]string{{"module", "banner"}, {"payment", "cod"}}, 0, nil, true
		}
		return nil, nil, 0, nil, false
	}
	f.withMySQL(t, m)
	o := f.ok(t, "web.opencart_audit", map[string]any{"docroot": "/var/www/html", "vendor_manifest": "/var/lib/phylax/oc.sha256",
		"known_extensions": []any{"payment_x"}, "database": "opencart"})
	fnd := o.Output["findings"]
	for _, want := range []string{
		"critical install/: installer directory still present",
		"warning admin/: default admin directory name",
		"critical config.php: group/world-writable",
		"critical image/cache/shell.php: executable script in an upload/cache directory",
		"critical catalog/controller/home.php: differs from the vendor release",
		"warning catalog/model/x.php: not in the vendor release",
		"warning extension/evil: extension not in the known list",
	} {
		if !strings.Contains(fnd, want) {
			t.Errorf("missing %q in:\n%s", want, fnd)
		}
	}
	if strings.Contains(fnd, "index.php: differs") || strings.Contains(fnd, "payment_x") {
		t.Errorf("false positives:\n%s", fnd)
	}
	if o.Output["admin_users"] != "admin,support" || o.Output["extensions_db"] != "module/banner,payment/cod" ||
		o.Output["modified"] != "1" || o.Output["missing_vendor_files"] != "1" {
		t.Fatalf("%v", o.Output)
	}
	if _, err := f.run(t, "web.opencart_audit", map[string]any{"docroot": "/var/www/html", "fail_on_critical": true}); err == nil {
		t.Fatal("fail_on_critical")
	}
	if _, err := f.run(t, "web.opencart_audit", map[string]any{"docroot": "/var/www/html", "database": "x`; drop"}); err == nil {
		t.Fatal("identifier injection accepted")
	}
}

// ---- probes ----

func TestNetTCPProbe(t *testing.T) {
	f := newFixture(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	f.ok(t, "net.tcp_probe", map[string]any{"host": "127.0.0.1", "port": port})
	ln.Close()
	if _, err := f.run(t, "net.tcp_probe", map[string]any{"host": "127.0.0.1", "port": port}); err == nil {
		t.Fatal("closed port passed")
	}
	// retries wait for a service that comes up late
	var mu sync.Mutex
	n := 0
	f.linux(t).Dial = func(context.Context, string, string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		n++
		if n < 3 {
			return nil, errors.New("refused")
		}
		c, _ := net.Pipe()
		return c, nil
	}
	f.ok(t, "net.tcp_probe", map[string]any{"host": "10.0.0.40", "port": 25, "retries": 3, "wait_ms": 1})
	if n != 3 {
		t.Fatalf("attempts=%d", n)
	}
	for _, bad := range []map[string]any{{"host": "a b", "port": 1}, {"host": "x", "port": 0}, {"host": "x", "port": 70000}, {"host": "x", "port": 1, "retries": 99}} {
		if _, err := f.run(t, "net.tcp_probe", bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestNetHTTPProbe(t *testing.T) {
	f := newFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			fmt.Fprint(w, "Welcome to the store")
		case "/redir":
			http.Redirect(w, r, "/ok", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ok := func(path string, extra map[string]any) error {
		p := map[string]any{"url": srv.URL + path}
		for k, v := range extra {
			p[k] = v
		}
		_, err := f.run(t, "net.http_probe", p)
		return err
	}
	if err := ok("/ok", map[string]any{"expect_status": 200, "expect_regex": "store$"}); err != nil {
		t.Fatal(err)
	}
	if err := ok("/redir", map[string]any{"expect_status": 200}); err != nil {
		t.Fatalf("redirects are followed like the scorer does: %v", err)
	}
	if err := ok("/ok", map[string]any{"expect_regex": "^nope"}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("regex: %v", err)
	}
	if err := ok("/missing", nil); err == nil {
		t.Fatal("404 passed without expect_status")
	}
	if err := ok("/missing", map[string]any{"expect_status": 404}); err != nil {
		t.Fatal(err)
	}
	if err := ok("/ok", map[string]any{"expect_status": 201}); err == nil {
		t.Fatal("wrong status passed")
	}
	for _, u := range []string{"ftp://x/", "file:///etc/passwd", "/relative", "http://"} {
		if _, err := f.run(t, "net.http_probe", map[string]any{"url": u}); err == nil {
			t.Errorf("url %q accepted", u)
		}
	}
	// self-signed TLS needs insecure
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "tls ok") }))
	defer ts.Close()
	if _, err := f.run(t, "net.http_probe", map[string]any{"url": ts.URL}); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	f.ok(t, "net.http_probe", map[string]any{"url": ts.URL, "insecure": true, "expect_regex": "tls ok"})
}

func TestCommandCheck(t *testing.T) {
	f := newFixture(t)
	fr := &fakeRunner{}
	f.linux(t).Exec = fr
	f.write(t, "usr/bin/pkexec", "", 0o755)
	f.write(t, "proc/sys/user/max_user_namespaces", "15000\n", 0o644)
	f.write(t, "proc/sys/kernel/osrelease", "6.8.0-1\n", 0o644)
	cases := []struct {
		out     string
		vuln    bool
		finding string
	}{
		{"Sudo version 1.9.5p1\nSudoers policy plugin version 1.9.5p1\n", true, "CVE-2021-3156"},
		{"Sudo version 1.9.5p2\n", true, "CVE-2025-32462"},
		{"Sudo version 1.9.16p2\n", true, "CVE-2025-32463"},
		{"Sudo version 1.9.17p1\n", false, ""},
		{"Sudo version 1.8.31\n", true, "CVE-2021-3156"},
		{"Sudo version 1.8.1\n", false, ""},
	}
	for _, c := range cases {
		fr.on("/usr/bin/sudo -V", CmdResult{Stdout: c.out})
		o := f.ok(t, "command.check", map[string]any{"probe": "sudo_version"})
		if (o.Output["vulnerable"] == "true") != c.vuln || !strings.Contains(o.Output["findings"], c.finding) {
			t.Errorf("%q: %v", c.out, o.Output)
		}
	}
	fr.on("/usr/bin/sudo -V", CmdResult{Stdout: "Sudo version 1.9.5p1\n"})
	if _, err := f.run(t, "command.check", map[string]any{"probe": "sudo_version", "fail_if_vulnerable": true}); err == nil {
		t.Fatal("fail_if_vulnerable")
	}
	fr.on("/usr/bin/ssh -V", CmdResult{Stderr: "OpenSSH_9.6p1 Ubuntu-3ubuntu13, OpenSSL 3.0.13\n"})
	if o := f.ok(t, "command.check", map[string]any{"probe": "ssh_version"}); o.Output["vulnerable"] != "true" || !strings.Contains(o.Output["findings"], "regreSSHion") {
		t.Fatalf("%v", o.Output)
	}
	fr.on("/usr/bin/ssh -V", CmdResult{Stderr: "OpenSSH_9.8p1\n"})
	if o := f.ok(t, "command.check", map[string]any{"probe": "ssh_version"}); o.Output["vulnerable"] != "false" {
		t.Fatalf("%v", o.Output)
	}
	fr.on("/usr/bin/pkexec --version", CmdResult{Stdout: "pkexec version 0.105\n"})
	if o := f.ok(t, "command.check", map[string]any{"probe": "pkexec_version"}); o.Output["version"] != "0.105" || o.Output["setuid"] != "false" || o.Output["mode"] != "0755" {
		t.Fatalf("%v", o.Output)
	}
	if o := f.ok(t, "command.check", map[string]any{"probe": "userns_check"}); o.Output["enabled"] != "true" {
		t.Fatalf("%v", o.Output)
	}
	if o := f.ok(t, "command.check", map[string]any{"probe": "kernel_release"}); o.Output["release"] != "6.8.0-1" {
		t.Fatalf("%v", o.Output)
	}
	if _, err := f.run(t, "command.check", map[string]any{"probe": "rm -rf /"}); err == nil {
		t.Fatal("arbitrary probe accepted")
	}
	fr.on("/usr/bin/sudo -V", CmdResult{ExitCode: 1, Stderr: "boom"})
	if _, err := f.run(t, "command.check", map[string]any{"probe": "sudo_version"}); err == nil {
		t.Fatal("failing probe passed")
	}
	if v1, _ := parseVer("1.9.17p1"); v1.cmp(ver{n: []int{1, 9, 17}, p: 1}) != 0 {
		t.Fatal("parseVer")
	}
}

// ---- wazuh ----

type fakeWazuh struct {
	h       *wazuh.Health
	herr    error
	agents  []wazuh.Agent
	gotAPI  string
	gotMin  string
	factory func(context.Context, string, string) (WazuhAPI, error)
}

func (w *fakeWazuh) Health(context.Context) (*wazuh.Health, error) { return w.h, w.herr }
func (w *fakeWazuh) Agents(context.Context) ([]wazuh.Agent, error) { return w.agents, nil }
func (w *fakeWazuh) Groups(context.Context) ([]wazuh.Group, error) {
	return []wazuh.Group{{Name: "default", Count: 1, ConfigSum: "c1"}, {Name: "phylax-fim", Count: 2}, {Name: "empty-group"}}, nil
}
func (w *fakeWazuh) install(f *fixture, t *testing.T) {
	f.linux(t).Wazuh = func(_ context.Context, api, min string) (WazuhAPI, error) {
		w.gotAPI, w.gotMin = api, min
		return w, nil
	}
}

func TestWazuhHealthCaptureAndTestAlert(t *testing.T) {
	f := newFixture(t)
	mv, _ := wazuh.ParseVersion("4.14.9")
	w := &fakeWazuh{
		h: &wazuh.Health{ManagerVersion: mv, Active: 2, Disconnected: []string{"win-dc"}, NeverConnected: []string{"win-ad"}},
		agents: []wazuh.Agent{
			{ID: "001", Name: "rocky-web", IP: "10.0.0.30", Version: "Wazuh v4.14.9", Status: "active", LastKeepAlive: "2026-10-22T12:00:00Z", Groups: []string{"default", "phylax-fim"}},
			{ID: "002", Name: "=cmd|' /C calc'!A0", IP: "10.0.0.31", Status: "active", Groups: []string{"phylax-fim"}},
		},
	}
	if _, err := f.run(t, "wazuh.health", map[string]any{"api": "https://10.0.0.10:55000"}); err == nil || !strings.Contains(err.Error(), "credentials") {
		t.Fatalf("no credentials configured: %v", err)
	}
	w.install(f, t)
	o := f.ok(t, "wazuh.health", map[string]any{"api": "https://10.0.0.10:55000", "min_version": "4.14.9"})
	if w.gotAPI != "https://10.0.0.10:55000" || w.gotMin != "4.14.9" || o.Output["active"] != "2" || o.Output["disconnected"] != "win-dc" {
		t.Fatalf("%v %v %v", w.gotAPI, w.gotMin, o.Output)
	}
	if _, err := f.run(t, "wazuh.health", map[string]any{"api": "https://10.0.0.10:55000", "min_active": 3}); err == nil {
		t.Fatal("min_active")
	}
	w.herr = wazuh.ErrVersionPin
	if _, err := f.run(t, "wazuh.health", map[string]any{"api": "https://10.0.0.10:55000", "min_version": "4.14.9"}); !errors.Is(err, wazuh.ErrVersionPin) {
		t.Fatalf("version pin must fail the node: %v", err)
	}
	w.herr = nil
	if _, err := f.run(t, "wazuh.health", map[string]any{"api": "ftp://x"}); err == nil {
		t.Fatal("non-http api accepted")
	}

	f.ok(t, "wazuh.capture", map[string]any{"api": "https://10.0.0.10:55000", "out": "/var/lib/phylax/inject-kit/wazuh"})
	var agents []wazuh.Agent
	if err := json.Unmarshal([]byte(f.read(t, "var/lib/phylax/inject-kit/wazuh/agents.json")), &agents); err != nil || len(agents) != 2 {
		t.Fatalf("agents.json: %v", err)
	}
	csvOut := f.read(t, "var/lib/phylax/inject-kit/wazuh/agents.csv")
	if !strings.HasPrefix(csvOut, "id,name,ip,version,status,last_keepalive,groups\n001,rocky-web,10.0.0.30") || strings.Contains(csvOut, ",=cmd") {
		t.Fatalf("csv (formula injection must be neutralised):\n%s", csvOut)
	}
	var groups map[string][]string
	_ = json.Unmarshal([]byte(f.read(t, "var/lib/phylax/inject-kit/wazuh/groups.json")), &groups)
	if len(groups["phylax-fim"]) != 2 {
		t.Fatalf("groups: %v", groups)
	}
	if g, ok := groups["empty-group"]; !ok || len(g) != 0 {
		t.Fatalf("group without agents must still be listed: %v", groups)
	}
	var gd []wazuh.Group
	if err := json.Unmarshal([]byte(f.read(t, "var/lib/phylax/inject-kit/wazuh/group_details.json")), &gd); err != nil || len(gd) != 3 || gd[0].ConfigSum != "c1" {
		t.Fatalf("group_details.json: %v %v", gd, err)
	}
	if !strings.Contains(f.read(t, "var/lib/phylax/inject-kit/wazuh/health.json"), `"manager_version": "4.14.9"`) {
		t.Fatal("health.json")
	}

	f.write(t, "var/log/phylax-wazuh-test.log", "old line\n", 0o640)
	ta := map[string]any{"path": "/var/log/phylax-wazuh-test.log", "marker": "phylax-wazuh-evidence-test"}
	f.ok(t, "wazuh.test_alert", ta)
	f.ok(t, "wazuh.test_alert", ta)
	got := f.read(t, "var/log/phylax-wazuh-test.log")
	if !strings.HasPrefix(got, "old line\n2026-10-22T12:00:00Z phylax phylax-wazuh-evidence-test\n") || strings.Count(got, "evidence-test") != 2 {
		t.Fatalf("log:\n%s", got)
	}
	for _, bad := range []map[string]any{
		{"path": "/etc/passwd", "marker": "x"}, {"path": "/var/log/../etc/passwd", "marker": "x"},
		{"path": "/var/log/x", "marker": "a\nroot::0:0"}, {"path": "/var/log/x", "marker": ""},
	} {
		if _, err := f.run(t, "wazuh.test_alert", bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	_ = os.Symlink("/etc/passwd", f.path("var/log/link"))
	if _, err := f.run(t, "wazuh.test_alert", map[string]any{"path": "/var/log/link", "marker": "x"}); err == nil {
		t.Fatal("symlink followed")
	}
}

func TestRegistryHasLinuxActionsAndSpecsAreSound(t *testing.T) {
	reg := Core()
	want := []string{"pkg.install", "pkg.upgrade", "pkg.remove", "firewall.allow", "ini.set", "conf.set", "xml.set", "agentopt.set",
		"sysctl.set", "kernel.module_block", "systemd.dropin", "service.config", "cockpit.disable", "cron.disable", "at.disable", "file.attr",
		"web.remove_dir", "web.rename_dir", "web.opencart_audit", "mysql.audit", "mysql.lock", "sql.query",
		"net.tcp_probe", "net.http_probe", "command.check", "wazuh.health", "wazuh.capture", "wazuh.test_alert"}
	for _, n := range want {
		a, err := reg.Get(n)
		if err != nil {
			t.Errorf("%s not registered", n)
			continue
		}
		s := a.Spec()
		if s.Doc == "" || s.Risk == "" {
			t.Errorf("%s: missing doc or risk", n)
		}
		seen := map[string]bool{}
		for _, p := range s.Params {
			if seen[p.Name] {
				t.Errorf("%s: duplicate param %s", n, p.Name)
			}
			seen[p.Name] = true
		}
		if s.ReadOnly && s.Risk != RiskNone {
			t.Errorf("%s: read-only action with risk %s", n, s.Risk)
		}
	}
}
