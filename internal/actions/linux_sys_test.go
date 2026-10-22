package actions

import (
	"context"
	"errors"
	"strings"
	"sync"
	"syscall"
	"testing"
)

const ossecConf = `<!-- Wazuh manager -->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
  </global>
  <auth>
    <disabled>no</disabled>
    <use_password>no</use_password>
  </auth>
  <active-response>
    <disabled>no</disabled>
  </active-response>
</ossec_config>

<ossec_config>
  <!-- second root keeps its comment -->
  <active-response>
    <disabled>no</disabled>
    <ca_store>/var/ossec/etc/wpk_root.pem</ca_store>
  </active-response>
  <client><server><address>1.2.3.4</address></server></client>
  <empty/>
</ossec_config>
`

func TestXMLSetInPlace(t *testing.T) {
	f := newFixture(t)
	f.write(t, "var/ossec/etc/ossec.conf", ossecConf, 0o640)
	p := "/var/ossec/etc/ossec.conf"
	// descendant path matching in both <ossec_config> roots
	o, err := f.run(t, "xml.set", map[string]any{"path": p, "xpath": "//active-response/disabled", "value": "yes"}, func(r *Request) { r.DryRun = true })
	if err != nil || strings.Count(o.Plan.Diff, "+    <disabled>yes</disabled>") != 2 {
		t.Fatalf("dry run: %+v %v", o.Plan, err)
	}
	f.ok(t, "xml.set", map[string]any{"path": p, "xpath": "//active-response/disabled", "value": "yes"}, func(r *Request) { r.Deadman = 60e9 })
	got := f.read(t, "var/ossec/etc/ossec.conf")
	want := strings.Replace(ossecConf, "<active-response>\n    <disabled>no", "<active-response>\n    <disabled>yes", 2)
	if got != want {
		t.Fatalf("only the two disabled elements may change:\n%s", got)
	}
	// untouched siblings keep comments and layout; the auth section's own <disabled> is separate
	if !strings.Contains(got, "<!-- second root keeps its comment -->") || !strings.Contains(got, "<disabled>no</disabled>\n    <use_password>") {
		t.Fatal("unrelated content changed")
	}
	// absolute path, text with markup characters
	f.ok(t, "xml.set", map[string]any{"path": p, "xpath": "/ossec_config/client/server/address", "value": "10.0.0.10"}, func(r *Request) { r.Deadman = NoDeadman })
	if !strings.Contains(f.read(t, "var/ossec/etc/ossec.conf"), "<address>10.0.0.10</address>") {
		t.Fatal("address not set")
	}
	f.ok(t, "xml.set", map[string]any{"path": p, "xpath": "//auth/use_password", "value": "a<b&c"}, func(r *Request) { r.Deadman = NoDeadman })
	if !strings.Contains(f.read(t, "var/ossec/etc/ossec.conf"), "<use_password>a&lt;b&amp;c</use_password>") {
		t.Fatal("value not escaped")
	}
	// a self-closing element is expanded
	f.ok(t, "xml.set", map[string]any{"path": p, "xpath": "//empty", "value": "x"}, func(r *Request) { r.Deadman = NoDeadman })
	if !strings.Contains(f.read(t, "var/ossec/etc/ossec.conf"), "<empty>x</empty>") {
		t.Fatalf("self-closing:\n%s", f.read(t, "var/ossec/etc/ossec.conf"))
	}
	// a missing leaf is created under an existing parent
	f.ok(t, "xml.set", map[string]any{"path": p, "xpath": "//auth/port", "value": "1515"}, func(r *Request) { r.Deadman = NoDeadman })
	if !strings.Contains(f.read(t, "var/ossec/etc/ossec.conf"), "    <use_password>a&lt;b&amp;c</use_password>\n    <port>1515</port>\n  </auth>") {
		t.Fatalf("created element:\n%s", f.read(t, "var/ossec/etc/ossec.conf"))
	}
	// idempotent, and refusal paths
	if o := f.ok(t, "xml.set", map[string]any{"path": p, "xpath": "//auth/port", "value": "1515"}); !o.Plan.Done {
		t.Fatal("not idempotent")
	}
	for _, x := range []string{"//global", "//nosuch/thing", "//auth[0]/port", "//a/*/b", "//auth/port/../x"} {
		if _, err := f.run(t, "xml.set", map[string]any{"path": p, "xpath": x, "value": "v"}); err == nil {
			t.Errorf("xpath %q accepted", x)
		}
	}
	f.write(t, "var/ossec/etc/broken.conf", "<a><b></a>", 0o640)
	if _, err := f.run(t, "xml.set", map[string]any{"path": "/var/ossec/etc/broken.conf", "xpath": "//b", "value": "x"}); err == nil {
		t.Fatal("malformed XML accepted")
	}
}

func TestXMLSetAttributePredicateAndRollback(t *testing.T) {
	f := newFixture(t)
	doc := `<c><wodle name="a"><disabled>no</disabled></wodle><wodle name="b"><disabled>no</disabled></wodle></c>`
	f.write(t, "x/c.xml", doc, 0o640)
	o := f.ok(t, "xml.set", map[string]any{"path": "/x/c.xml", "xpath": `//wodle[@name='b']/disabled`, "value": "yes"}, func(r *Request) { r.Deadman = 60e9 })
	if f.read(t, "x/c.xml") != `<c><wodle name="a"><disabled>no</disabled></wodle><wodle name="b"><disabled>yes</disabled></wodle></c>` {
		t.Fatal(f.read(t, "x/c.xml"))
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil || f.read(t, "x/c.xml") != doc {
		t.Fatalf("rollback: %v", err)
	}
}

func TestSysctlSetPersistsAndRollsBack(t *testing.T) {
	f := newFixture(t)
	f.write(t, "proc/sys/user/max_user_namespaces", "15000\n", 0o644)
	f.write(t, "etc/sysctl.d/99-phylax.conf", "# mine\nkernel.dmesg_restrict = 1\n", 0o644)
	p := map[string]any{"key": "user.max_user_namespaces", "value": "0"}
	o, err := f.run(t, "sysctl.set", p, func(r *Request) { r.DryRun = true })
	if err != nil || !strings.Contains(o.Plan.Diff, "runtime user.max_user_namespaces: 15000 -> 0") || !strings.Contains(strings.Join(o.Plan.Notes, " "), "user namespaces") {
		t.Fatalf("dry run: %+v %v", o.Plan, err)
	}
	if f.read(t, "proc/sys/user/max_user_namespaces") != "15000\n" {
		t.Fatal("dry run wrote")
	}
	o = f.ok(t, "sysctl.set", p, func(r *Request) { r.Deadman = 60e9 })
	if f.read(t, "proc/sys/user/max_user_namespaces") != "0\n" || f.read(t, "etc/sysctl.d/99-phylax.conf") != "# mine\nkernel.dmesg_restrict = 1\nuser.max_user_namespaces = 0\n" {
		t.Fatalf("applied: %q %q", f.read(t, "proc/sys/user/max_user_namespaces"), f.read(t, "etc/sysctl.d/99-phylax.conf"))
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if f.read(t, "proc/sys/user/max_user_namespaces") != "15000\n" || f.read(t, "etc/sysctl.d/99-phylax.conf") != "# mine\nkernel.dmesg_restrict = 1\n" {
		t.Fatal("rollback must restore both the runtime value and the file")
	}
}

func TestSysctlRefusals(t *testing.T) {
	f := newFixture(t)
	f.write(t, "proc/sys/net/ipv4/icmp_echo_ignore_all", "0\n", 0o644)
	if err := f.refused(t, "sysctl.set", map[string]any{"key": "net.ipv4.icmp_echo_ignore_all", "value": "1"}); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("icmp: %v", err)
	}
	for _, k := range []string{"../etc.passwd", "Net.IPv4.X", "nodot", "a.b/../../c"} {
		if _, err := f.run(t, "sysctl.set", map[string]any{"key": k, "value": "1"}); err == nil {
			t.Errorf("key %q accepted", k)
		}
	}
	if _, err := f.run(t, "sysctl.set", map[string]any{"key": "no.such.key", "value": "1"}); err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestKernelModuleBlock(t *testing.T) {
	f := newFixture(t)
	f.write(t, "proc/modules", "algif_aead 16384 0 - Live 0x0\nother 1 0 - Live 0x0\n", 0o444)
	var mu sync.Mutex
	var unloaded []string
	busy := false
	f.linux(t).UnloadModule = func(n string) error {
		mu.Lock()
		defer mu.Unlock()
		if busy {
			return syscall.EBUSY
		}
		unloaded = append(unloaded, n)
		return nil
	}
	o, err := f.run(t, "kernel.module_block", map[string]any{"module": "algif_aead"}, func(r *Request) { r.DryRun = true })
	if err != nil || !strings.Contains(o.Plan.Diff, "unload module algif_aead") || !strings.Contains(o.Plan.Diff, "+install algif_aead /bin/false") {
		t.Fatalf("dry run: %+v %v", o.Plan, err)
	}
	if len(unloaded) != 0 {
		t.Fatal("dry run unloaded")
	}
	o = f.ok(t, "kernel.module_block", map[string]any{"module": "algif_aead"}, func(r *Request) { r.Deadman = 60e9 })
	if f.read(t, "etc/modprobe.d/phylax-algif_aead.conf") != "# managed by phylax: module blocked\nblacklist algif_aead\ninstall algif_aead /bin/false\n" || len(unloaded) != 1 || o.Output["unloaded"] != "true" {
		t.Fatalf("applied: %v %v", unloaded, o.Output)
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.run(t, "kernel.module_block", map[string]any{"module": "../x"}); err == nil {
		t.Fatal("bad module accepted")
	}
	// a module in use stays resident but is blocked from loading; that is not a failure
	busy = true
	o = f.ok(t, "kernel.module_block", map[string]any{"module": "algif_aead"}, func(r *Request) { r.Deadman = NoDeadman })
	if o.Output["unloaded"] != "false" {
		t.Fatalf("busy module: %v", o.Output)
	}
}

func TestSystemdDropin(t *testing.T) {
	f := newFixture(t)
	rs := &reloadServices{fakeServices: newFakeServices()}
	f.env.Services = rs
	p := map[string]any{"unit": "splunk", "settings": map[string]any{"MemoryMax": "2G", "Restart": "on-failure"}}
	o, err := f.run(t, "systemd.dropin", p, func(r *Request) { r.DryRun = true })
	if err != nil || !strings.Contains(o.Plan.Diff, "+MemoryMax=2G") {
		t.Fatalf("dry run: %+v %v", o.Plan, err)
	}
	o = f.ok(t, "systemd.dropin", p, func(r *Request) { r.Deadman = 60e9 })
	path := "etc/systemd/system/splunk.service.d/10-phylax.conf"
	if f.read(t, path) != "# managed by phylax\n[Service]\nMemoryMax=2G\nRestart=on-failure\n" || rs.reloads != 1 {
		t.Fatalf("applied: %q reloads=%d", f.read(t, path), rs.reloads)
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "drop-in removed and units reloaded", func() bool { _, err := readBoundedErr(f.path(path)); return err != nil && rs.reloads == 2 })
	// the allowlist keeps ExecStart out
	if _, err := f.run(t, "systemd.dropin", map[string]any{"unit": "sshd", "settings": map[string]any{"ExecStart": "/bin/sh"}}); err == nil {
		t.Fatal("ExecStart accepted")
	}
	// restrictive settings are refused on a scored service
	f.env.Guard = StaticGuard{Services: []string{"httpd"}}
	if err := f.refused(t, "systemd.dropin", map[string]any{"unit": "httpd", "settings": map[string]any{"ProtectSystem": "strict"}}); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("scored restrictive: %v", err)
	}
	if err := f.refused(t, "systemd.dropin", map[string]any{"unit": "httpd.service", "settings": map[string]any{"Restart": "no"}}); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("scored Restart=no: %v", err)
	}
	f.ok(t, "systemd.dropin", map[string]any{"unit": "httpd", "settings": map[string]any{"LimitNOFILE": "65536"}}, func(r *Request) { r.Deadman = NoDeadman })
}

func readBoundedErr(p string) ([]byte, error) { b, _, err := readBounded(p); return b, err }

func TestCockpitDisable(t *testing.T) {
	f := newFixture(t)
	fs := f.env.Services.(*fakeServices)
	fs.units["cockpit.socket"] = &UnitState{Exists: true, Active: true, Enabled: "enabled"}
	fs.units["cockpit.service"] = &UnitState{Exists: true, Active: true, Enabled: "static"}
	o, err := f.run(t, "cockpit.disable", map[string]any{}, func(r *Request) { r.DryRun = true })
	if err != nil || !strings.Contains(o.Plan.Diff, "cockpit.socket") {
		t.Fatalf("dry run: %+v %v", o.Plan, err)
	}
	o = f.ok(t, "cockpit.disable", map[string]any{}, func(r *Request) { r.Deadman = 60e9 })
	if fs.units["cockpit.socket"].Active || fs.units["cockpit.socket"].Enabled != "disabled" || fs.units["cockpit.service"].Active {
		t.Fatalf("state: %+v %+v", fs.units["cockpit.socket"], fs.units["cockpit.service"])
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if !fs.units["cockpit.socket"].Active || fs.units["cockpit.socket"].Enabled != "enabled" {
		t.Fatalf("rollback: %+v", fs.units["cockpit.socket"])
	}
	// a host without Cockpit is already done
	f2 := newFixture(t)
	if o := f2.ok(t, "cockpit.disable", map[string]any{}); !o.Plan.Done {
		t.Fatalf("no cockpit: %+v", o.Plan)
	}
	// a scored cockpit unit is protected
	f.env.Guard = StaticGuard{Services: []string{"cockpit.socket"}}
	if err := f.refused(t, "cockpit.disable", map[string]any{}); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("scored: %v", err)
	}
}

func TestCronAndAtDisableQuarantineNeverDelete(t *testing.T) {
	f := newFixture(t)
	f.write(t, "etc/cron.d/backdoor", "* * * * * root /tmp/x\n", 0o644)
	f.write(t, "var/spool/cron/crontabs/bob", "@reboot /tmp/y\n", 0o600)
	f.write(t, "var/spool/at/a0001", "#!/bin/sh\nid\n", 0o700)
	o := f.ok(t, "cron.disable", map[string]any{"path": "/etc/cron.d/backdoor", "reason": "unknown job"}, func(r *Request) { r.Deadman = 60e9 })
	if _, err := readBoundedErr(f.path("etc/cron.d/backdoor")); err == nil {
		t.Fatal("cron file still active")
	}
	id := o.Output["id"]
	if id == "" || readAbs(t, f.env.QuarantineDir+"/"+id) != "* * * * * root /tmp/x\n" {
		t.Fatalf("payload not in quarantine: %v", o.Output)
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil || f.read(t, "etc/cron.d/backdoor") != "* * * * * root /tmp/x\n" {
		t.Fatalf("rollback: %v", err)
	}
	f.ok(t, "cron.disable", map[string]any{"path": "/var/spool/cron/crontabs/bob"}, func(r *Request) { r.Deadman = NoDeadman })
	f.ok(t, "at.disable", map[string]any{"path": "/var/spool/at/a0001"}, func(r *Request) { r.Deadman = NoDeadman })
	// location allowlists: no deletion/quarantine of arbitrary files through these actions
	f.write(t, "etc/passwd.keep", "x", 0o644)
	for _, bad := range []struct{ a, p string }{
		{"cron.disable", "/etc/passwd"}, {"cron.disable", "/etc/cron.d/"}, {"cron.disable", "/etc/cron.d/../passwd"},
		{"at.disable", "/etc/cron.d/backdoor"}, {"cron.disable", "/var/spool/at/a0001"},
	} {
		if _, err := f.run(t, bad.a, map[string]any{"path": bad.p}); err == nil {
			t.Errorf("%s %s accepted", bad.a, bad.p)
		}
	}
}

func readAbs(t *testing.T, abs string) string {
	t.Helper()
	b, err := readBoundedErr(abs)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type fakeAttr struct {
	mu    sync.Mutex
	flags map[string]uint32
}

func (a *fakeAttr) Get(p string) (uint32, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.flags[p], nil
}
func (a *fakeAttr) Set(p string, f uint32) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.flags[p] = f
	return nil
}

func TestFileAttr(t *testing.T) {
	f := newFixture(t)
	fa := &fakeAttr{flags: map[string]uint32{}}
	f.linux(t).Attr = fa
	f.write(t, "var/www/html/index.php", "<?php", 0o644)
	f.write(t, "var/www/html/system/storage/cache/x", "", 0o644)
	real := f.path("var/www/html/index.php")
	o, err := f.run(t, "file.attr", map[string]any{"path": "/var/www/html/index.php", "add": "i"}, func(r *Request) { r.DryRun = true })
	if err != nil || !strings.Contains(o.Plan.Diff, "- -> i") {
		t.Fatalf("dry run: %+v %v", o.Plan, err)
	}
	o = f.ok(t, "file.attr", map[string]any{"path": "/var/www/html/index.php", "add": "i"}, func(r *Request) { r.Deadman = 60e9 })
	if fa.flags[real]&flagImmutable == 0 {
		t.Fatal("flag not set")
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil || fa.flags[real] != 0 {
		t.Fatalf("rollback: %v %x", err, fa.flags[real])
	}
	f.ok(t, "file.attr", map[string]any{"path": "/var/www/html/index.php", "add": "i"}, func(r *Request) { r.Deadman = NoDeadman })
	f.ok(t, "file.attr", map[string]any{"path": "/var/www/html/index.php", "remove": "i"}, func(r *Request) { r.Deadman = NoDeadman })
	if fa.flags[real] != 0 {
		t.Fatal("remove failed")
	}
	// sensitive locations and scored content are refused; bad flags and conflicts too
	if err := f.refused(t, "file.attr", map[string]any{"path": "/var/www/html/system/storage/cache/x", "add": "i"}); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("cache: %v", err)
	}
	f.env.Guard = StaticGuard{Paths: []string{"/var/www/html"}}
	if err := f.refused(t, "file.attr", map[string]any{"path": "/var/www/html/index.php", "add": "i"}); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("scored content: %v", err)
	}
	f.env.Guard = AllowAll{}
	for _, bad := range []map[string]any{{"path": "/var/www/html/index.php", "add": "z"}, {"path": "/var/www/html/index.php", "add": "i", "remove": "i"}, {"path": "/var/www/html/index.php"}} {
		if _, err := f.run(t, "file.attr", bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestFileAttrRealIoctl(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/a"
	if err := writeTestFile(p); err != nil {
		t.Fatal(err)
	}
	var b realAttr
	cur, err := b.Get(p)
	if err != nil {
		t.Skipf("filesystem under %s does not support inode flags: %v", dir, err)
	}
	if err := b.Set(p, cur|flagNoDump); err != nil {
		t.Skipf("cannot set inode flags here: %v", err)
	}
	got, _ := b.Get(p)
	if got&flagNoDump == 0 {
		t.Fatalf("flag not set: %x", got)
	}
	_ = b.Set(p, cur)
}

var _ = context.Background
