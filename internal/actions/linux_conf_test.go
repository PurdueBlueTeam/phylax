package actions

import (
	"errors"
	"strings"
	"testing"
)

func TestEditConfINIPreservesCommentsAndOrder(t *testing.T) {
	src := "; php config\n[PHP]\nexpose_php = On ; leak\n; allow_url_fopen = On\nallow_url_fopen = On\n\n[Date]\ndate.timezone = UTC\n"
	out, ch, err := editConf(src, styleINI, "PHP", "expose_php", "Off")
	if err != nil || !ch {
		t.Fatalf("%v %v", ch, err)
	}
	want := "; php config\n[PHP]\nexpose_php = Off\n; allow_url_fopen = On\nallow_url_fopen = On\n\n[Date]\ndate.timezone = UTC\n"
	if out != want {
		t.Fatalf("got:\n%s", out)
	}
	// a key missing from an existing stanza is appended inside that stanza, not at EOF
	out, _, _ = editConf(src, styleINI, "PHP", "open_basedir", "/var/www")
	if !strings.Contains(out, "allow_url_fopen = On\nopen_basedir = /var/www\n\n[Date]") {
		t.Fatalf("insert position:\n%s", out)
	}
	// a missing stanza is created at the end
	out, _, _ = editConf(src, styleINI, "postgres", "disabled", "true")
	if !strings.HasSuffix(out, "date.timezone = UTC\n\n[postgres]\ndisabled = true\n") {
		t.Fatalf("new stanza:\n%s", out)
	}
	// same value: no change, byte-identical
	out, ch, _ = editConf(src, styleINI, "Date", "date.timezone", "UTC")
	if ch || out != src {
		t.Fatal("idempotent edit changed the text")
	}
	// the same key in another stanza is untouched
	out, _, _ = editConf("[a]\nk=1\n[b]\nk=2\n", styleINI, "b", "k", "9")
	if out != "[a]\nk=1\n[b]\nk=9\n" {
		t.Fatalf("stanza scoping: %q", out)
	}
}

func TestEditConfSSHDInsertsBeforeMatch(t *testing.T) {
	src := "# sshd\nPort 22\n#X11Forwarding yes\nx11forwarding yes\nMatch User bob\n    X11Forwarding yes\n"
	out, _, err := editConf(src, styleSpace, "", "X11Forwarding", "no")
	if err != nil {
		t.Fatal(err)
	}
	if out != "# sshd\nPort 22\n#X11Forwarding yes\nx11forwarding no\nMatch User bob\n    X11Forwarding yes\n" {
		t.Fatalf("case-insensitive key, Match block untouched:\n%s", out)
	}
	out, _, _ = editConf(src, styleSpace, "", "LoginGraceTime", "20")
	if out != "# sshd\nPort 22\n#X11Forwarding yes\nx11forwarding yes\nLoginGraceTime 20\nMatch User bob\n    X11Forwarding yes\n" {
		t.Fatalf("new global key must land before the first Match:\n%s", out)
	}
}

func TestEditConfPostfixContinuationAndDovecotBlocks(t *testing.T) {
	pf := "myhostname = mail\nsmtpd_relay_restrictions = permit_mynetworks,\n    permit_sasl_authenticated,\n    defer_unauth_destination\n# end\n"
	out, _, _ := editConf(pf, styleEquals, "", "smtpd_relay_restrictions", "permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination")
	if out != "myhostname = mail\nsmtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination\n# end\n" {
		t.Fatalf("continuation lines must be replaced with the value:\n%s", out)
	}
	dv := "protocols = imap\nservice imap-login {\n  inet_listener imap {\n    port = 143\n  }\n}\nssl = yes\n"
	out, _, _ = editConf(dv, styleEquals, "", "port", "0")
	if !strings.Contains(out, "port = 143") || !strings.HasSuffix(out, "ssl = yes\nport = 0\n") {
		t.Fatalf("top-level edit must not touch keys inside blocks:\n%s", out)
	}
	out, _, _ = editConf(dv, styleEquals, "", "ssl", "yes")
	if out != dv {
		t.Fatal("idempotent")
	}
	if _, _, err := editConf("service x {\n", styleEquals, "", "a", "b"); err == nil {
		t.Fatal("unbalanced braces must be refused")
	}
}

func TestEditConfRejectsInjection(t *testing.T) {
	for _, v := range []string{"a\nPermitRootLogin yes", "a\x00b", "a\rb"} {
		if _, _, err := editConf("", styleSpace, "", "Port", v); err == nil {
			t.Fatalf("value %q accepted", v)
		}
	}
	if _, _, err := editConf("", styleINI, "x\n[evil]", "k", "v"); err == nil {
		t.Fatal("stanza injection accepted")
	}
	if _, _, err := editConf("", styleINI, "", "bad key", "v"); err == nil {
		t.Fatal("bad key accepted")
	}
}

const splunkServerConf = "# Splunk server.conf\n[general]\nserverName = splunk1\n\n[sslConfig]\nsslPassword = $7$abc\n"

func TestIniSetSplunkDryRunApplyRollback(t *testing.T) {
	f := newFixture(t)
	f.write(t, "opt/splunk/etc/system/local/server.conf", splunkServerConf, 0o600)
	p := map[string]any{"path": "/opt/splunk/etc/system/local/server.conf", "stanza": "postgres", "key": "disabled", "value": "true"}
	o, err := f.run(t, "ini.set", p, func(r *Request) { r.DryRun = true })
	if err != nil || !strings.Contains(o.Plan.Diff, "+[postgres]") || !strings.Contains(o.Plan.Diff, "+disabled = true") {
		t.Fatalf("dry run: %+v %v", o.Plan, err)
	}
	if f.read(t, "opt/splunk/etc/system/local/server.conf") != splunkServerConf {
		t.Fatal("dry run changed the file")
	}
	o = f.ok(t, "ini.set", p, func(r *Request) { r.Deadman = 60e9 })
	got := f.read(t, "opt/splunk/etc/system/local/server.conf")
	if got != splunkServerConf+"\n[postgres]\ndisabled = true\n" {
		t.Fatalf("applied:\n%s", got)
	}
	if o.DeadmanID == "" {
		t.Fatal("dead-man not armed")
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if f.read(t, "opt/splunk/etc/system/local/server.conf") != splunkServerConf {
		t.Fatal("rollback did not restore the file")
	}
	// re-run is a no-op once applied
	f.ok(t, "ini.set", p, func(r *Request) { r.Deadman = NoDeadman })
	o = f.ok(t, "ini.set", p, func(r *Request) { r.Deadman = NoDeadman })
	if o.Changed || !o.Plan.Done {
		t.Fatalf("second run should be Done: %+v", o)
	}
}

func TestConfSetScoringRefusals(t *testing.T) {
	f := newFixture(t)
	f.write(t, "etc/ssh/sshd_config", "Port 22\nPasswordAuthentication yes\n", 0o600)
	f.write(t, "etc/dovecot/dovecot.conf", "disable_plaintext_auth = no\nssl = yes\n", 0o644)
	f.write(t, "etc/postfix/main.cf", "smtpd_tls_security_level = may\n", 0o644)
	f.write(t, "opt/splunk/etc/system/local/web.conf", "[settings]\nenableSplunkWebSSL = 0\n", 0o644)
	f.write(t, "etc/my.cnf", "[mysqld]\nbind-address = 0.0.0.0\n", 0o644)
	cases := []struct {
		path, key, value string
	}{
		{"/etc/ssh/sshd_config", "PasswordAuthentication", "no"},
		{"/etc/ssh/sshd_config", "AuthenticationMethods", "publickey"},
		{"/etc/ssh/sshd_config", "PermitTTY", "no"},
		{"/etc/ssh/sshd_config", "ForceCommand", "/bin/false"},
		{"/etc/ssh/sshd_config", "LoginGraceTime", "0"},
		{"/etc/ssh/sshd_config", "AllowGroups", "wheel"},
		{"/etc/dovecot/dovecot.conf", "disable_plaintext_auth", "yes"},
		{"/etc/dovecot/dovecot.conf", "ssl", "required"},
		{"/etc/postfix/main.cf", "smtpd_tls_security_level", "encrypt"},
		{"/etc/postfix/main.cf", "smtpd_tls_auth_only", "yes"},
		{"/etc/postfix/main.cf", "smtpd_sasl_security_options", "noanonymous,noplaintext"},
		{"/etc/postfix/main.cf", "smtpd_sender_restrictions", "reject_non_fqdn_sender, reject_unknown_sender_domain"},
		{"/etc/postfix/main.cf", "postscreen_greet_action", "enforce"},
		{"/opt/splunk/etc/system/local/web.conf", "enableSplunkWebSSL", "1"},
		{"/etc/my.cnf", "bind-address", "127.0.0.1"},
	}
	for _, c := range cases {
		before := f.read(t, strings.TrimPrefix(c.path, "/"))
		err := f.refused(t, "conf.set", map[string]any{"path": c.path, "key": c.key, "value": c.value})
		if !errors.Is(err, ErrScoringUnsafe) {
			t.Errorf("%s %s=%s: want a scoring refusal, got %v", c.path, c.key, c.value, err)
		}
		if f.read(t, strings.TrimPrefix(c.path, "/")) != before {
			t.Errorf("%s changed despite the refusal", c.path)
		}
	}
	// the dry run refuses too
	if _, err := f.run(t, "conf.set", map[string]any{"path": "/etc/ssh/sshd_config", "key": "PasswordAuthentication", "value": "no"},
		func(r *Request) { r.DryRun = true }); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("dry run: %v", err)
	}
	// safe edits pass
	f.ok(t, "conf.set", map[string]any{"path": "/etc/ssh/sshd_config", "key": "X11Forwarding", "value": "no"}, func(r *Request) { r.Deadman = NoDeadman })
	f.ok(t, "conf.set", map[string]any{"path": "/etc/dovecot/dovecot.conf", "key": "ssl", "value": "yes"}, func(r *Request) { r.Deadman = NoDeadman })
	f.ok(t, "conf.set", map[string]any{"path": "/etc/ssh/sshd_config", "key": "PermitRootLogin", "value": "no"}, func(r *Request) { r.Deadman = NoDeadman })
	// ... but not once root is a scored account
	f.env.Guard = StaticGuard{Accounts: []string{"root"}}
	if err := f.refused(t, "conf.set", map[string]any{"path": "/etc/ssh/sshd_config", "key": "PermitRootLogin", "value": "no"}); err == nil {
		t.Fatal("unreachable")
	}
}

func TestSSHDAllowUsersMustCoverScoredAccounts(t *testing.T) {
	f := newFixture(t)
	f.write(t, "etc/ssh/sshd_config", "Port 22\n", 0o600)
	f.env.Guard = StaticGuard{Accounts: []string{"alice", "bob"}, Services: []string{"sshd"}}
	p := func(v string) map[string]any {
		return map[string]any{"path": "/etc/ssh/sshd_config", "key": "AllowUsers", "value": v}
	}
	if err := f.refused(t, "conf.set", p("alice sysadmin")); !errors.Is(err, ErrScoringUnsafe) || !strings.Contains(err.Error(), "bob") {
		t.Fatalf("AllowUsers omitting bob: %v", err)
	}
	f.ok(t, "conf.set", p("alice bob sysadmin"), func(r *Request) { r.Deadman = NoDeadman })
}

func TestLintSkippedWhenServiceIsNotScored(t *testing.T) {
	f := newFixture(t)
	f.write(t, "etc/dovecot/dovecot.conf", "ssl = yes\n", 0o644)
	// the guard knows this host's scored services and dovecot is not one of them
	f.env.Guard = StaticGuard{Services: []string{"httpd"}}
	f.ok(t, "conf.set", map[string]any{"path": "/etc/dovecot/dovecot.conf", "key": "ssl", "value": "required"}, func(r *Request) { r.Deadman = NoDeadman })
}

func TestConfSetValidatorFailureRollsBack(t *testing.T) {
	f := newFixture(t)
	orig := "Port 22\nPasswordAuthentication yes\n"
	f.write(t, "etc/ssh/sshd_config", orig, 0o600)
	fr := &fakeRunner{}
	fr.on("/usr/sbin/sshd -t", CmdResult{ExitCode: 255, Stderr: "line 3: Bad configuration option"})
	f.linux(t).Exec = fr
	_, err := f.run(t, "conf.set", map[string]any{"path": "/etc/ssh/sshd_config", "key": "X11Forwarding", "value": "no"})
	if err == nil || !strings.Contains(err.Error(), "config check") {
		t.Fatalf("want a config check failure, got %v", err)
	}
	waitFor(t, "sshd_config restored", func() bool { return f.read(t, "etc/ssh/sshd_config") == orig })
	// with a passing validator the edit stands, and the checker ran on the resolved config
	fr.on("/usr/sbin/sshd -t", CmdResult{})
	f.ok(t, "conf.set", map[string]any{"path": "/etc/ssh/sshd_config", "key": "X11Forwarding", "value": "no"}, func(r *Request) { r.Deadman = NoDeadman })
	if c := fr.ran("/usr/sbin/sshd -t -f " + f.path("etc/ssh/sshd_config")); len(c) == 0 {
		t.Fatalf("validator not run against the resolved path: %v", fr.calls)
	}
}

func TestServiceConfigTransactionAndRestart(t *testing.T) {
	f := newFixture(t)
	f.write(t, "etc/ssh/sshd_config", "Port 22\n", 0o600)
	fr := &fakeRunner{}
	fr.on("/usr/sbin/sshd -t", CmdResult{})
	f.linux(t).Exec = fr
	// one bad setting refuses the whole transaction
	err := f.refused(t, "service.config", map[string]any{"service": "sshd", "settings": map[string]any{"X11Forwarding": "no", "PasswordAuthentication": "no"}})
	if !errors.Is(err, ErrScoringUnsafe) || f.read(t, "etc/ssh/sshd_config") != "Port 22\n" {
		t.Fatalf("%v", err)
	}
	f.env.Services.(*fakeServices).units["sshd.service"] = &UnitState{Exists: true, Active: true, Enabled: "enabled"}
	o := f.ok(t, "service.config", map[string]any{"service": "sshd", "restart": true,
		"settings": map[string]any{"X11Forwarding": "no", "LoginGraceTime": "20"}}, func(r *Request) { r.Deadman = 60e9 })
	got := f.read(t, "etc/ssh/sshd_config")
	if got != "Port 22\nLoginGraceTime 20\nX11Forwarding no\n" && got != "Port 22\nX11Forwarding no\nLoginGraceTime 20\n" {
		t.Fatalf("config:\n%s", got)
	}
	calls := strings.Join(f.env.Services.(*fakeServices).calls, ",")
	if !strings.Contains(calls, "restart sshd") {
		t.Fatalf("no restart: %s", calls)
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if f.read(t, "etc/ssh/sshd_config") != "Port 22\n" {
		t.Fatal("rollback")
	}
	if n := strings.Count(strings.Join(f.env.Services.(*fakeServices).calls, ","), "restart sshd"); n != 2 {
		t.Fatalf("rollback must restart the service again, restarts=%d", n)
	}
}

func TestAgentOptSetWindowsPath(t *testing.T) {
	f := newFixture(t)
	path := `C:\Program Files (x86)\ossec-agent\local_internal_options.conf`
	f.write(t, "Program Files (x86)/ossec-agent/local_internal_options.conf", "# local\nwazuh_command.remote_commands=1\n", 0o640)
	keys := "wazuh_command.remote_commands=0,logcollector.remote_commands=0,sca.remote_commands=0"
	f.ok(t, "agentopt.set", map[string]any{"path": path, "keys": keys}, func(r *Request) { r.Deadman = NoDeadman })
	got := f.read(t, "Program Files (x86)/ossec-agent/local_internal_options.conf")
	if got != "# local\nwazuh_command.remote_commands=0\nlogcollector.remote_commands=0\nsca.remote_commands=0\n" {
		t.Fatalf("got:\n%s", got)
	}
	o := f.ok(t, "agentopt.set", map[string]any{"path": path, "keys": keys})
	if !o.Plan.Done {
		t.Fatal("second run not Done")
	}
	for _, bad := range []map[string]any{
		{"path": "/etc/passwd", "keys": keys},
		{"path": "relative/local_internal_options.conf", "keys": keys},
		{"path": path, "keys": "no_equals"},
		{"path": path, "keys": "a.b=1\nc.d=2\x00"},
	} {
		if _, err := f.run(t, "agentopt.set", bad); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}
