package actions

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// ---- win.service.config ----

func (f *winFixture) addService(name, start string, running bool) {
	f.svc.cfg[strings.ToLower(name)] = &SvcConfig{Exists: true, Start: start, Running: running}
	fs := f.env.Services.(*fakeServices)
	fs.units[name+".service"] = &UnitState{Exists: true, Active: running, Enabled: "enabled"}
}

func TestSpoolerDisabledOnDC(t *testing.T) {
	f := newWinFixture(t)
	f.setOS("17763", 3650, "LanmanNT")
	f.addService("Spooler", "auto", true)
	p := map[string]any{"unit": "Spooler", "start": "disabled", "stop": true, "dc_only": true}
	o := f.ok(t, "win.service.config", p, func(r *Request) { r.DryRun = true })
	if !strings.Contains(o.Plan.Diff, "auto -> disabled") || !strings.Contains(o.Plan.Diff, "running -> stopped") {
		t.Fatalf("diff %q", o.Plan.Diff)
	}
	o = f.ok(t, "win.service.config", p, func(r *Request) { r.Deadman = time.Minute })
	c, _ := f.svc.Config(t.Context(), "Spooler")
	if c.Start != "disabled" {
		t.Fatal("start type not changed")
	}
	if st, _ := f.env.Services.State(t.Context(), "Spooler"); st.Active {
		t.Fatal("service still running")
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	c, _ = f.svc.Config(t.Context(), "Spooler")
	if st, _ := f.env.Services.State(t.Context(), "Spooler"); c.Start != "auto" || !st.Active {
		t.Fatalf("rollback: start=%s active=%v", c.Start, st.Active)
	}
}

func TestServiceConfigDCOnlyLeavesMemberServersAlone(t *testing.T) {
	f := newWinFixture(t)
	f.setOS("17763", 3650, "ServerNT")
	f.addService("Spooler", "auto", true)
	o := f.ok(t, "win.service.config", map[string]any{"unit": "Spooler", "start": "disabled", "dc_only": true})
	if o.Changed {
		t.Fatal("changed a non-DC with dc_only")
	}
	if c, _ := f.svc.Config(t.Context(), "Spooler"); c.Start != "auto" {
		t.Fatal("start type changed")
	}
}

func TestServiceConfigRefusals(t *testing.T) {
	f := newWinFixture(t)
	f.setOS("17763", 3650, "LanmanNT")
	for _, u := range []string{"WinRM", "TermService", "LanmanServer", "Netlogon", "NTDS", "DNS"} {
		f.addService(u, "auto", true)
		if _, err := f.run(t, "win.service.config", map[string]any{"unit": u, "start": "disabled"}); !errors.Is(err, ErrScoringUnsafe) {
			t.Errorf("%s: want a refusal, got %v", u, err)
		}
		if _, err := f.run(t, "win.service.config", map[string]any{"unit": u, "start": "auto", "stop": true}); !errors.Is(err, ErrScoringUnsafe) {
			t.Errorf("%s stop: want a refusal, got %v", u, err)
		}
	}
	// scored service refused by the guard
	f.addService("Dnscache", "auto", true)
	f.env.Guard = StaticGuard{Services: []string{"dnscache"}}
	if _, err := f.run(t, "win.service.config", map[string]any{"unit": "Dnscache", "start": "disabled"}); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("scored service: %v", err)
	}
	// setting a non-disabling start type on a core service is fine
	f.env.Guard = AllowAll{}
	f.ok(t, "win.service.config", map[string]any{"unit": "WinRM", "start": "auto_delayed"})
	// a missing service is not an error
	o := f.ok(t, "win.service.config", map[string]any{"unit": "NoSuchSvc", "start": "disabled"})
	if o.Changed {
		t.Fatal("changed a service that does not exist")
	}
}

// ---- audit policy ----

const auditpolCSV = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\r\n" +
	"DC1,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},%s,\r\n"

func TestExecAuditParsesAndSets(t *testing.T) {
	ex := &fakeExec{reply: func(c execCall) (string, int) {
		if c.args[0] == "/get" {
			return strings.Replace(auditpolCSV, "%s", "Success and Failure", 1), 0
		}
		return "The command was successfully executed.", 0
	}}
	a := ExecAudit{Exec: ex}
	got, err := a.Get(t.Context(), "Process Creation")
	if err != nil || !got.Success || !got.Failure {
		t.Fatalf("%+v %v", got, err)
	}
	if err := a.Set(t.Context(), "process creation", AuditSetting{Success: true}); err != nil {
		t.Fatal(err)
	}
	last := ex.calls[len(ex.calls)-1]
	if strings.Join(last.args, " ") != "/set /subcategory:process creation /success:enable /failure:disable" {
		t.Fatalf("args %v", last.args)
	}
	if err := a.Set(t.Context(), `Logon" /clear`, AuditSetting{}); err == nil {
		t.Fatal("arbitrary subcategory string reached auditpol")
	}
}

func TestAuditPolicySetWithRollback(t *testing.T) {
	f := newWinFixture(t)
	f.aud.m["logon"] = AuditSetting{Success: true}
	p := map[string]any{"subcategories": map[string]any{"Process Creation": "success", "Logon": "success,failure"}}
	o := f.ok(t, "win.audit_policy.set", p, func(r *Request) { r.DryRun = true })
	if !strings.Contains(o.Plan.Diff, "audit Process Creation: none -> success") || !strings.Contains(o.Plan.Diff, "ProcessCreationIncludeCmdLine_Enabled") {
		t.Fatalf("diff %q", o.Plan.Diff)
	}
	o = f.ok(t, "win.audit_policy.set", p, func(r *Request) { r.Deadman = time.Minute })
	if !f.aud.m["process creation"].Success || !f.aud.m["logon"].Failure {
		t.Fatalf("audit not set: %+v", f.aud.m)
	}
	if n, _ := f.reg.dword(auditCmdlineKey, auditCmdlineName); n != 1 {
		t.Fatal("4688 command-line logging not enabled")
	}
	if n, _ := f.reg.dword(lsaKey, "SCENoApplyLegacyAuditPolicy"); n != 1 {
		t.Fatal("advanced audit policy override not set")
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if f.aud.m["process creation"] != (AuditSetting{}) || f.aud.m["logon"] != (AuditSetting{Success: true}) {
		t.Fatalf("audit not rolled back: %+v", f.aud.m)
	}
	if _, ok := f.reg.val(auditCmdlineKey, auditCmdlineName); ok {
		t.Fatal("cmdline key not rolled back")
	}
	// idempotent
	f.ok(t, "win.audit_policy.set", p)
	if o := f.ok(t, "win.audit_policy.set", p); o.Changed {
		t.Fatal("not idempotent")
	}
}

func TestAuditPolicyProfileAndErrors(t *testing.T) {
	f := newWinFixture(t)
	f.ok(t, "win.audit_policy.set", map[string]any{"profile": "dc"})
	for _, k := range []string{"directory service changes", "kerberos authentication service", "process creation"} {
		if !f.aud.m[k].Success {
			t.Errorf("profile dc left %s unset", k)
		}
	}
	for _, p := range []map[string]any{
		{"subcategories": map[string]any{"Not A Thing": "success"}},
		{"subcategories": map[string]any{"Logon": "maybe"}},
	} {
		if _, err := f.run(t, "win.audit_policy.set", p); err == nil {
			t.Errorf("%v accepted", p)
		}
	}
	if _, err := f.run(t, "win.audit_policy.set", map[string]any{"cmdline": false}); err == nil {
		t.Error("empty request accepted")
	}
}

// ---- defender ----

func TestDefenderAuditAndRemoval(t *testing.T) {
	f := newWinFixture(t)
	f.def.excl = []Exclusion{{ExclPath, `C:\Program Files\phylax-7f3a`}, {ExclPath, `C:\Users\Public`}, {ExclExtension, ".ps1"}, {ExclProcess, "beacon.exe"}}
	f.def.realtime = false
	o := f.ok(t, "win.defender.audit", map[string]any{"keep": []any{`C:\Program Files\phylax-7f3a`}})
	if o.Output["unexpected_count"] != "3" || !strings.Contains(o.Output["unexpected"], "beacon.exe") || o.Output["realtime"] != "false" {
		t.Fatalf("audit output %v", o.Output)
	}
	p := map[string]any{"keep": []any{`C:\Program Files\phylax-7f3a`}}
	o = f.ok(t, "win.defender", p, func(r *Request) { r.Deadman = time.Minute })
	if len(f.def.excl) != 1 || !f.def.realtime {
		t.Fatalf("after removal: %+v realtime=%v", f.def.excl, f.def.realtime)
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if len(f.def.excl) != 4 || f.def.realtime {
		t.Fatalf("rollback: %+v realtime=%v", f.def.excl, f.def.realtime)
	}
	// keep matches path prefixes, case-insensitively
	if !kept(Exclusion{ExclPath, `c:\program files\PHYLAX-7f3a\bin`}, []string{`C:\Program Files\phylax-7f3a\`}) {
		t.Fatal("prefix keep failed")
	}
	if kept(Exclusion{ExclPath, `C:\Program Files\phylax-7f3a-evil`}, []string{`C:\Program Files\phylax-7f3a`}) {
		t.Fatal("keep matched a sibling directory")
	}
}

func TestExecDefenderQuoting(t *testing.T) {
	ex := &fakeExec{}
	d := ExecDefender{Reg: newFakeReg(), Exec: ex}
	if err := d.RemoveExclusion(t.Context(), Exclusion{ExclPath, `C:\O'Brien`}); err != nil {
		t.Fatal(err)
	}
	cmd := ex.calls[0].args[len(ex.calls[0].args)-1]
	if !strings.Contains(cmd, `'C:\O''Brien'`) || !strings.Contains(cmd, "Remove-MpPreference -ExclusionPath") {
		t.Fatalf("command %q", cmd)
	}
	if err := d.AddExclusion(t.Context(), Exclusion{ExclPath, "a\nb"}); err == nil {
		t.Fatal("control character accepted")
	}
	reg := newFakeReg()
	reg.put(`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`, `C:\x`, RegValue{Type: "dword"})
	reg.put(`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes`, `evil.exe`, RegValue{Type: "dword"})
	got, _ := ExecDefender{Reg: reg, Exec: ex}.Exclusions(t.Context())
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
}

// ---- windows firewall ----

func TestWinFirewallAllowAndRollback(t *testing.T) {
	f := newWinFixture(t)
	p := map[string]any{"name": "phylax-hec", "ports": "8088", "proto": "tcp", "from": "10.0.0.0/24"}
	o := f.ok(t, "win.firewall", p, func(r *Request) { r.DryRun = true })
	if !strings.Contains(o.Plan.Diff, "phylax-phylax-hec") {
		t.Fatalf("diff %q", o.Plan.Diff)
	}
	if _, ok := f.fw.rules["phylax-phylax-hec"]; ok {
		t.Fatal("dry-run added a rule")
	}
	o = f.ok(t, "win.firewall", p)
	r, ok := f.fw.rules["phylax-phylax-hec"]
	if !ok || r.LocalPorts != "8088" || r.RemoteAddresses != "10.0.0.0/24" || r.Group != winServiceGroup || r.Action != "Allow" {
		t.Fatalf("rule %+v", r)
	}
	if o.DeadmanID == "" {
		t.Fatal("no dead-man")
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.fw.rules["phylax-phylax-hec"]; ok {
		t.Fatal("rollback left the rule")
	}
	if _, ok := f.fw.rules["Remote Desktop (foreign)"]; !ok {
		t.Fatal("a foreign rule was touched")
	}
	// idempotent, then remove
	f.ok(t, "win.firewall", p)
	if o := f.ok(t, "win.firewall", p); o.Changed {
		t.Fatal("not idempotent")
	}
	f.ok(t, "win.firewall", map[string]any{"name": "phylax-hec", "ports": "8088", "remove": true})
	if _, ok := f.fw.rules["phylax-phylax-hec"]; ok {
		t.Fatal("rule not removed")
	}
	if _, ok := f.fw.rules["Remote Desktop (foreign)"]; !ok {
		t.Fatal("remove touched a foreign rule")
	}
}

func TestWinFirewallValidation(t *testing.T) {
	f := newWinFixture(t)
	for _, p := range []map[string]any{
		{"name": "x", "ports": ""},
		{"name": "x", "ports": "*"},
		{"name": "x", "ports": "RPC"},
		{"name": "bad/name", "ports": "80"},
		{"name": "x", "ports": "80", "from": "not-an-ip/99"},
	} {
		if _, err := f.run(t, "win.firewall", p); err == nil {
			t.Errorf("%v accepted", p)
		}
	}
}

// ---- hotfix ----

func TestHotfix(t *testing.T) {
	f := newWinFixture(t)
	installed := false
	f.exe.reply = func(c execCall) (string, int) {
		switch c.prog {
		case "powershell.exe":
			if installed {
				return "KB4571694\n", 0
			}
			return "", 1
		case "wusa.exe":
			installed = true
			return "", 3010
		}
		return "", 0
	}
	p := map[string]any{"kb": "kb4571694", "reboot": true}
	o := f.ok(t, "windows.hotfix", p, func(r *Request) { r.DryRun = true })
	if !strings.Contains(o.Plan.Diff, `C:\ProgramData\phylax\depot\windows\KB4571694.msu`) || !strings.Contains(strings.Join(o.Plan.Notes, " "), "DNS and WinRM") {
		t.Fatalf("plan %+v", o.Plan)
	}
	o = f.ok(t, "windows.hotfix", p)
	if o.Output["reboot_required"] != "true" || o.Output["reboot_scheduled"] != "true" {
		t.Fatalf("output %v", o.Output)
	}
	joined := strings.Join(f.exe.joined(), "\n")
	if !strings.Contains(joined, `wusa.exe C:\ProgramData\phylax\depot\windows\KB4571694.msu /quiet /norestart`) || !strings.Contains(joined, "shutdown.exe /r /t 60") {
		t.Fatalf("calls:\n%s", joined)
	}
	// installed now: a no-op
	if o := f.ok(t, "windows.hotfix", map[string]any{"kb": "KB4571694"}); o.Changed {
		t.Fatal("reinstalled")
	}
	for _, bad := range []string{"KB1", "../../x", "KB4571694; calc", ""} {
		if _, err := f.run(t, "windows.hotfix", map[string]any{"kb": bad}); err == nil {
			t.Errorf("kb %q accepted", bad)
		}
	}
	// failures surface
	f.exe.reply = func(c execCall) (string, int) {
		if c.prog == "wusa.exe" {
			return "boom", 5
		}
		return "", 1
	}
	if _, err := f.run(t, "windows.hotfix", map[string]any{"kb": "KB5000001"}); err == nil {
		t.Fatal("wusa failure ignored")
	}
}

// ---- agentopt.set and the platform-aware path validator ----

func TestIsAbsPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/etc/x": true, `C:\Program Files\x`: true, "C:/x": true, `d:\x`: true, `\\srv\share\x`: true,
		"relative/x": false, `C:x`: false, `\x`: false, "": false, `\\srv`: false,
	} {
		if got := IsAbsPath(p); got != want {
			t.Errorf("IsAbsPath(%q) = %v", p, got)
		}
	}
	// the file actions now accept Windows paths on the controller
	spec := fileWrite{name: "file.write"}.Spec()
	if _, err := spec.Validate(map[string]any{"path": `C:\Windows\Temp\x.txt`, "content": "x"}); err != nil {
		t.Fatalf("file.write rejects a Windows path: %v", err)
	}
	if _, err := spec.Validate(map[string]any{"path": `Temp\x.txt`, "content": "x"}); err == nil {
		t.Fatal("relative path accepted")
	}
}

func TestAgentOptSetWindowsPath(t *testing.T) {
	f := newWinFixture(t)
	path := `C:\Program Files (x86)\ossec-agent\local_internal_options.conf`
	f.write(t, "Program Files (x86)/ossec-agent/local_internal_options.conf", "# local\r\nwazuh_command.remote_commands=1\r\nlogcollector.debug=0\r\n", 0o640)
	p := map[string]any{"path": path, "keys": "wazuh_command.remote_commands=0,logcollector.remote_commands=0,sca.remote_commands=0"}
	o := f.ok(t, "agentopt.set", p, func(r *Request) { r.DryRun = true })
	if !strings.Contains(o.Plan.Diff, "+sca.remote_commands=0") || !strings.Contains(o.Plan.Diff, "-wazuh_command.remote_commands=1") {
		t.Fatalf("diff %q", o.Plan.Diff)
	}
	o = f.ok(t, "agentopt.set", p, func(r *Request) { r.Deadman = time.Minute })
	got := f.read(t, "Program Files (x86)/ossec-agent/local_internal_options.conf")
	want := "# local\r\nwazuh_command.remote_commands=0\r\nlogcollector.debug=0\r\nlogcollector.remote_commands=0\r\nsca.remote_commands=0\r\n"
	if got != want {
		t.Fatalf("file:\n%q\nwant\n%q", got, want)
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if f.read(t, "Program Files (x86)/ossec-agent/local_internal_options.conf") != "# local\r\nwazuh_command.remote_commands=1\r\nlogcollector.debug=0\r\n" {
		t.Fatal("rollback did not restore the options file")
	}
	f.ok(t, "agentopt.set", p)
	if o := f.ok(t, "agentopt.set", p); o.Changed {
		t.Fatal("not idempotent")
	}
}

func TestAgentOptSetCreatesAndRefuses(t *testing.T) {
	f := newWinFixture(t)
	f.ok(t, "agentopt.set", map[string]any{"path": "/var/ossec/etc/local_internal_options.conf", "keys": "logcollector.remote_commands=0"})
	if got := f.read(t, "var/ossec/etc/local_internal_options.conf"); got != "logcollector.remote_commands=0\n" {
		t.Fatalf("new file %q", got)
	}
	for _, p := range []map[string]any{
		{"path": "/etc/passwd", "keys": "a.b=1"},
		{"path": `C:\Windows\System32\drivers\etc\hosts`, "keys": "a.b=1"},
		{"path": "/var/ossec/etc/local_internal_options.conf", "keys": "NotAKey=1"},
		{"path": "/var/ossec/etc/local_internal_options.conf", "keys": "a.b=$(rm -rf)"},
		{"path": "/var/ossec/etc/local_internal_options.conf", "keys": ""},
		{"path": "var/ossec/etc/local_internal_options.conf", "keys": "a.b=1"},
	} {
		if _, err := f.run(t, "agentopt.set", p); err == nil {
			t.Errorf("%v accepted", p)
		}
	}
	if _, err := os.Stat(f.path("etc/passwd.bak")); err == nil {
		t.Fatal("unexpected file")
	}
}
