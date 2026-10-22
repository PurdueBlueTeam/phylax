package winevt

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func loadFixture(t *testing.T, name string) *Record {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name+".xml"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseXML(b)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}

func mapOne(t *testing.T, m *Mapper, name string) event.Event {
	t.Helper()
	evs := m.Map(loadFixture(t, name))
	if len(evs) != 1 {
		t.Fatalf("%s: got %d events", name, len(evs))
	}
	return evs[0]
}

func TestMapFixtures(t *testing.T) {
	type want struct {
		kind   string
		prio   event.Priority
		fields map[string]any
	}
	cases := map[string]want{
		"sysmon1": {KindProcessStart, event.PriorityNormal, map[string]any{
			"exe": `C:\Windows\System32\cmd.exe`, "comm": "cmd.exe", "cmdline": "cmd.exe /c whoami & net user",
			"pid": 4242, "ppid": 3000, "pexe": `C:\Windows\System32\inetsrv\w3wp.exe`, "pcomm": "w3wp.exe",
			"user": `CCDC\svc_web`, "sha256": "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb",
			"md5": "0123456789abcdef0123456789abcdef", "imphash": "fedcba9876543210fedcba9876543210",
			"original_file_name": "Cmd.Exe", "sensor": "sysmon", "host": "DC01.ccdc.local",
			"integrity_level": "High", "event_id": 1, "process_guid": "{a1b2c3d4-0000-0000-0000-000000001234}"}},
		"sysmon3": {KindNetConnect, event.PriorityNormal, map[string]any{
			"proto": "tcp", "src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "dst_port": 4444, "src_port": 49152,
			"initiated": true, "dir": "out", "exe": `C:\Windows\System32\cmd.exe`}},
		"sysmon6":  {KindSecEvent, event.PriorityHigh, map[string]any{"category": "driver_load", "signed": false, "sha256": "aa11", "path": `C:\Users\Public\evil.sys`}},
		"sysmon7":  {KindSecEvent, event.PriorityBulk, map[string]any{"category": "image_load", "image_loaded": `C:\Users\Public\x.dll`, "signed": false}},
		"sysmon8":  {KindSecEvent, event.PriorityHigh, map[string]any{"category": "remote_thread", "source_exe": `C:\Users\x\inj.exe`, "target_exe": `C:\Windows\System32\notepad.exe`}},
		"sysmon10": {KindSecEvent, event.PriorityHigh, map[string]any{"category": "process_access", "target_lsass": true, "granted_access": "0x1010", "source_process_guid": "{s}"}},
		"sysmon11": {KindFileChange, event.PriorityNormal, map[string]any{"path": `C:\inetpub\wwwroot\shell.aspx`, "op": "create", "actor_exe": `C:\Windows\System32\inetsrv\w3wp.exe`}},
		"sysmon13": {KindSecEvent, event.PriorityHigh, map[string]any{"category": "registry", "op": "set_value", "event_id": 13,
			"target_object": `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater`, "details": `C:\Users\Public\u.exe`}},
		"sysmon22": {KindSecEvent, event.PriorityBulk, map[string]any{"category": "dns_query", "query": "evil.example.com"}},
		"sysmon25": {KindSecEvent, event.PriorityHigh, map[string]any{"category": "process_tampering", "tamper_type": "Image is replaced"}},
		"sysmon16": {KindSecEvent, event.PriorityCritical, map[string]any{"category": "sysmon_config", "config_hash": "sha256=abcdef0123"}},
		"sysmon4":  {KindSecEvent, event.PriorityCritical, map[string]any{"category": "sysmon_state", "state": "Stopped"}},
		"sec4624": {KindAuthSuccess, event.PriorityHigh, map[string]any{
			"account": "Administrator", "domain": "CCDC", "source": "198.51.100.7", "method": "NTLM", "service": "windows",
			"logon_type": 3, "logon_type_name": "network", "workstation": "KALI", "machine_account": false, "host": "DC01.ccdc.local"}},
		"sec4624_dcmachine": {KindAuthSuccess, event.PriorityHigh, map[string]any{"account": "DC01$", "machine_account": true, "logon_type": 3, "source": "10.0.0.99"}},
		"sec4625": {KindAuthFail, event.PriorityHigh, map[string]any{"account": "admin", "source": "198.51.100.7", "logon_type": 10,
			"status": "0xc000006d", "sub_status": "0xc000006a", "workstation": "ATTACKER"}},
		"sec4688": {KindProcessStart, event.PriorityNormal, map[string]any{
			"exe": `C:\Windows\System32\whoami.exe`, "comm": "whoami.exe", "cmdline": "whoami /all", "pid": 0x1a4c, "ppid": 0xbb8,
			"pexe": `C:\Windows\System32\cmd.exe`, "pcomm": "cmd.exe", "user": `CCDC\bob`, "sensor": "4688"}},
		"sec4697": {KindSecEvent, event.PriorityHigh, map[string]any{"category": "service_install", "service_name": "PSEXESVC", "image_path": `%SystemRoot%\PSEXESVC.exe`, "event_id": 4697}},
		"sec4698": {KindSecEvent, event.PriorityHigh, map[string]any{"category": "scheduled_task", "op": "created", "task_command": "powershell.exe", "task_arguments": "-enc SQBFAFgA", "task_name": `\Microsoft\Windows\Updater`}},
		"sec4720": {KindSecEvent, event.PriorityHigh, map[string]any{"category": "account_change", "op": "created", "account": "hacker$", "subject_account": `CCDC\Administrator`}},
		"sec4728": {KindSecEvent, event.PriorityHigh, map[string]any{"category": "group_change", "op": "member_added", "group_name": "Domain Admins", "member_sid": "S-1-5-21-1-2-3-2000"}},
		"sec4732": {KindSecEvent, event.PriorityHigh, map[string]any{"category": "group_change", "group_name": "Administrators", "event_id": 4732}},
		"sec4742_zerologon": {KindSecEvent, event.PriorityHigh, map[string]any{"category": "computer_account_change", "anonymous_subject": true,
			"zerologon_signal": "4742_anonymous", "account": "DC01$", "subject_user_name": "ANONYMOUS LOGON"}},
		"sec4768": {KindSecEvent, event.PriorityHigh, map[string]any{"category": "kerberos", "rc4_ticket": true, "source": "10.0.0.7", "service_name": "krbtgt"}},
		"sec4769": {KindSecEvent, event.PriorityHigh, map[string]any{"category": "kerberos", "rc4_ticket": false, "service_name": "MSSQLSvc"}},
		"sec4776": {KindSecEvent, event.PriorityHigh, map[string]any{"category": "ntlm_validation", "status": "0xc000006a", "workstation": "KALI", "account": "bob"}},
		"sec5136": {KindSecEvent, event.PriorityHigh, map[string]any{"category": "ad_object_change", "op": "modified", "operation": "value_added",
			"attribute": "gPCMachineExtensionNames", "object_class": "groupPolicyContainer"}},
		"sec5137": {KindSecEvent, event.PriorityHigh, map[string]any{"category": "ad_object_change", "op": "created", "object_class": "groupPolicyContainer"}},
		"sec4670": {KindSecEvent, event.PriorityHigh, map[string]any{"category": "permission_change", "object_name": `C:\Windows\NTDS\ntds.dit`, "new_sd": "D:(A;;FA;;;WD)"}},
		"sec4662": {KindSecEvent, event.PriorityHigh, map[string]any{"category": "ad_access", "replication_rights": true}},
		"sec1102": {KindSecEvent, event.PriorityCritical, map[string]any{"category": "log_cleared", "log": "Security", "subject_account": `CCDC\Administrator`}},
		"sys7045": {KindSecEvent, event.PriorityHigh, map[string]any{"category": "service_install", "service_name": "evilsvc",
			"image_path": "%COMSPEC% /c powershell -nop -w hidden", "service_account": "LocalSystem"}},
		"sys104": {KindSecEvent, event.PriorityCritical, map[string]any{"category": "log_cleared", "log": "Security", "subject_account": `CCDC\Administrator`}},
		"sys5829": {KindSecEvent, event.PriorityCritical, map[string]any{"category": "netlogon_secure_channel", "zerologon_signal": "5829_vulnerable_allowed",
			"machine_name": "WKS01$", "data_4": "10.0.0.99"}},
		"def1116": {KindSecEvent, event.PriorityHigh, map[string]any{"category": "defender_detection", "threat_name": "HackTool:Win32/Mimikatz.D"}},
		"def5001": {KindSecEvent, event.PriorityCritical, map[string]any{"category": "defender_tamper", "tamper": "realtime_disabled"}},
		"def5007": {KindSecEvent, event.PriorityCritical, map[string]any{"category": "defender_tamper", "defender_exclusion": true}},
		"ps4104":  {KindSecEvent, event.PriorityHigh, map[string]any{"category": "script_block", "event_id": 4104}},
		"ts106":   {KindSecEvent, event.PriorityHigh, map[string]any{"category": "scheduled_task", "op": "created", "task_name": `\Updater`, "task_user": `CCDC\bob`}},
		"wmi5861": {KindSecEvent, event.PriorityHigh, map[string]any{"category": "wmi_subscription", "namespace": "//./root/subscription", "possible_cause": "Permanent"}},
	}
	m := &Mapper{}
	for name, w := range cases {
		t.Run(name, func(t *testing.T) {
			e := mapOne(t, m, name)
			if e.Kind != w.kind {
				t.Errorf("kind = %s want %s", e.Kind, w.kind)
			}
			if e.Priority != w.prio {
				t.Errorf("priority = %d want %d", e.Priority, w.prio)
			}
			if e.Time.IsZero() || e.Time.Year() != 2026 {
				t.Errorf("time = %v", e.Time)
			}
			for k, v := range w.fields {
				if got := e.Fields[k]; got != v {
					t.Errorf("field %s = %#v want %#v", k, got, v)
				}
			}
			for _, k := range []string{"channel", "provider", "event_id", "record_id", "host"} {
				if _, ok := e.Fields[k]; !ok {
					t.Errorf("missing common field %s", k)
				}
			}
		})
	}
}

func TestEveryFixtureIsCovered(t *testing.T) {
	// Guards against adding a fixture without a mapping expectation.
	ents, _ := os.ReadDir("testdata")
	if len(ents) < 38 {
		t.Fatalf("only %d fixtures", len(ents))
	}
}

func TestScriptBlockTextSurvives(t *testing.T) {
	e := mapOne(t, &Mapper{}, "ps4104")
	if s, _ := e.Fields["script_block_text"].(string); s == "" || s[:3] != "IEX" {
		t.Fatalf("script_block_text = %q", s)
	}
}

func TestSigmaStyleRawFieldsKept(t *testing.T) {
	e := mapOne(t, &Mapper{}, "sysmon1")
	for _, k := range []string{"image", "command_line", "parent_image", "parent_command_line", "current_directory", "logon_id", "hashes"} {
		if _, ok := e.Fields[k]; !ok {
			t.Errorf("raw snake_case field %s missing", k)
		}
	}
}

func TestAuthDashIPBecomesEmpty(t *testing.T) {
	r := loadFixture(t, "sec4625")
	r.Data["ip_address"] = "-"
	e := (&Mapper{}).Map(r)[0]
	if e.Fields["source"] != "" {
		t.Fatalf("source = %v", e.Fields["source"])
	}
}

func TestUse4688Suppression(t *testing.T) {
	on := true
	m := &Mapper{Use4688: func() bool { return on }}
	if len(m.Map(loadFixture(t, "sec4688"))) != 1 {
		t.Fatal("4688 should map while the fallback is on")
	}
	on = false
	if len(m.Map(loadFixture(t, "sec4688"))) != 0 {
		t.Fatal("4688 must be suppressed while Sysmon feeds process events")
	}
	if len(m.Map(loadFixture(t, "sysmon1"))) != 1 {
		t.Fatal("Sysmon 1 unaffected")
	}
}

func TestDropExeSelfExclusion(t *testing.T) {
	m := &Mapper{DropExe: []string{`c:\windows\system32\CMD.EXE`}}
	if len(m.Map(loadFixture(t, "sysmon1"))) != 0 || len(m.Map(loadFixture(t, "sysmon3"))) != 0 {
		t.Fatal("agent's own process and network events should be dropped")
	}
	if len(m.Map(loadFixture(t, "sec4688"))) != 1 {
		t.Fatal("other executables must pass")
	}
}

func TestHostOverride(t *testing.T) {
	e := (&Mapper{Host: "box"}).Map(loadFixture(t, "sec4624"))[0]
	if e.Fields["host"] != "box" {
		t.Fatalf("host = %v", e.Fields["host"])
	}
}

func TestEventsHashChainable(t *testing.T) {
	// Mapped events must encode canonically (spool requirement): no
	// unsupported value types in Fields.
	for _, n := range []string{"sysmon1", "sec4624", "sec4698", "sys5829"} {
		e := mapOne(t, &Mapper{}, n)
		e.Agent = "a"
		if err := e.Seal(0, event.GenesisHash); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
	}
}
