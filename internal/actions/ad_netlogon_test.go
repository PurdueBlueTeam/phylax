package actions

import (
	"strings"
	"testing"
	"time"
)

func TestZerologonPatched(t *testing.T) {
	for _, tc := range []struct {
		build, ubr int
		want       string
	}{
		{17763, 1396, "no"}, {17763, 1397, "yes"}, {17763, 3650, "yes"},
		{14393, 3929, "no"}, {14393, 3930, "yes"},
		{20348, 1, "yes"}, {26100, 0, "yes"},
		{9600, 18000, "unknown"},
	} {
		if got := zerologonPatched(tc.build, tc.ubr); got != tc.want {
			t.Errorf("%d.%d: %s want %s", tc.build, tc.ubr, got, tc.want)
		}
	}
}

func TestZerologonCheckReportsAndNeverFails(t *testing.T) {
	f := newWinFixture(t)
	f.setOS("17763", 1000, "LanmanNT") // unpatched DC
	f.evts.n, f.evts.latest = 3, fixedNow
	o := f.ok(t, "ad.zerologon_check", map[string]any{})
	for k, want := range map[string]string{"patched": "no", "dc": "true", "full_secure_channel_protection": "absent", "event_5829": "3"} {
		if o.Output[k] != want {
			t.Errorf("%s = %q, want %q", k, o.Output[k], want)
		}
	}
	if !strings.HasPrefix(o.Output["verdict"], "VULNERABLE") {
		t.Fatalf("verdict %q", o.Output["verdict"])
	}
	// patched and enforced
	f.setOS("17763", 3650, "LanmanNT")
	f.reg.put(netlogonParams, "FullSecureChannelProtection", RegValue{Type: "dword", Num: 1})
	o = f.ok(t, "ad.zerologon_check", map[string]any{})
	if !strings.HasPrefix(o.Output["verdict"], "ok") {
		t.Fatalf("verdict %q", o.Output["verdict"])
	}
	// allow-list is called out
	f.reg.put(netlogonParams, "vulnerablechannelallowlist", RegValue{Type: "sz", Str: "O:BAG:BAD:(A;;RC;;;S-1-1-0)"})
	o = f.ok(t, "ad.zerologon_check", map[string]any{})
	if !strings.HasPrefix(o.Output["verdict"], "WEAK") {
		t.Fatalf("verdict %q", o.Output["verdict"])
	}
}

func TestSecureChannelEnforceWithRollback(t *testing.T) {
	f := newWinFixture(t)
	f.setOS("17763", 1000, "LanmanNT")
	f.evts.n, f.evts.latest = 2, fixedNow
	o := f.ok(t, "ad.secure_channel", map[string]any{"enforce": true}, func(r *Request) { r.DryRun = true })
	if !strings.Contains(o.Plan.Diff, "FullSecureChannelProtection = dword 1") {
		t.Fatalf("diff %q", o.Plan.Diff)
	}
	notes := strings.Join(o.Plan.Notes, "\n")
	if !strings.Contains(notes, "below the August 2020 update") || !strings.Contains(notes, "5829") {
		t.Fatalf("notes %q", notes)
	}
	o = f.ok(t, "ad.secure_channel", map[string]any{"enforce": true}) // lockout: default dead-man
	if o.DeadmanID == "" {
		t.Fatal("no dead-man for a lockout-class action")
	}
	if n, _ := f.reg.dword(netlogonParams, "FullSecureChannelProtection"); n != 1 {
		t.Fatal("not enforced")
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.reg.val(netlogonParams, "FullSecureChannelProtection"); ok {
		t.Fatal("rollback left the key behind")
	}
}

func TestSecureChannelReportOnlyAndNonDC(t *testing.T) {
	f := newWinFixture(t)
	f.setOS("17763", 3650, "LanmanNT")
	o := f.ok(t, "ad.secure_channel", map[string]any{"enforce": true, "report_only": true})
	if o.Changed || f.reg.nlog() != 0 {
		t.Fatal("report_only changed something")
	}
	if !strings.Contains(strings.Join(o.Plan.Notes, "\n"), "would change") {
		t.Fatalf("notes %v", o.Plan.Notes)
	}
	f.setOS("17763", 3650, "ServerNT")
	if _, err := f.run(t, "ad.secure_channel", map[string]any{"enforce": true}); err == nil || !strings.Contains(err.Error(), "not a domain controller") {
		t.Fatalf("member server accepted: %v", err)
	}
}

func TestRPCRange(t *testing.T) {
	f := newWinFixture(t)
	f.setOS("20348", 1, "LanmanNT")
	for _, bad := range []string{"5000", "5000-5050", "80-9000", "6000-5000", "5000-70000", "a-b"} {
		if _, err := f.run(t, "ad.dc.rpc_range", map[string]any{"range": bad}); err == nil {
			t.Errorf("range %q accepted", bad)
		}
	}
	o := f.ok(t, "ad.dc.rpc_range", map[string]any{"range": "5000:5200"}, func(r *Request) { r.Deadman = time.Minute })
	v, _ := f.reg.val(rpcInternetKey, "Ports")
	if len(v.Multi) != 1 || v.Multi[0] != "5000-5200" {
		t.Fatalf("Ports = %+v", v)
	}
	if s, _ := f.reg.val(rpcInternetKey, "UseInternetPorts"); s.Str != "Y" {
		t.Fatal("UseInternetPorts not Y")
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.reg.val(rpcInternetKey, "Ports"); ok {
		t.Fatal("rollback left Ports")
	}
	f.setOS("20348", 1, "WinNT")
	if _, err := f.run(t, "ad.dc.rpc_range", map[string]any{"range": "5000-5200"}); err == nil {
		t.Fatal("rpc range applied on a non-DC")
	}
}

func TestSMB1(t *testing.T) {
	f := newWinFixture(t)
	f.reg.put(lanmanServerParams, "SMB1", RegValue{Type: "dword", Num: 1})
	f.reg.put(lanmanWorkstation, "DependOnService", RegValue{Type: "multi_sz", Multi: []string{"Bowser", "MRxSmb10", "MRxSmb20", "NSI"}})
	o := f.ok(t, "windows.smb1", map[string]any{"enabled": false}, func(r *Request) { r.Deadman = time.Minute })
	if n, _ := f.reg.dword(lanmanServerParams, "SMB1"); n != 0 {
		t.Fatal("server SMB1 not disabled")
	}
	if n, _ := f.reg.dword(mrxsmb10Key, "Start"); n != 4 {
		t.Fatal("client driver not disabled")
	}
	if v, _ := f.reg.val(lanmanWorkstation, "DependOnService"); len(v.Multi) != 3 {
		t.Fatalf("dependency not trimmed: %+v", v)
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if v, _ := f.reg.val(lanmanWorkstation, "DependOnService"); len(v.Multi) != 4 {
		t.Fatalf("rollback did not restore the dependency list: %+v", v)
	}
	if n, _ := f.reg.dword(lanmanServerParams, "SMB1"); n != 1 {
		t.Fatal("rollback did not restore SMB1")
	}
	// The scorer's SMB service itself is not what is being disabled.
	f.env.Guard = StaticGuard{Services: []string{"LanmanServer"}}
	f.ok(t, "windows.smb1", map[string]any{"enabled": false})
}
