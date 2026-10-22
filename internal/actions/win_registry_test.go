package actions

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const lsaKeyT = `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`

func TestParseRegValue(t *testing.T) {
	for _, tc := range []struct {
		typ, in string
		want    RegValue
		bad     bool
	}{
		{"dword", "1", RegValue{Type: "dword", Num: 1}, false},
		{"dword", "0x10", RegValue{Type: "dword", Num: 16}, false},
		{"dword", "4294967296", RegValue{}, true},
		{"qword", "4294967296", RegValue{Type: "qword", Num: 4294967296}, false},
		{"multi_sz", "a\nb\n", RegValue{Type: "multi_sz", Multi: []string{"a", "b"}}, false},
		{"binary", "de ad,be:ef", RegValue{Type: "binary", Bin: []byte{0xde, 0xad, 0xbe, 0xef}}, false},
		{"binary", "zz", RegValue{}, true},
		{"sz", "a\x00b", RegValue{}, true},
		{"nope", "1", RegValue{}, true},
	} {
		got, err := ParseRegValue(tc.typ, tc.in)
		if tc.bad != (err != nil) {
			t.Fatalf("%v: err=%v", tc, err)
		}
		if !tc.bad && !got.equal(tc.want) {
			t.Fatalf("%v: got %+v", tc, got)
		}
	}
}

func TestNormRegKey(t *testing.T) {
	for in, want := range map[string]string{
		`HKLM\SOFTWARE\X`:                `HKLM\SOFTWARE\X`,
		`HKEY_LOCAL_MACHINE\\SOFTWARE/X`: `HKLM\SOFTWARE\X`,
		`HKLM:\SOFTWARE\X\`:              `HKLM\SOFTWARE\X`,
	} {
		got, err := normRegKey(in)
		if err != nil || got != want {
			t.Fatalf("%q -> %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{`HKCU\Software\X`, `HKLM`, `HKLM\A\..\B`, ``} {
		if _, err := normRegKey(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestRegistrySetDryRunApplyIdempotentRollback(t *testing.T) {
	f := newWinFixture(t)
	key := `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`
	f.reg.put(key, "Foo", RegValue{Type: "dword", Num: 0})
	p := map[string]any{"key": key, "name": "Foo", "type": "dword", "value": "7"}

	o := f.ok(t, "registry.set", p, func(r *Request) { r.DryRun = true })
	if !strings.Contains(o.Plan.Diff, "dword 0 -> dword 7") {
		t.Fatalf("diff %q", o.Plan.Diff)
	}
	if n, _ := f.reg.dword(key, "Foo"); n != 0 {
		t.Fatal("dry-run changed the registry")
	}

	o = f.ok(t, "registry.set", p, func(r *Request) { r.Deadman = 150 * time.Millisecond })
	if n, _ := f.reg.dword(key, "Foo"); n != 7 || o.DeadmanID == "" {
		t.Fatalf("not applied or no dead-man: %d %q", n, o.DeadmanID)
	}
	// dead-man fires: the prior value comes back
	waitFor(t, "registry rollback", func() bool { n, _ := f.reg.dword(key, "Foo"); return n == 0 })

	// idempotent
	f.ok(t, "registry.set", p)
	o = f.ok(t, "registry.set", p)
	if o.Changed || !o.Plan.Done {
		t.Fatalf("second run should be a no-op: %+v", o)
	}
}

func TestRegistrySetRollbackRemovesNewValue(t *testing.T) {
	f := newWinFixture(t)
	key := `HKLM\SOFTWARE\Phylax\Test`
	o := f.ok(t, "registry.set", map[string]any{"key": key, "name": "New", "type": "sz", "value": "x"},
		func(r *Request) { r.Deadman = time.Minute })
	if _, ok := f.reg.dword(key, "New"); !ok {
		t.Fatal("value not created")
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.reg.val(key, "New"); ok {
		t.Fatal("rollback left the new value behind")
	}
}

func TestRegistryDelete(t *testing.T) {
	f := newWinFixture(t)
	key := `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	f.reg.put(key, "evil", RegValue{Type: "sz", Str: `C:\x.exe`})
	// deleting a planted Run value is allowed (clean-up) ...
	o := f.ok(t, "registry.delete", map[string]any{"key": key, "name": "evil"}, func(r *Request) { r.Deadman = time.Minute })
	if _, ok := f.reg.val(key, "evil"); ok {
		t.Fatal("not deleted")
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if v, ok := f.reg.val(key, "evil"); !ok || v.Str != `C:\x.exe` {
		t.Fatal("rollback did not restore the deleted value")
	}
	// ... but writing one is not.
	_, err := f.run(t, "registry.set", map[string]any{"key": key, "name": "ok", "type": "sz", "value": "x"})
	if err == nil || !strings.Contains(err.Error(), "autostart") {
		t.Fatalf("Run key write accepted: %v", err)
	}
}

func TestRegistryScoringRefusals(t *testing.T) {
	f := newWinFixture(t)
	cases := []struct {
		name string
		p    map[string]any
	}{
		{"lm level below 3", map[string]any{"key": lsaKeyT, "name": "LmCompatibilityLevel", "type": "dword", "value": "1"}},
		{"restrict receiving ntlm", map[string]any{"key": lsaKeyT + `\MSV1_0`, "name": "RestrictReceivingNTLMTraffic", "type": "dword", "value": "2"}},
		{"ntlm min sec integrity", map[string]any{"key": lsaKeyT + `\MSV1_0`, "name": "NtlmMinServerSec", "type": "dword", "value": "0x20080030"}},
		{"lockout", map[string]any{"key": `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`, "name": "AccountLockoutThreshold", "type": "dword", "value": "5"}},
		{"winrm unencrypted off", map[string]any{"key": `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service`, "name": "AllowUnencrypted", "type": "dword", "value": "0"}},
		{"smb encryption", map[string]any{"key": lanmanServerParams, "name": "EncryptData", "type": "dword", "value": "1"}},
		{"mssql force encryption", map[string]any{"key": `HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQLServer\SuperSocketNetLib`, "name": "ForceEncryption", "type": "dword", "value": "1"}},
		{"sam hive", map[string]any{"key": `HKLM\SAM\SAM`, "name": "x", "type": "dword", "value": "1"}},
	}
	for _, tc := range cases {
		if _, err := f.run(t, "registry.set", tc.p); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
	if f.reg.nlog() != 0 {
		t.Fatalf("registry was written: %v", f.reg.log)
	}
	// LmCompatibilityLevel 5 is fine.
	f.ok(t, "registry.set", map[string]any{"key": lsaKeyT, "name": "LmCompatibilityLevel", "type": "dword", "value": "5"})
}

func TestRegistryImpliedServiceTouchRefusedWhenScored(t *testing.T) {
	f := newWinFixture(t)
	p := map[string]any{"key": `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`, "name": "fDenyTSConnections", "type": "dword", "value": "1"}
	f.env.Guard = StaticGuard{Services: []string{"TermService"}}
	if _, err := f.run(t, "registry.set", p); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("RDP off accepted on a scored host: %v", err)
	}
	// service start=4 under Services\<name> is the same thing
	f.env.Guard = StaticGuard{Services: []string{"LanmanServer"}}
	p2 := map[string]any{"key": `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer`, "name": "Start", "type": "dword", "value": "4"}
	if _, err := f.run(t, "registry.set", p2); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("SMB server disable accepted: %v", err)
	}
	// unscored host: allowed
	f.env.Guard = StaticGuard{Services: []string{"WinRM"}}
	f.ok(t, "registry.set", p)
}

func TestRegistryUnsupportedWithoutBackend(t *testing.T) {
	f := newFixture(t) // no Win backends
	_, err := f.run(t, "registry.set", map[string]any{"key": `HKLM\SOFTWARE\X`, "name": "a", "type": "dword", "value": "1"})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("want ErrUnsupported, got %v", err)
	}
}

func TestSafeModeBlocksWindowsActions(t *testing.T) {
	f := newWinFixture(t)
	f.env.Safe, _ = NewSafeMode("")
	_ = f.env.Safe.Set(true)
	_, err := f.run(t, "registry.set", map[string]any{"key": `HKLM\SOFTWARE\X`, "name": "a", "type": "dword", "value": "1"})
	if !errors.Is(err, ErrSafeMode) {
		t.Fatalf("got %v", err)
	}
}
