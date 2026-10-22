package actions

import (
	"strings"
	"testing"
)

func TestWinFamilyRegisteredInCore(t *testing.T) {
	reg := Core()
	want := []string{"registry.set", "registry.delete", "windows.smb1", "windows.hotfix", "agentopt.set", "win.service.config",
		"win.audit_policy.set", "win.defender", "win.defender.audit", "win.firewall", "ad.secure_channel", "ad.zerologon_check",
		"ad.dc.rpc_range", "ad.account.audit_groups", "ad.account.admincount_sweep", "ad.account.disable",
		"ad.account.reset_password", "ad.account.group_remove", "ad.account.krbtgt_reset", "palo.permitted_ips", "palo.commit",
		"palo.apply", "palo.snapshot", "vyos.snapshot", "vyos.apply", "splunk.rest", "splunk.password", "splunk.hec_setup",
		"splunk.sidecar_off"}
	for _, n := range want {
		a, err := reg.Get(n)
		if err != nil {
			t.Errorf("%s not registered", n)
			continue
		}
		s := a.Spec()
		if s.Doc == "" {
			t.Errorf("%s has no doc", n)
		}
		switch s.Risk {
		case RiskNone, RiskService, RiskLockout, RiskDestructive:
		default:
			t.Errorf("%s risk %q", n, s.Risk)
		}
		if s.Risk == RiskNone && !s.ReadOnly {
			t.Errorf("%s is risk none but not read-only", n)
		}
	}
}

func TestRiskClassesOfDangerousActions(t *testing.T) {
	reg := Core()
	for n, want := range map[string]Risk{
		"ad.account.krbtgt_reset": RiskDestructive, "ad.secure_channel": RiskLockout, "palo.permitted_ips": RiskLockout,
		"ad.account.disable": RiskLockout, "win.firewall": RiskLockout, "vyos.apply": RiskLockout,
		"windows.hotfix": RiskLockout, "splunk.password": RiskLockout, "registry.set": RiskService,
	} {
		a, _ := reg.Get(n)
		if a.Spec().Risk != want {
			t.Errorf("%s risk %s, want %s", n, a.Spec().Risk, want)
		}
	}
}

func TestSecretsAreRedactedInParams(t *testing.T) {
	reg := Core()
	for _, n := range []string{"splunk.password", "ad.account.reset_password"} {
		a, _ := reg.Get(n)
		p, err := a.Spec().Validate(map[string]any{"user": "u", "password": "hunter2-hunter2"})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(p.Redacted(), "hunter2") {
			t.Errorf("%s leaks the password in Redacted()", n)
		}
	}
}

func TestResolveWindowsPathUnderRoot(t *testing.T) {
	e := &Env{Root: "/tmp/root"}
	if got := e.Resolve(`C:\Program Files\x\y.conf`); got != "/tmp/root/Program Files/x/y.conf" {
		t.Fatalf("got %q", got)
	}
}
