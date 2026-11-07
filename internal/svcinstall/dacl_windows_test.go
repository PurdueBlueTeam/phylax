//go:build windows

package svcinstall

import (
	"context"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestServiceSDDLParses is the Windows half of the shape test: the SDDL the
// installer writes must be one the security APIs accept.
func TestServiceSDDLParses(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString(ServiceSDDL)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sd.DACL(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sd.SACL(); err != nil {
		t.Fatal(err)
	}
	for _, sddl := range []string{ServiceSDDL, defaultServiceSDDL} {
		if _, err := windows.SecurityDescriptorFromString(sddl); err != nil {
			t.Errorf("%q does not parse: %v", sddl, err)
		}
	}
}

// TestServiceSDDLDeniesStop installs a throw-away service with the protected
// DACL and reads the DACL back from the SCM: interactive, service and batch
// logons are denied stop, reconfiguration, pause and delete but may start and
// query, and administrators keep WRITE_DAC (the `sc sdset` break-glass, which
// the cleanup's Uninstall uses). The token-level check (a non-SYSTEM process
// really cannot open with SERVICE_STOP) needs an interactive logon and is
// exercised in the lab.
func TestServiceSDDLDeniesStop(t *testing.T) {
	if os.Getenv("PHYLAX_PRIVILEGED_TESTS") != "1" {
		t.Skip("installs a real Windows service; set PHYLAX_PRIVILEGED_TESTS=1 (as Administrator) to run")
	}
	name := DeriveNames([]byte(t.Name())).Service
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := New().Install(context.Background(), Spec{Name: name, Binary: exe, Args: []string{"version"}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := New().Uninstall(context.Background(), name); err != nil {
			t.Errorf("break-glass uninstall failed: %v", err)
		}
	})
	sd, err := windows.GetNamedSecurityInfo(name, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	type principal struct {
		label string
		sid   *windows.SID
	}
	var who []principal
	for label, kind := range map[string]windows.WELL_KNOWN_SID_TYPE{
		"interactive":    windows.WinInteractiveSid,
		"service":        windows.WinServiceSid,
		"users":          windows.WinBuiltinUsersSid,
		"administrators": windows.WinBuiltinAdministratorsSid,
	} {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			t.Fatal(err)
		}
		who = append(who, principal{label, sid})
	}
	deny, allow := map[string]windows.ACCESS_MASK{}, map[string]windows.ACCESS_MASK{}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			t.Fatal(err)
		}
		label := ""
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		for _, p := range who {
			if p.sid.Equals(aceSID) {
				label = p.label
				break
			}
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			deny[label] |= ace.Mask
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			allow[label] |= ace.Mask
		}
	}
	blocked := windows.ACCESS_MASK(windows.SERVICE_STOP | windows.SERVICE_CHANGE_CONFIG | windows.SERVICE_PAUSE_CONTINUE | windows.DELETE)
	for _, label := range []string{"administrators", "interactive", "service", "users"} {
		if deny[label]&blocked != blocked {
			t.Errorf("%s is not denied stop/reconfigure/pause/delete: mask %#x", label, deny[label])
		}
		if allow[label]&windows.SERVICE_START == 0 || allow[label]&windows.SERVICE_QUERY_STATUS == 0 {
			t.Errorf("%s may not start and query: mask %#x", label, allow[label])
		}
	}
	if allow["administrators"]&windows.WRITE_DAC == 0 {
		t.Errorf("administrators lost the break-glass WRITE_DAC: mask %#x", allow["administrators"])
	}
}
