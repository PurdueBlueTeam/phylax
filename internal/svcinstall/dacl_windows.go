//go:build windows

package svcinstall

import (
	"errors"

	"golang.org/x/sys/windows"
)

// applyServiceSDDL sets the protected DACL and its audit SACL on a service.
func applyServiceSDDL(name string) error { return setServiceSDDL(name, ServiceSDDL) }

// resetServiceDACL restores the SCM default DACL so the service can be
// stopped and deleted: `phylax agent uninstall` from an elevated console is
// the break-glass companion to the protected DACL.
func resetServiceDACL(name string) error { return setServiceSDDL(name, defaultServiceSDDL) }

// setServiceSDDL replaces a service's DACL (and SACL, when the SDDL has one).
func setServiceSDDL(name, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	var sacl *windows.ACL
	if s, _, err := sd.SACL(); err == nil {
		sacl = s // the audit ACEs are optional
		info |= windows.SACL_SECURITY_INFORMATION
		if err := enableSecurityPrivilege(); err != nil {
			return err
		}
	} else if !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return err
	}
	return windows.SetNamedSecurityInfo(name, windows.SE_SERVICE, info, nil, nil, dacl, sacl)
}

// enableSecurityPrivilege turns on SeSecurityPrivilege in this process's token:
// an elevated administrator holds it disabled, and writing a SACL needs it on.
func enableSecurityPrivilege() error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeSecurityPrivilege"), &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	return windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
}
