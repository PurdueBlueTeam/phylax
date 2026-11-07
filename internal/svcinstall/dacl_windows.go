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
	} else if !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return err
	}
	return windows.SetNamedSecurityInfo(name, windows.SE_SERVICE, info, nil, nil, dacl, sacl)
}
