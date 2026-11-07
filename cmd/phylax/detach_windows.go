//go:build windows

package main

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// detachAttr starts the swap helper detached from the service, so stopping the
// service does not kill the helper that is about to restart it: its own process
// group, no console inherited from the service, and out of the agent's Job
// Object when it is in one that kills its children.
func detachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_BREAKAWAY_FROM_JOB}
}

// detachAttrFallback is detachAttr without the breakaway request: a Job Object
// that does not allow breakaway refuses CreateProcess otherwise.
func detachAttrFallback() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP}
}
