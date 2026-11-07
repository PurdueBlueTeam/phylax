//go:build windows

package main

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// detachAttr starts the swap helper detached from the service, so stopping the
// service does not kill the helper that is about to restart it.
func detachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP}
}
