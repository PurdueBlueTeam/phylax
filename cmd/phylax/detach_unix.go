//go:build !windows

package main

import "syscall"

// detachAttr puts the swap helper in its own session, so stopping the agent's
// service does not kill the helper that is about to restart it.
func detachAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }
