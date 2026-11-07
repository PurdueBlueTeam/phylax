//go:build windows

package main

import (
	"testing"

	"golang.org/x/sys/windows"
)

// TestDetachAttrWindows proves the swap helper is not a child the service
// manager kills: a detached process in its own group, and breaking away from
// the agent's Job Object when there is one.
func TestDetachAttrWindows(t *testing.T) {
	flags := detachAttr().CreationFlags
	for _, want := range []uint32{windows.DETACHED_PROCESS, windows.CREATE_NEW_PROCESS_GROUP, windows.CREATE_BREAKAWAY_FROM_JOB} {
		if flags&want == 0 {
			t.Fatalf("creation flags %#x lack %#x", flags, want)
		}
	}
	if fallback := detachAttrFallback().CreationFlags; fallback&windows.CREATE_BREAKAWAY_FROM_JOB != 0 {
		t.Fatalf("fallback flags %#x still ask to break away", fallback)
	}
}
