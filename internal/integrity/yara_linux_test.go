//go:build linux

package integrity

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestScanProcessMemory(t *testing.T) {
	m, _ := ParseRules(`rule Mem { strings: $a = "PHYLAX-MEM-CANARY-7731" condition: $a }`)
	// Built at run time so the heap, not just rodata, holds the canary.
	canary := []byte(strings.Join([]string{"PHYLAX", "MEM", "CANARY", "7731"}, "-"))
	buf := make([]byte, 1<<16)
	copy(buf[1000:], canary)
	ms, err := (GoScanner{M: m}).ScanProcess(context.Background(), os.Getpid())
	if err != nil {
		t.Skipf("cannot read own /proc/self/mem: %v", err)
	}
	if len(ms) != 1 || ms[0].Rule != "Mem" {
		t.Fatalf("canary not found in process memory: %+v", ms)
	}
	_ = buf[1000]
}
