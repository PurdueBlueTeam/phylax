package action

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestSysctlPath(t *testing.T) {
	if got := sysctlPath("net.ipv4.ip_forward"); got != "/proc/sys/net/ipv4/ip_forward" {
		t.Fatalf("sysctlPath = %q", got)
	}
}

func TestModprobeManagedLine(t *testing.T) {
	for _, l := range []string{
		"# phylax module.block: cdc_ether",
		"blacklist cdc_ether",
		"install cdc_ether /bin/false",
	} {
		if !modprobeManagedLine(l) {
			t.Fatalf("should be managed: %q", l)
		}
	}
	for _, l := range []string{"# a comment", "options usbcore autosuspend=1", ""} {
		if modprobeManagedLine(l) {
			t.Fatalf("should not be managed: %q", l)
		}
	}
}

func TestModprobeHasModule(t *testing.T) {
	c := "blacklist cdc_ether\ninstall cdc_ether /bin/false\nblacklist cdc_ncm\n"
	if !modprobeHasModule(c, "cdc_ether") {
		t.Fatal("should find cdc_ether")
	}
	if modprobeHasModule(c, "cdc_mbim") {
		t.Fatal("should not find cdc_mbim")
	}
}

func TestHostsManagedBlock(t *testing.T) {
	entries := []string{"127.0.0.1 evil.example.com", "127.0.0.1 evil2.example.com"}
	block := hostsManagedBlock(entries)
	if !strings.Contains(block, hostsMarker) || !strings.Contains(block, hostsMarkerEnd) {
		t.Fatalf("block missing markers: %q", block)
	}
	got := hostsCurrentEntries("foo\n" + block + "\nbar\n")
	if len(got) != 2 || !sameStringSet(got, entries) {
		t.Fatalf("entries = %v", got)
	}
	if got := hostsCurrentEntries("no block here\n"); len(got) != 0 {
		t.Fatalf("entries = %v", got)
	}
}

func TestSameStringSet(t *testing.T) {
	if !sameStringSet([]string{"a", "b"}, []string{"b", "a"}) {
		t.Fatal("order-insensitive match failed")
	}
	if sameStringSet([]string{"a"}, []string{"a", "b"}) {
		t.Fatal("size mismatch should differ")
	}
}

// TestProcKillTree kills a child we spawned (no root needed).
func TestProcKillTree(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	// own process group so the -pid kill targets only our tree
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	params := Params(map[string]any{"pid": strconv.Itoa(pid)})

	a := procKillTree{}
	r, err := a.Check(params)
	if err != nil || r.Done || r.Before == nil {
		t.Fatalf("check: %+v %v", r, err)
	}
	if _, err := a.Apply(params); err != nil {
		t.Fatal(err)
	}
	if r, _ := a.Verify(params); !r.Done {
		t.Fatalf("verify: %+v", r)
	}
	// re-apply on a dead pid is a no-op
	if r, err := a.Apply(params); err != nil || !r.Done {
		t.Fatalf("no-op apply: %+v %v", r, err)
	}
	_ = cmd.Wait()
}

func TestProcExists(t *testing.T) {
	if !procExists(os.Getpid()) {
		t.Fatal("own pid should exist")
	}
	if procExists(99999999) {
		t.Fatal("impossible pid should not exist")
	}
}
