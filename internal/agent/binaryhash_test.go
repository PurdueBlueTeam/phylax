package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

// TestHelloCarriesBinaryHash: the agent reports the sha256 of the binary it is
// running in hello, so the controller can compare it with the binaries it
// served.
func TestHelloCarriesBinaryHash(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])

	ctl := newFakeController(t, "ubuntu-ecom", "tok-1", 0)
	l := Layout{Root: t.TempDir()}
	writeBundle(t, l, ctl, "tok-1")
	startAgent(t, Config{Layout: l, Version: "9.9", HeartbeatInterval: 50 * time.Millisecond})

	eventually(t, 5*time.Second, "hello", func() bool {
		_, hellos, _ := ctl.snapshot()
		return len(hellos) > 0
	})
	_, hellos, _ := ctl.snapshot()
	if hellos[0].BinarySHA256 != want {
		t.Fatalf("hello binary hash %q, want %q (sha256 of %s)", hellos[0].BinarySHA256, want, exe)
	}
}
