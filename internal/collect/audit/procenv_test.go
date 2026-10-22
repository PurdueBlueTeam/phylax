//go:build linux

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseEnvironKeepsOnlyLoaderFamily(t *testing.T) {
	blob := "PATH=/usr/bin\x00AWS_SECRET_ACCESS_KEY=hunter2\x00LD_PRELOAD=/tmp/.x/libhide.so\x00" +
		"LD_LIBRARY_PATH=/dev/shm\x00HIDDEN=/root/.implant\x00BLOCKED=10.0.0.9\x00DB_PASSWORD=pw\x00LD_DEBUG=\x00"
	got := parseEnviron([]byte(blob))
	want := map[string]any{"LD_PRELOAD": "/tmp/.x/libhide.so", "LD_LIBRARY_PATH": "/dev/shm", "HIDDEN": envMarker, "BLOCKED": envMarker}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	for _, v := range got {
		s := v.(string)
		if strings.Contains(s, "hunter2") || strings.Contains(s, "pw") || s == "/root/.implant" || s == "10.0.0.9" {
			t.Fatalf("a non-allowed value leaked: %q", s)
		}
	}
}

func TestParseEnvironBounds(t *testing.T) {
	if parseEnviron([]byte("PATH=/bin\x00HOME=/root\x00")) != nil {
		t.Fatal("an environment with nothing of interest must yield no env field")
	}
	long := "LD_PRELOAD=" + strings.Repeat("a", 5000)
	if v := parseEnviron([]byte(long))["LD_PRELOAD"].(string); len(v) != environValMax {
		t.Fatalf("value not clipped: %d", len(v))
	}
	var b strings.Builder
	for i := 0; i < 100; i++ {
		b.WriteString("HIDDEN=1\x00LD_PRELOAD=/x\x00")
	}
	if n := len(parseEnviron([]byte(b.String()))); n > environKeysMax {
		t.Fatalf("%d keys", n)
	}
}

func TestReadEnvKeysFromProcRoot(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "4242")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "environ"), []byte("SECRET=x\x00LD_PRELOAD=/tmp/e.so\x00"), 0o600)
	got := readEnvKeys(root, 4242)
	if got["LD_PRELOAD"] != "/tmp/e.so" || len(got) != 1 {
		t.Fatalf("%v", got)
	}
	if readEnvKeys(root, 1) != nil {
		t.Fatal("missing process must give nil")
	}
	// Self test against the real /proc: our own environment must never leak other keys.
	t.Setenv("PHYLAX_TEST_SECRET", "s3cret")
	t.Setenv("LD_LIBRARY_PATH", "/tmp/lib")
	live := readEnvKeys("/proc", os.Getpid())
	for k := range live {
		if !envValueKeys[k] && !envMarkerKeys[k] {
			t.Fatalf("leaked key %s", k)
		}
	}
}
