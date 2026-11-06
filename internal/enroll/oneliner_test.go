package enroll

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/link"
)

func writeReleases(t *testing.T, dir string) (linux, windows []byte) {
	t.Helper()
	linux = []byte("#!/bin/sh\necho fake phylax linux binary\n")
	windows = []byte("fake windows binary\n")
	if err := os.WriteFile(filepath.Join(dir, "phylax-linux-amd64"), linux, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "phylax-windows-amd64.exe"), windows, 0o600); err != nil {
		t.Fatal(err)
	}
	return linux, windows
}

func TestOneLinerShape(t *testing.T) {
	f := newEnrollerWith(t, func(o *Options) { o.ReleaseDir = t.TempDir() })
	writeReleases(t, f.e.opt.ReleaseDir)
	tok, err := f.e.MintToken("h1", 0)
	if err != nil {
		t.Fatal(err)
	}
	const ctl = "10.0.0.5:7443"
	linux, err := f.e.OneLiner(OSLinux, ctl, tok)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(linux, "\r\n") || !isASCII(linux) {
		t.Fatalf("Linux line is not one ASCII line: %q", linux)
	}
	// Measured with the real generator, a 14-byte controller address and a
	// 32-character token.
	const linuxLen = 136
	if len(linux) != linuxLen {
		t.Fatalf("Linux line is %d bytes, measured %d: %q", len(linux), linuxLen, linux)
	}
	if !strings.Contains(linux, "--pinnedpubkey "+f.id.Pin.Curl()) {
		t.Fatalf("Linux line does not pin the identity key: %q", linux)
	}
	if !strings.Contains(linux, "https://"+ctl+"/l/"+tok) {
		t.Fatalf("Linux line has no https://%s/l/<token>: %q", ctl, linux)
	}

	win, err := f.e.OneLiner(OSWindows, ctl, tok)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(win, "\r\n") || !isASCII(win) {
		t.Fatalf("Windows line is not one ASCII line: %q", win)
	}
	// Measured with the same address and token.
	const windowsLen = 294
	if len(win) != windowsLen {
		t.Fatalf("Windows line is %d bytes, measured %d: %q", len(win), windowsLen, win)
	}
	sum := sha1.Sum(f.id.Cert.Certificate[0])
	thumb := strings.ToUpper(hex.EncodeToString(sum[:]))
	if !strings.Contains(win, thumb) {
		t.Fatalf("Windows line does not carry the certificate thumbprint %s: %q", thumb, win)
	}
	if !strings.Contains(win, "/w/"+tok) {
		t.Fatalf("Windows line has no /w/<token>: %q", win)
	}

	if _, err := f.e.OneLiner("plan9", ctl, tok); err == nil {
		t.Fatal("unknown OS: no error")
	}
	if _, err := f.e.OneLiner(OSLinux, "", tok); err == nil {
		t.Fatal("empty controller address: no error")
	}
	missing := newEnrollerWith(t, func(o *Options) { o.ReleaseDir = t.TempDir() })
	if _, err := missing.e.OneLiner(OSLinux, ctl, tok); err == nil || !strings.Contains(err.Error(), "phylax-linux-amd64") {
		t.Fatalf("missing release err = %v, want it to name phylax-linux-amd64", err)
	}
}

func TestOneLinerWrongPinSendsNothing(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl is not installed")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	f := newEnrollerWith(t, func(o *Options) { o.ReleaseDir = t.TempDir() })
	writeReleases(t, f.e.opt.ReleaseDir)
	tok, err := f.e.MintToken("h1", 0)
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int64
	bs := startBoot(t, f.e, func(ctx context.Context, c *link.Conn) {
		f.e.serveBootstrap(ctx, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			f.e.bootstrap(w, r)
		}))
	})
	line, err := f.e.OneLiner(OSLinux, bs.addr, tok)
	if err != nil {
		t.Fatal(err)
	}
	bad := f.id.Pin
	bad[0] ^= 0xff
	line = strings.Replace(line, f.id.Pin.Curl(), bad.Curl(), 1)
	// A POSIX pipeline reports sh's status, not curl's, so this only proves
	// that nothing reached the handler.
	out, _ := exec.Command("sh", "-c", line).CombinedOutput()
	if hits.Load() != 0 {
		t.Fatalf("wrong pin reached the handler %d times: %s", hits.Load(), out)
	}

	// The bare curl command is the one that must report the pin failure.
	curl := exec.Command("curl", "-sk", "--pinnedpubkey", bad.Curl(), "https://"+bs.addr+"/l/"+tok)
	out, err = curl.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 90 {
		t.Fatalf("curl with a wrong pin: err=%v output=%s, want exit 90", err, out)
	}
	if hits.Load() != 0 {
		t.Fatalf("wrong pin reached the handler %d times", hits.Load())
	}
}

func TestOneLinerInstallsWithRealCurlAndSh(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl is not installed")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args")
	bootSeen := filepath.Join(dir, "boot.seen")
	fake := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" >> '" + argsPath + "'\n" +
		"while [ $# -gt 0 ]; do\n" +
		"  if [ \"$1\" = --bootstrap ]; then shift; cp \"$1\" '" + bootSeen + "'; fi\n" +
		"  shift\n" +
		"done\n"
	release := []byte(fake)
	relDir := filepath.Join(dir, "release")
	if err := os.MkdirAll(relDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rel := filepath.Join(relDir, "phylax-linux-amd64")
	if err := os.WriteFile(rel, release, 0o600); err != nil {
		t.Fatal(err)
	}
	f := newEnrollerWith(t, func(o *Options) { o.ReleaseDir = relDir })
	tok, err := f.e.MintToken("h1", 0)
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int64
	bs := startBoot(t, f.e, func(ctx context.Context, c *link.Conn) {
		f.e.serveBootstrap(ctx, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			f.e.bootstrap(w, r)
		}))
	})
	line, err := f.e.OneLiner(OSLinux, bs.addr, tok)
	if err != nil {
		t.Fatal(err)
	}
	inst := filepath.Join(dir, "inst")
	cmd := exec.Command("sh", "-c", line)
	cmd.Env = append(os.Environ(), "PHYLAX_DIR="+inst, "INSTALL_DIR="+inst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install script: %v\n%s", err, out)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("the fake release never ran: %v", err)
	}
	if !strings.Contains(string(args), "agent\ninstall\n--bootstrap\n") {
		t.Fatalf("install args = %q, want agent install --bootstrap <path>", args)
	}
	if _, err := os.Stat(bootSeen); err != nil {
		t.Fatalf("the downloaded boot JSON did not exist at install time: %v", err)
	}
	if _, err := os.Stat(filepath.Join(inst, "boot.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("boot.json was not removed: %v", err)
	}
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return false
		}
	}
	return true
}
