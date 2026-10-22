package depot

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/integrity"
)

const envProg = `package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("argv0=" + os.Args[0])
	for _, a := range os.Args[1:] {
		fmt.Println("arg=" + a)
	}
	for _, e := range os.Environ() {
		fmt.Println("env=" + e)
	}
}
`

// buildFixture compiles a tiny static program into dir/name.
func buildFixture(t *testing.T, dir, name, src string) string {
	t.Helper()
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-o", out, filepath.Join(work, "main.go"))
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	return out
}

type kit struct {
	pub    integrity.Ed25519Verifier
	sg     integrity.Ed25519Signer
	store  Store
	raw    []byte
	m      *Manifest
	deploy string
}

func newKit(t *testing.T) *kit {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("fixture deploy tests run on linux")
	}
	pk, sk, _ := ed25519.GenerateKey(rand.Reader)
	k := &kit{pub: integrity.Ed25519Verifier{Key: pk}, sg: integrity.Ed25519Signer{Key: sk}}
	src := t.TempDir()
	buildFixture(t, src, "envdump", envProg)
	spec := &Spec{Tools: []SpecTool{
		{Entry: Entry{Name: "envdump", Version: "1.0", OS: runtime.GOOS, Arch: runtime.GOARCH, License: "MIT", Provides: []string{"alias1"}}, File: "envdump"},
		{Entry: Entry{Name: "procmon.exe", Version: "9.9", OS: "windows", Arch: "amd64", License: "LicenseRef-Sysinternals", URL: "https://example.invalid/x?a=1&b=<2>", SHA256: strings.Repeat("ab", 32), FetchAtInit: true}},
	}}
	k.store = Store{Dir: t.TempDir()}
	m, err := Pack(spec, src, k.store, k.sg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	k.m = m
	k.raw, _ = os.ReadFile(k.store.ManifestPath())
	k.deploy = filepath.Join(t.TempDir(), "d")
	if _, err := Deploy(k.store, m, k.raw, k.deploy, runtime.GOOS, runtime.GOARCH); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestManifestSignVerifyTamper(t *testing.T) {
	k := newKit(t)
	m, err := Parse(k.raw, k.pub)
	if err != nil || len(m.Tools) != 2 {
		t.Fatalf("parse: %v %v", err, m)
	}
	// tampered body (change a hash digit's neighbour: swap the version)
	bad := bytes.Replace(k.raw, []byte(`1.0`), []byte(`1.1`), 1)
	if bytes.Equal(bad, k.raw) {
		t.Fatal("tamper did not apply")
	}
	if _, err := Parse(bad, k.pub); !errors.Is(err, integrity.ErrBadSignature) {
		t.Fatalf("tampered manifest: %v", err)
	}
	// wrong key
	pk2, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Parse(k.raw, integrity.Ed25519Verifier{Key: pk2}); !errors.Is(err, integrity.ErrBadSignature) {
		t.Fatalf("wrong key: %v", err)
	}
	// unsigned
	if _, err := Parse([]byte(`{"body":{"format":1,"tools":[]}}`), k.pub); !errors.Is(err, ErrNoSig) {
		t.Fatalf("unsigned: %v", err)
	}
	if _, err := Parse(k.raw, nil); err == nil {
		t.Fatal("nil verifier accepted")
	}
}

func TestValidateRejects(t *testing.T) {
	for name, e := range map[string]Entry{
		"slash name": {Name: "a/b", Version: "1", OS: "linux", Arch: "amd64", License: "MIT", SHA256: strings.Repeat("00", 32)},
		"no hash":    {Name: "a", Version: "1", OS: "linux", Arch: "amd64", License: "MIT"},
		"no license": {Name: "a", Version: "1", OS: "linux", Arch: "amd64", SHA256: strings.Repeat("00", 32)},
		"bad applet": {Name: "a", Version: "1", OS: "linux", Arch: "amd64", License: "MIT", SHA256: strings.Repeat("00", 32), Provides: []string{"../x"}},
	} {
		m := &Manifest{Format: 1, Tools: []Entry{e}}
		if m.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestStoreRejectsWrongHash(t *testing.T) {
	st := Store{Dir: t.TempDir()}
	want := strings.Repeat("11", 32)
	if _, _, err := st.Put(strings.NewReader("hello"), want, 100); err == nil {
		t.Fatal("wrong hash stored")
	}
	if st.Has(want) {
		t.Fatal("blob present after failed put")
	}
	if _, _, err := st.Put(strings.NewReader(strings.Repeat("x", 50)), want, 10); err == nil {
		t.Fatal("oversize accepted")
	}
}

type fakeFetcher map[string]string

func (f fakeFetcher) Fetch(_ context.Context, e Entry) (io.ReadCloser, error) {
	s, ok := f[e.URL]
	if !ok {
		return nil, errors.New("404")
	}
	return io.NopCloser(strings.NewReader(s)), nil
}

func TestFetchMissingVerifiesHash(t *testing.T) {
	good := "good-bytes"
	st := Store{Dir: t.TempDir()}
	h := sha256Hex(good)
	m := &Manifest{Format: 1, Tools: []Entry{
		{Name: "ok", Version: "1", OS: "linux", Arch: "amd64", License: "MIT", SHA256: h, Size: int64(len(good)), URL: "u1", FetchAtInit: true},
		{Name: "evil", Version: "1", OS: "linux", Arch: "amd64", License: "MIT", SHA256: sha256Hex("expected"), URL: "u2", FetchAtInit: true},
		{Name: "relasset", Version: "1", OS: "linux", Arch: "amd64", License: "MIT", SHA256: sha256Hex("zzz"), URL: "u3"},
	}}
	got, errs := st.FetchMissing(context.Background(), m, fakeFetcher{"u1": good, "u2": "substituted"}, "linux", "amd64")
	if len(got) != 1 || got[0] != "ok" || len(errs) != 2 {
		t.Fatalf("got=%v errs=%v", got, errs)
	}
	if st.Has(sha256Hex("expected")) || st.Has(sha256Hex("substituted")) {
		t.Fatal("substituted content was stored")
	}
}

func TestDeployPermsAndVerify(t *testing.T) {
	k := newKit(t)
	fi, _ := os.Stat(k.deploy)
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir perm %v", fi.Mode().Perm())
	}
	d, err := OpenDeployed(k.deploy, k.pub)
	if err != nil {
		t.Fatal(err)
	}
	if ps := d.Verify(); len(ps) != 0 {
		t.Fatalf("clean depot has problems: %v", ps)
	}
	fi, _ = os.Stat(filepath.Join(d.BinDir(), "envdump"))
	if fi.Mode().Perm() != 0o500 {
		t.Fatalf("tool perm %v", fi.Mode().Perm())
	}
	if tgt, _ := os.Readlink(filepath.Join(d.BinDir(), "alias1")); tgt != "envdump" {
		t.Fatalf("applet link %q", tgt)
	}
	// extra planted file and redirected applet are reported
	os.WriteFile(filepath.Join(d.BinDir(), "planted"), []byte("x"), 0o500)
	os.Remove(filepath.Join(d.BinDir(), "alias1"))
	os.Symlink("/bin/sh", filepath.Join(d.BinDir(), "alias1"))
	ps := d.Verify()
	if len(ps) != 2 {
		t.Fatalf("want 2 problems, got %v", ps)
	}
	// a forged manifest copy on the host is refused
	pk2, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := OpenDeployed(k.deploy, integrity.Ed25519Verifier{Key: pk2}); err == nil {
		t.Fatal("manifest accepted under another key")
	}
}

func TestRunVerifiedAndCleanEnv(t *testing.T) {
	k := newKit(t)
	d, err := OpenDeployed(k.deploy, k.pub)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	t.Setenv("LD_LIBRARY_PATH", "/tmp/evil")
	t.Setenv("BASH_ENV", "/tmp/evil.sh")
	t.Setenv("PATH", "/usr/bin:/bin")
	t.Setenv("SECRET_FROM_HOST", "leak")
	var out, errb bytes.Buffer
	code, err := d.Run(context.Background(), "alias1", []string{"-x", "y z"}, map[string]string{"LD_AUDIT": "bad", "PATH": "/evil", "OK": "1"}, IO{Stdout: &out, Stderr: &errb})
	if err != nil || code != 0 {
		t.Fatalf("run: %d %v %s", code, err, errb.String())
	}
	o := out.String()
	for _, want := range []string{"argv0=alias1", "arg=-x", "arg=y z", "env=PATH=" + d.BinDir() + "\n", "env=OK=1"} {
		if !strings.Contains(o, want+"") && !strings.Contains(o+"\n", want) {
			t.Errorf("missing %q in:\n%s", want, o)
		}
	}
	for _, bad := range []string{"LD_", "evil", "BASH_ENV", "SECRET_FROM_HOST", "/usr/bin"} {
		if strings.Contains(o, bad) {
			t.Errorf("environment leaked %q:\n%s", bad, o)
		}
	}
}

func TestRunRefusesTampered(t *testing.T) {
	k := newKit(t)
	d, _ := OpenDeployed(k.deploy, k.pub)
	p := filepath.Join(d.BinDir(), "envdump")
	os.Chmod(p, 0o700)
	b, _ := os.ReadFile(p)
	b[len(b)-1] ^= 0xff
	os.WriteFile(p, b, 0o500)
	var out bytes.Buffer
	_, err := d.Run(context.Background(), "envdump", nil, nil, IO{Stdout: &out})
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("want ErrTampered, got %v", err)
	}
	if out.Len() != 0 {
		t.Fatal("tampered tool produced output")
	}
	if len(d.Verify()) == 0 {
		t.Fatal("verify missed tampering")
	}
	// writable by others is refused even with the right content
	k2 := newKit(t)
	d2, _ := OpenDeployed(k2.deploy, k2.pub)
	os.Chmod(filepath.Join(d2.BinDir(), "envdump"), 0o757)
	if _, err := d2.Run(context.Background(), "envdump", nil, nil, IO{}); !errors.Is(err, ErrTampered) {
		t.Fatalf("world-writable: %v", err)
	}
	if _, err := d2.Run(context.Background(), "nosuch", nil, nil, IO{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown tool: %v", err)
	}
}

func TestRunExecsVerifiedBytesNotDisk(t *testing.T) {
	// The bytes that were hashed are what runs: swapping the file after
	// Command() returns must not change what executes.
	k := newKit(t)
	d, _ := OpenDeployed(k.deploy, k.pub)
	var out bytes.Buffer
	cmd, cleanup, err := d.Command(context.Background(), "envdump", []string{"hi"}, nil, IO{Stdout: &out})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	p := filepath.Join(d.BinDir(), "envdump")
	os.Remove(p)
	os.WriteFile(p, []byte("#!/bin/sh\necho pwned\n"), 0o755)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "pwned") || !strings.Contains(out.String(), "arg=hi") {
		t.Fatalf("ran swapped file: %s", out.String())
	}
}

func TestHiddenDir(t *testing.T) {
	a, b := HiddenDir("/var/tmp", "s1"), HiddenDir("/var/tmp", "s1")
	if a != b || a == HiddenDir("/var/tmp", "s2") || !strings.HasPrefix(filepath.Base(a), ".") {
		t.Fatalf("%s %s", a, b)
	}
}

func TestLookupAndLicenseSource(t *testing.T) {
	m := &Manifest{Format: 1, Tools: []Entry{{Name: "busybox", Version: "1", OS: "linux", Arch: "amd64", License: "GPL-2.0-only", SHA256: strings.Repeat("00", 32), Provides: []string{"ps", "ls"}}}}
	e, ap, err := m.Lookup("linux", "amd64", "ps")
	if err != nil || e.Name != "busybox" || ap != "ps" {
		t.Fatal(e, ap, err)
	}
	if _, _, err := m.Lookup("windows", "amd64", "ps"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
