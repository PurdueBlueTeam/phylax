package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDepotAndToolsRegistered(t *testing.T) {
	for _, n := range []string{"depot", "tools"} {
		if _, ok := commands[n]; !ok {
			t.Errorf("%s not registered", n)
		}
	}
}

func TestToolsLSHash(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "f"), []byte("x"), 0o600)
	var out, errb bytes.Buffer
	if err := runTools([]string{"ls", d}, &out, &errb); err != nil || !strings.Contains(out.String(), " f\n") {
		t.Fatal(err, out.String())
	}
	out.Reset()
	if err := runTools([]string{"hash", filepath.Join(d, "f")}, &out, &errb); err != nil || !strings.HasPrefix(out.String(), "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881") {
		t.Fatal(err, out.String())
	}
	if runtime.GOOS == "linux" {
		out.Reset()
		if err := runTools([]string{"lsof", "1"}, &out, &errb); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDepotKeygenPackDeployVerifyRun(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	w := t.TempDir()
	var out, errb bytes.Buffer
	ctx := context.Background()
	run := func(args ...string) error {
		out.Reset()
		errb.Reset()
		return runDepot(ctx, args, strings.NewReader(""), &out, &errb)
	}
	if err := run("keygen", "--out", filepath.Join(w, "k")); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(w, "src")
	os.MkdirAll(src, 0o755)
	// pack/deploy/list/verify only hash and copy bytes, so any file will do;
	// execution of real static fixtures is covered in internal/depot tests.
	self, _ := os.Executable()
	b, _ := os.ReadFile(self)
	os.WriteFile(filepath.Join(src, "fx"), b[:1<<16], 0o755)
	spec := `{"tools":[{"name":"fx","version":"1","os":"` + runtime.GOOS + `","arch":"` + runtime.GOARCH + `","license":"MIT","file":"fx"}]}`
	os.WriteFile(filepath.Join(w, "spec.json"), []byte(spec), 0o644)
	store, dd, pub := filepath.Join(w, "store"), filepath.Join(w, "dep"), filepath.Join(w, "k.pub")
	if err := run("pack", "--spec", filepath.Join(w, "spec.json"), "--src", src, "--store", store, "--key", filepath.Join(w, "k.key")); err != nil {
		t.Fatal(err)
	}
	if err := run("deploy", "--store", store, "--dir", dd, "--pub", pub); err != nil {
		t.Fatal(err)
	}
	if err := run("list", "--dir", dd, "--pub", pub); err != nil || !strings.Contains(out.String(), "fx") {
		t.Fatal(err, out.String())
	}
	if err := run("verify", "--dir", dd, "--pub", pub); err != nil {
		t.Fatal(err)
	}
	// wrong key refuses everything
	if err := run("keygen", "--out", filepath.Join(w, "other")); err != nil {
		t.Fatal(err)
	}
	if err := run("verify", "--dir", dd, "--pub", filepath.Join(w, "other.pub")); err == nil {
		t.Fatal("verify accepted the wrong key")
	}
	// tamper
	p := filepath.Join(dd, "bin", "fx")
	os.Chmod(p, 0o700)
	os.WriteFile(p, []byte("evil"), 0o500)
	if err := run("verify", "--dir", dd, "--pub", pub); err == nil {
		t.Fatal("verify missed tampering")
	}
	if err := run("run", "--dir", dd, "--pub", pub, "fx"); err == nil {
		t.Fatal("run executed a tampered tool")
	}
}
