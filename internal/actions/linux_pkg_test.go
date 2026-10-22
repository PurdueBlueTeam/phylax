package actions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeApt simulates dpkg-query/apt-get against an in-memory package set.
type fakeApt struct {
	mu        sync.Mutex
	installed map[string]string
}

func newFakeApt(f *fixture, t *testing.T) (*fakeApt, *fakeRunner) {
	t.Helper()
	f.write(t, "usr/bin/apt-get", "", 0o755)
	fa := &fakeApt{installed: map[string]string{}}
	fr := &fakeRunner{}
	fr.onFn("/usr/bin/dpkg-query", func(c Cmd) CmdResult {
		fa.mu.Lock()
		defer fa.mu.Unlock()
		name := c.Argv[len(c.Argv)-1]
		if v, ok := fa.installed[name]; ok {
			return CmdResult{Stdout: "install ok installed|" + v}
		}
		return CmdResult{ExitCode: 1, Stderr: "no packages found"}
	})
	fr.onFn("/usr/bin/apt-get", func(c Cmd) CmdResult {
		fa.mu.Lock()
		defer fa.mu.Unlock()
		sim := false
		var verb, target string
		for _, a := range c.Argv[1:] {
			switch {
			case a == "-s":
				sim = true
			case a == "install" || a == "remove":
				verb = a
			case !strings.HasPrefix(a, "-") && verb != "" && a != "install" && a != "remove" && !strings.HasPrefix(a, "Acquire"):
				target = a
			}
		}
		if sim {
			return CmdResult{Stdout: "Inst " + target + " (simulated)\n"}
		}
		name, ver := target, "1.0-1"
		if strings.HasSuffix(target, ".deb") {
			b := filepath.Base(target)
			name, ver, _ = strings.Cut(strings.TrimSuffix(b, "_amd64.deb"), "_")
		} else if n, v, ok := strings.Cut(target, "="); ok {
			name, ver = n, v
		}
		if verb == "remove" {
			delete(fa.installed, name)
		} else {
			fa.installed[name] = ver
		}
		return CmdResult{Stdout: "done\n"}
	})
	f.linux(t).Exec = fr
	f.linux(t).PackageManager = "apt"
	return fa, fr
}

func depotWith(t *testing.T, f *fixture, rel, name string, content string, list bool) (path, sum string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "depot")
	d := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(content))
	sum = hex.EncodeToString(h[:])
	path = filepath.Join(d, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if list {
		_ = os.WriteFile(filepath.Join(d, "SHA256SUMS"), []byte(sum+"  "+name+"\n"), 0o644)
	}
	f.linux(t).DepotDir = dir
	return path, sum
}

func TestPkgInstallRequiresPatchWindow(t *testing.T) {
	f := newFixture(t)
	fa, fr := newFakeApt(f, t)
	depotWith(t, f, "wazuh/4.14.9", "wazuh-agent_4.14.9-1_amd64.deb", "deb-bytes", true)
	p := map[string]any{"name": "wazuh-agent", "version": "4.14.9", "source": "depot:wazuh/4.14.9"}
	// the dry run works without a window and shows the simulated transaction
	o, err := f.run(t, "pkg.install", p, func(r *Request) { r.DryRun = true })
	if err != nil || !strings.Contains(o.Plan.Diff, "Inst /") || !strings.Contains(o.Plan.Diff, "sha256") ||
		!strings.Contains(strings.Join(o.Plan.Notes, " "), "apply will be refused") {
		t.Fatalf("dry run: %+v %v", o.Plan, err)
	}
	// a real run without a window is refused before the package manager is touched
	_, err = f.run(t, "pkg.install", p)
	if err == nil || !strings.Contains(err.Error(), "patch window") {
		t.Fatalf("want a patch window refusal, got %v", err)
	}
	if len(fr.ran("/usr/bin/apt-get install")) != 0 || len(fa.installed) != 0 {
		t.Fatal("package manager ran outside a window")
	}
	// an expired window is no window
	f.linux(t).PatchWindow = func(context.Context) (*PatchWindow, error) {
		return &PatchWindow{ID: "old", Until: fixedNow.Add(-time.Second)}, nil
	}
	if _, err = f.run(t, "pkg.install", p); err == nil {
		t.Fatal("expired window accepted")
	}
	f.openWindow(t)
	o = f.ok(t, "pkg.install", p)
	if fa.installed["wazuh-agent"] != "4.14.9-1" || o.Output["window"] != "w1" || o.Output["window_tag"] != "patch-1" {
		t.Fatalf("installed=%v out=%v", fa.installed, o.Output)
	}
	inst := fr.ran("/usr/bin/apt-get -o Acquire::http::Proxy=http://127.0.0.1:3128")
	if len(inst) != 1 || !strings.Contains(strings.Join(inst[0].Env, " "), "http_proxy=http://127.0.0.1:3128") {
		t.Fatalf("install did not go through the window proxy: %v", fr.calls)
	}
	// already at the pinned version: nothing to do
	if o := f.ok(t, "pkg.install", p); !o.Plan.Done || o.Changed {
		t.Fatalf("second run: %+v", o)
	}
	// 4.14.90 is not 4.14.9
	if versionMatches("4.14.90-1", "4.14.9") || !versionMatches("1:4.14.9-1ubuntu1", "4.14.9") || !versionMatches("4.14.9", "4.14.9") {
		t.Fatal("versionMatches")
	}
}

func TestPkgInstallDepotVerification(t *testing.T) {
	f := newFixture(t)
	fa, _ := newFakeApt(f, t)
	f.openWindow(t)
	file, _ := depotWith(t, f, "wazuh/4.14.9", "wazuh-agent_4.14.9-1_amd64.deb", "deb-bytes", true)
	p := map[string]any{"name": "wazuh-agent", "version": "4.14.9", "source": "depot:wazuh/4.14.9"}
	// tampered after the hash list was written: refused, nothing installed
	if err := os.WriteFile(file, []byte("evil"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := f.refused(t, "pkg.install", p); !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("tampered: %v", err)
	}
	// no hash at all: refused
	f2 := newFixture(t)
	newFakeApt(f2, t)
	f2.openWindow(t)
	depotWith(t, f2, "wazuh/4.14.9", "wazuh-agent_4.14.9-1_amd64.deb", "deb-bytes", false)
	if err := f2.refused(t, "pkg.install", p); !strings.Contains(err.Error(), "unverified") {
		t.Fatalf("no sha256: %v", err)
	}
	// an explicit sha256 param is enough, and a wrong one is refused
	f3 := newFixture(t)
	fa3, _ := newFakeApt(f3, t)
	f3.openWindow(t)
	_, sum := depotWith(t, f3, "wazuh/4.14.9", "wazuh-agent_4.14.9-1_amd64.deb", "deb-bytes", false)
	pp := map[string]any{"name": "wazuh-agent", "version": "4.14.9", "source": "depot:wazuh/4.14.9", "sha256": strings.Repeat("0", 64)}
	if err := f3.refused(t, "pkg.install", pp); !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong sha256: %v", err)
	}
	pp["sha256"] = sum
	f3.ok(t, "pkg.install", pp)
	if fa3.installed["wazuh-agent"] == "" || len(fa.installed) != 0 {
		t.Fatal("install state")
	}
	// source/param validation
	for _, src := range []string{"depot:../etc", "depot:/abs", "http://evil/x.deb", "depot:", "depot:a/../../b"} {
		if _, err := f3.run(t, "pkg.install", map[string]any{"name": "x", "version": "1", "source": src}); err == nil {
			t.Errorf("source %q accepted", src)
		}
	}
	// a symlink inside the depot may not point outside it
	depot := f3.linux(t).DepotDir
	outside := filepath.Join(t.TempDir(), "o.deb")
	_ = os.WriteFile(outside, []byte("x"), 0o644)
	_ = os.Symlink(outside, filepath.Join(depot, "link.deb"))
	if _, err := f3.run(t, "pkg.install", map[string]any{"name": "x", "version": "1", "source": "depot:link.deb", "sha256": sum}); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("symlink escape: %v", err)
	}
}

func TestPkgUnpinnedAndUpgradeRules(t *testing.T) {
	f := newFixture(t)
	fa, _ := newFakeApt(f, t)
	f.openWindow(t)
	if _, err := f.run(t, "pkg.install", map[string]any{"name": "nginx"}); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("unpinned install: %v", err)
	}
	if _, err := f.run(t, "pkg.upgrade", map[string]any{"name": "openssh-server"}); err == nil {
		t.Fatal("pkg.upgrade without version accepted")
	}
	if _, err := f.run(t, "pkg.upgrade", map[string]any{"name": "openssh-server", "version": "9.8p1"}); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("upgrade of a missing package: %v", err)
	}
	fa.installed["openssh-server"] = "9.6p1-3"
	o := f.ok(t, "pkg.upgrade", map[string]any{"name": "openssh-server", "version": "9.8p1"})
	if fa.installed["openssh-server"] != "9.8p1" || !o.Changed {
		t.Fatalf("upgrade: %v", fa.installed)
	}
	for _, bad := range []string{"a b", "-oBad", "x;rm", "../x", ""} {
		if _, err := f.run(t, "pkg.install", map[string]any{"name": bad, "version": "1"}); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
	if _, err := f.run(t, "pkg.install", map[string]any{"name": "x", "version": "--force"}); err == nil {
		t.Error("option-like version accepted")
	}
}

func TestPkgRemoveKeepsConfigAndRefusesScored(t *testing.T) {
	f := newFixture(t)
	fa, fr := newFakeApt(f, t)
	f.openWindow(t)
	fa.installed["cups"] = "2.4"
	fa.installed["apache2"] = "2.4.58"
	o, err := f.run(t, "pkg.remove", map[string]any{"name": "cups"}, func(r *Request) { r.DryRun = true })
	if err != nil || !strings.Contains(o.Plan.Diff, "configuration kept") {
		t.Fatalf("dry run: %+v %v", o.Plan, err)
	}
	f.ok(t, "pkg.remove", map[string]any{"name": "cups"})
	if _, ok := fa.installed["cups"]; ok {
		t.Fatal("not removed")
	}
	for _, c := range fr.calls {
		if strings.Contains(strings.Join(c.Argv, " "), "purge") {
			t.Fatal("purge used; config must be kept")
		}
	}
	if o := f.ok(t, "pkg.remove", map[string]any{"name": "cups"}); !o.Plan.Done {
		t.Fatal("removing an absent package should be Done")
	}
	f.env.Guard = StaticGuard{Services: []string{"apache2"}}
	if err := f.refused(t, "pkg.remove", map[string]any{"name": "apache2"}); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("scored package: %v", err)
	}
	if fa.installed["apache2"] == "" {
		t.Fatal("scored package removed")
	}
}

func TestPkgDnfPath(t *testing.T) {
	f := newFixture(t)
	f.write(t, "usr/bin/dnf", "", 0o755)
	have := map[string]string{}
	fr := &fakeRunner{}
	fr.onFn("/usr/bin/rpm", func(c Cmd) CmdResult {
		if v, ok := have[c.Argv[len(c.Argv)-1]]; ok {
			return CmdResult{Stdout: v}
		}
		return CmdResult{ExitCode: 1, Stdout: "package x is not installed"}
	})
	fr.onFn("/usr/bin/dnf", func(c Cmd) CmdResult {
		j := strings.Join(c.Argv, " ")
		if strings.Contains(j, "--assumeno") {
			return CmdResult{ExitCode: 1, Stdout: "Transaction Summary\nInstall 1 Package\nOperation aborted.\n"}
		}
		have["wazuh-agent"] = "4.14.9-1"
		return CmdResult{}
	})
	f.linux(t).Exec = fr
	f.openWindow(t)
	p := map[string]any{"name": "wazuh-agent", "version": "4.14.9"}
	o, err := f.run(t, "pkg.install", p, func(r *Request) { r.DryRun = true })
	if err != nil || !strings.Contains(o.Plan.Diff, "Transaction Summary") {
		t.Fatalf("dry run: %+v %v", o.Plan, err)
	}
	f.ok(t, "pkg.install", p)
	if have["wazuh-agent"] != "4.14.9-1" {
		t.Fatal("not installed")
	}
	if c := fr.ran("/usr/bin/dnf --setopt=proxy=http://127.0.0.1:3128 install -y wazuh-agent-4.14.9"); len(c) != 1 {
		t.Fatalf("dnf command: %v", fr.calls)
	}
}

func TestPinnedToolHashCheck(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := execRunner{pinned: map[string]string{tool: strings.Repeat("a", 64)}}
	if _, err := r.Run(t.Context(), Cmd{Argv: []string{tool}}); err == nil || !strings.Contains(err.Error(), "pinned hash") {
		t.Fatalf("hash mismatch must refuse to run: %v", err)
	}
	sum, _ := hashFile(tool, "sha256")
	r = execRunner{pinned: map[string]string{tool: sum}}
	res, err := r.Run(t.Context(), Cmd{Argv: []string{tool}})
	if err != nil || strings.TrimSpace(res.Stdout) != "hi" {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := (execRunner{}).Run(t.Context(), Cmd{Argv: []string{"sh", "-c", "id"}}); err == nil {
		t.Fatal("relative command accepted")
	}
}
