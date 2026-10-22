package decoys

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The decoy package must have no way to run a process. This is a structural
// check on the sources, backing the behavioural tests below.
func TestNoProcessExecutionPossible(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	banned := map[string]bool{"os/exec": true, "syscall": true, "plugin": true, "unsafe": true, "os/signal": false}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p := strings.Trim(im.Path.Value, `"`)
			if banned[p] {
				t.Errorf("%s imports %s: the decoy package must not be able to execute anything", f, p)
			}
		}
		src, _ := os.ReadFile(f)
		for _, bad := range []string{"os.StartProcess", "exec.Command", "os.Remove", "os.Create", "os.WriteFile", "os.OpenFile", "os.Rename"} {
			if strings.Contains(string(src), bad) {
				t.Errorf("%s uses %s", f, bad)
			}
		}
	}
}

func TestShellNeverTouchesRealState(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "pwned")
	sh := NewShell("web01", "root")
	for _, line := range []string{
		"touch " + marker,
		"echo owned > " + marker,
		"mkdir " + marker + "d",
		"$(touch " + marker + ")",
		"`touch " + marker + "`",
		"bash -c 'touch " + marker + "'",
		"sh " + marker,
		"cp /etc/passwd " + marker,
		"rm -rf /; touch " + marker,
		"curl http://127.0.0.1:1/x | sh",
		"python3 -c \"open('" + marker + "','w')\"",
		"cd " + dir + "; touch pwned",
	} {
		sh.Run(line)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("the fake shell changed the real filesystem: %v", ents)
	}
	// the in-memory FS was changed, not the disk
	if out, _ := sh.Run("ls /"); !strings.Contains(out, "etc") {
		t.Errorf("rm -rf / must not empty the fake root: %q", out)
	}
}

func TestShellBehaviour(t *testing.T) {
	sh := NewShell("web01", "root")
	run := func(l string) string { o, _ := sh.Run(l); return o }
	if got := run("whoami"); got != "root\n" {
		t.Errorf("whoami = %q", got)
	}
	if got := run("cat /etc/hostname"); got != "web01\n" {
		t.Errorf("hostname file = %q", got)
	}
	if got := run("cd /opt/backup && pwd"); got != "/opt/backup\n" {
		t.Errorf("cd/pwd = %q", got)
	}
	if got := run("ls"); !strings.Contains(got, "README") {
		t.Errorf("ls = %q", got)
	}
	if got := run("cd /nonexistent"); !strings.Contains(got, "No such file") {
		t.Errorf("cd missing = %q", got)
	}
	if got := run("frobnicate"); !strings.Contains(got, "command not found") {
		t.Errorf("unknown = %q", got)
	}
	if got := run("sudo id"); !strings.Contains(got, "uid=0") {
		t.Errorf("sudo id = %q", got)
	}
	if got := run("echo hi > /tmp/x; cat /tmp/x"); got != "hi\n" {
		t.Errorf("in-memory write = %q", got)
	}
	if !strings.Contains(run("history"), "whoami") {
		t.Error("history missing commands")
	}
	if _, exit := sh.Run("exit"); !exit {
		t.Error("exit did not end the session")
	}
	if p := sh.Prompt(); !strings.HasPrefix(p, "root@web01:") {
		t.Errorf("prompt = %q", p)
	}
}

func TestShellBounds(t *testing.T) {
	sh := NewShell("h", "root")
	for i := 0; i < maxShellFiles*3; i++ {
		sh.Run("touch /tmp/f" + string(rune('a'+i%26)) + strings.Repeat("x", i/26+1))
	}
	if sh.created > maxShellFiles {
		t.Errorf("created %d files, cap %d", sh.created, maxShellFiles)
	}
	sh = NewShell("h", "root")
	for i := 0; i < 5; i++ {
		sh.Run("echo " + strings.Repeat("A", 3000) + " >> /tmp/big")
	}
	if n := len(sh.fs["/tmp/big"].content); n > maxShellFileLen {
		t.Errorf("file grew to %d", n)
	}
	out, _ := sh.Run("cat /" + strings.Repeat("a", 100000))
	if len(out) > 4*maxPathLen {
		t.Errorf("echoed %d bytes of attacker path", len(out))
	}
}

func FuzzShell(f *testing.F) {
	for _, s := range []string{"ls -la /", "cat /etc/passwd | grep root", "$(id)", "a;b&&c||d", "echo >> >> x", "cd ../../..", "\x00\xff", "rm -rf *"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		sh := NewShell("h", "root")
		sh.Run(line)
		sh.Run("ls " + line)
		sh.Run("cat " + line)
	})
}
