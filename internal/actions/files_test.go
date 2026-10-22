package actions

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileWriteIdempotentAndModes(t *testing.T) {
	f := newFixture(t)
	p := map[string]any{"path": "/etc/app/app.conf", "content": "a=1\n", "mode": "0600"}
	o := f.ok(t, "file.write", p)
	if !o.Changed || f.read(t, "etc/app/app.conf") != "a=1\n" {
		t.Fatalf("%+v", o)
	}
	if st, _ := os.Stat(f.path("etc/app/app.conf")); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if o := f.ok(t, "file.write", p); o.Changed || !o.Plan.Done {
		t.Fatalf("second run changed: %+v", o)
	}
	// mode-only drift is detected and fixed
	os.Chmod(f.path("etc/app/app.conf"), 0o644)
	if o := f.ok(t, "file.write", p); !o.Changed {
		t.Fatal("mode drift not fixed")
	}
	// existing file keeps its mode when none requested
	f.write(t, "etc/keep", "old", 0o640)
	f.ok(t, "file.write", map[string]any{"path": "/etc/keep", "content": "new"})
	if st, _ := os.Stat(f.path("etc/keep")); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode not kept: %v", st.Mode())
	}
	// base64 content, binary
	bin := []byte{0, 1, 2, 0xff}
	f.ok(t, "file.write", map[string]any{"path": "/etc/bin", "content_b64": base64.StdEncoding.EncodeToString(bin)})
	if f.read(t, "etc/bin") != string(bin) {
		t.Fatal("binary content")
	}
	if _, err := f.run(t, "file.write", map[string]any{"path": "/etc/x"}); err == nil {
		t.Fatal("content required")
	}
	if _, err := f.run(t, "file.write", map[string]any{"path": "/etc/x", "content": "a", "content_b64": "YQ=="}); err == nil {
		t.Fatal("content xor content_b64")
	}
}

func TestFileWriteFollowsSymlinkAndKeepsIt(t *testing.T) {
	f := newFixture(t)
	f.write(t, "etc/real.conf", "one", 0o640)
	if err := os.Symlink("real.conf", f.path("etc/link.conf")); err != nil {
		t.Fatal(err)
	}
	f.ok(t, "file.write", map[string]any{"path": "/etc/link.conf", "content": "two"})
	if fi, _ := os.Lstat(f.path("etc/link.conf")); fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink replaced")
	}
	if f.read(t, "etc/real.conf") != "two" {
		t.Fatal("target not updated")
	}
}

func TestFileTemplate(t *testing.T) {
	f := newFixture(t)
	p := map[string]any{"path": "/etc/php.ini", "template": "host={{.Host}} port={{.port}}\n", "vars": map[string]any{"port": "8080"}}
	f.ok(t, "file.template", p)
	if got := f.read(t, "etc/php.ini"); got != "host=testhost port=8080\n" {
		t.Fatalf("%q", got)
	}
	// missing variable is an error, not "<no value>"
	if _, err := f.run(t, "file.template", map[string]any{"path": "/etc/x.ini", "template": "{{.nope}}"}); err == nil {
		t.Fatal("missing var accepted")
	}
	if _, err := f.run(t, "file.template", map[string]any{"path": "/etc/x.ini", "template": "{{"}); err == nil {
		t.Fatal("bad template accepted")
	}
	if o := f.ok(t, "file.template", p); o.Changed {
		t.Fatal("template not idempotent")
	}
}

func TestFileWriteDeadmanRollbackRestoresContentAndMode(t *testing.T) {
	f := newFixture(t)
	f.write(t, "etc/ssh/sshd_config", "Port 22\n", 0o600)
	o := f.ok(t, "file.write", map[string]any{"path": "/etc/ssh/sshd_config", "content": "Port 2222\n", "mode": "0644"},
		func(r *Request) { r.Deadman = 120 * time.Millisecond })
	if o.DeadmanID == "" {
		t.Fatal("no dead-man armed")
	}
	waitFor(t, "rollback", func() bool { return f.read(t, "etc/ssh/sshd_config") == "Port 22\n" })
	if st, _ := os.Stat(f.path("etc/ssh/sshd_config")); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode after rollback %v", st.Mode())
	}
	// creating a new file: rollback removes it
	o = f.ok(t, "file.write", map[string]any{"path": "/etc/ssh/new.conf", "content": "x"}, func(r *Request) { r.Deadman = 120 * time.Millisecond })
	waitFor(t, "removal", func() bool { _, err := os.Stat(f.path("etc/ssh/new.conf")); return err != nil })
}

func TestFilePerms(t *testing.T) {
	f := newFixture(t)
	f.write(t, "etc/secret", "s", 0o644)
	o := f.ok(t, "file.perms", map[string]any{"path": "/etc/secret", "mode": "0600"}, func(r *Request) { r.Deadman = time.Minute })
	if st, _ := os.Stat(f.path("etc/secret")); st.Mode().Perm() != 0o600 {
		t.Fatal("mode not set")
	}
	if o2 := f.ok(t, "file.perms", map[string]any{"path": "/etc/secret", "mode": "0600"}); !o2.Plan.Done {
		t.Fatal("not idempotent")
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(f.path("etc/secret")); st.Mode().Perm() != 0o644 {
		t.Fatalf("rollback mode %v", st.Mode())
	}
	// setuid bit round trip
	f.ok(t, "file.perms", map[string]any{"path": "/etc/secret", "mode": "04755"})
	if st, _ := os.Stat(f.path("etc/secret")); st.Mode()&os.ModeSetuid == 0 {
		t.Fatal("setuid not set")
	}
	if _, err := f.run(t, "file.perms", map[string]any{"path": "/etc/secret"}); err == nil {
		t.Fatal("no-op perms accepted")
	}
}

func TestFileHash(t *testing.T) {
	f := newFixture(t)
	f.write(t, "etc/h", "hello", 0o644)
	sum := sha256.Sum256([]byte("hello"))
	o := f.ok(t, "file.hash", map[string]any{"path": "/etc/h"})
	if o.Output["hash"] != hex.EncodeToString(sum[:]) || o.Changed {
		t.Fatalf("%+v", o)
	}
	f.ok(t, "file.hash", map[string]any{"path": "/etc/h", "expect": strings.ToUpper(hex.EncodeToString(sum[:]))})
	if _, err := f.run(t, "file.hash", map[string]any{"path": "/etc/h", "expect": "00"}); err == nil {
		t.Fatal("mismatch accepted")
	}
	if o := f.ok(t, "file.hash", map[string]any{"path": "/etc/h", "algorithm": "sha512"}); len(o.Output["hash"]) != 128 {
		t.Fatal("sha512")
	}
	if _, err := f.run(t, "file.hash", map[string]any{"path": "/etc/missing"}); err == nil {
		t.Fatal("missing file")
	}
}

func TestQuarantineAndRestore(t *testing.T) {
	f := newFixture(t)
	f.write(t, "usr/bin/evil", "payload\x00bytes", 0o755)
	st0, _ := os.Stat(f.path("usr/bin/evil"))
	o := f.ok(t, "file.quarantine", map[string]any{"path": "/usr/bin/evil", "reason": "implant"})
	if _, err := os.Lstat(f.path("usr/bin/evil")); err == nil {
		t.Fatal("original still present")
	}
	id := o.Output["id"]
	payload := filepath.Join(f.env.QuarantineDir, id)
	if b, _ := os.ReadFile(payload); string(b) != "payload\x00bytes" {
		t.Fatalf("payload not preserved: %q", b)
	}
	var meta QuarantineMeta
	mb, err := os.ReadFile(payload + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(mb, &meta); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("payload\x00bytes"))
	if meta.OriginalPath != "/usr/bin/evil" || meta.Reason != "implant" || meta.SHA256 != hex.EncodeToString(sum[:]) ||
		meta.Mode.Perm() != 0o755 || !meta.ModTime.Equal(st0.ModTime()) || meta.Size != int64(len("payload\x00bytes")) {
		t.Fatalf("meta: %+v", meta)
	}
	// quarantining again: original gone, so nothing to do
	if o2 := f.ok(t, "file.quarantine", map[string]any{"path": "/usr/bin/evil"}); !o2.Plan.Done {
		t.Fatal("not idempotent")
	}
	// restore
	f.ok(t, "file.restore", map[string]any{"id": id})
	st1, err := os.Stat(f.path("usr/bin/evil"))
	if err != nil {
		t.Fatal(err)
	}
	if f.read(t, "usr/bin/evil") != "payload\x00bytes" || st1.Mode().Perm() != 0o755 || !st1.ModTime().Equal(st0.ModTime()) {
		t.Fatalf("restore lost metadata: %v %v", st1.Mode(), st1.ModTime())
	}
	// restore twice: done, and refuses path traversal ids
	if o := f.ok(t, "file.restore", map[string]any{"id": id}); !o.Plan.Done {
		t.Fatal("restore not idempotent")
	}
	for _, bad := range []string{"../x", "a/b", id + ".json"} {
		if _, err := f.run(t, "file.restore", map[string]any{"id": bad}); err == nil {
			t.Errorf("accepted id %q", bad)
		}
	}
}

func TestQuarantineDeadmanUndo(t *testing.T) {
	f := newFixture(t)
	f.write(t, "srv/page.html", "<html>", 0o644)
	f.ok(t, "file.quarantine", map[string]any{"path": "/srv/page.html"}, func(r *Request) { r.Deadman = 120 * time.Millisecond })
	waitFor(t, "undo", func() bool { return f.read2("srv/page.html") == "<html>" })
}

func (f *fixture) read2(rel string) string { b, _ := os.ReadFile(f.path(rel)); return string(b) }

func TestRestoreRefusesToOverwriteUnlessForce(t *testing.T) {
	f := newFixture(t)
	f.write(t, "srv/a", "orig", 0o644)
	id := f.ok(t, "file.quarantine", map[string]any{"path": "/srv/a"}).Output["id"]
	f.write(t, "srv/a", "replacement", 0o644)
	if _, err := f.run(t, "file.restore", map[string]any{"id": id}); err == nil {
		t.Fatal("overwrote existing file")
	}
	f.ok(t, "file.restore", map[string]any{"id": id, "force": true})
	if f.read(t, "srv/a") != "orig" {
		t.Fatal("force restore failed")
	}
	// the replacement was set aside, never deleted
	m, _ := filepath.Glob(f.path("srv/a.phylax-*"))
	if len(m) != 1 {
		t.Fatalf("replacement not kept aside: %v", m)
	}
}

func TestPathResolutionStaysUnderRoot(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{"/../../etc/evil", "/etc/../../evil"} {
		if got := f.env.Resolve(p); !strings.HasPrefix(got, f.root) {
			t.Fatalf("%q escaped root: %s", p, got)
		}
	}
}
