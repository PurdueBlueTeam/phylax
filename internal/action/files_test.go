package action

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileWriteApplyVerifyRollback(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "conf.d", "svc.conf")
	params := map[string]any{"path": p, "content": "listen 8443\n"}

	a := fileWrite{}
	r, err := a.Check(Params(params))
	if err != nil {
		t.Fatal(err)
	}
	if r.Done || r.Diff == "" {
		t.Fatalf("expected a diff, got %+v", r)
	}
	firstBefore := r.Before
	if _, err := a.Apply(Params(params)); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != "listen 8443\n" {
		t.Fatalf("file content = %q err=%v", b, err)
	}
	r, err = a.Verify(Params(params))
	if err != nil || !r.Done {
		t.Fatalf("verify: %+v err=%v", r, err)
	}
	// idempotent check
	if r, _ = a.Check(Params(params)); !r.Done {
		t.Fatalf("expected idempotent check, got %+v", r)
	}
	// rollback restores the (empty) original captured by the first check
	if _, err := a.Rollback(Params(params), firstBefore); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(p); err == nil && string(b) != "" {
		t.Fatalf("rollback left content %q", b)
	}
}

func TestFileWritePreservesModeOnReplace(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "locked")
	if err := os.WriteFile(p, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	a := fileWrite{}
	if _, err := a.Apply(Params(map[string]any{"path": p, "content": "new"})); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o640 {
		t.Fatalf("mode = %v, want 0640", got)
	}
}

func TestFileTemplate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nginx.conf")
	params := Params(map[string]any{
		"path":     p,
		"template": "server { listen {{ .port }}; }",
		"vars":     map[string]any{"port": 8080},
	})
	a := fileTemplate{}
	if r, err := a.Check(params); err == nil && r.Done {
		t.Fatal("expected diff on missing file")
	} else if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(params); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "server { listen 8080; }" {
		t.Fatalf("rendered %q", b)
	}
	r, err := a.Verify(params)
	if err != nil || !r.Done {
		t.Fatalf("verify: %+v %v", r, err)
	}
}

func TestFilePermsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "script")
	if err := os.WriteFile(p, []byte("x"), 0o777); err != nil {
		t.Fatal(err)
	}
	a := filePerms{}
	st0, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	orig := st0.Mode().Perm()
	if orig == 0o755 {
		t.Skip("umask made the file already 0755")
	}
	params := Params(map[string]any{"path": p, "mode": "0755"})
	r, err := a.Check(params)
	if err != nil || r.Done {
		t.Fatalf("expected diff, got %+v %v", r, err)
	}
	firstBefore := r.Before
	if _, err := a.Apply(params); err != nil {
		t.Fatal(err)
	}
	if r, _ = a.Check(params); !r.Done {
		t.Fatal("expected idempotent")
	}
	if _, err := a.Rollback(params, firstBefore); err != nil {
		t.Fatal(err)
	}
	// rollback restored the pre-apply mode
	st, _ := os.Stat(p)
	if st.Mode().Perm() != orig {
		t.Fatalf("rollback mode = %v, want %v", st.Mode().Perm(), orig)
	}
}

func TestFileQuarantineRollback(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "malware")
	qd := filepath.Join(dir, "quarantine")
	if err := os.WriteFile(p, []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	params := Params(map[string]any{"path": p, "dir": qd})
	a := fileQuarantine{}
	r, err := a.Check(params)
	if err != nil || r.Done || r.Before == nil {
		t.Fatalf("check: %+v %v", r, err)
	}
	if _, err := a.Apply(params); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("file still present after quarantine")
	}
	if r, _ := a.Verify(params); !r.Done {
		t.Fatal("verify should pass")
	}
	if _, err := a.Rollback(params, r.Before); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "bad" {
		t.Fatalf("restore: %q %v", b, err)
	}
}

func TestFileHashMismatch(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bin")
	if err := os.WriteFile(p, []byte("elf"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := fileHash{}
	full := fullSHA([]byte("elf"))
	r, err := a.Check(Params(map[string]any{"path": p, "sha256": full}))
	if err != nil || !r.Done {
		t.Fatalf("matching hash: %+v %v", r, err)
	}
	r, err = a.Check(Params(map[string]any{"path": p, "sha256": strings.Repeat("0", 64)}))
	if err != nil || r.Done {
		t.Fatalf("want mismatch, got %+v %v", r, err)
	}
}

func TestDirSnapshotDetectsDrift(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := dirSnapshot{}
	r1, err := a.Check(Params(map[string]any{"path": dir}))
	if err != nil || !r1.Done || r1.After == nil {
		t.Fatalf("snap1: %+v %v", r1, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("2"), 0o644); err != nil {
		t.Fatal(err)
	}
	r2, err := a.Check(Params(map[string]any{"path": dir}))
	if err != nil {
		t.Fatal(err)
	}
	if string(r1.After) == string(r2.After) {
		t.Fatal("snapshot did not detect content change")
	}
}
