package action

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"text/template"
)

// writeWithReplace writes path atomically: temp file in the same directory,
// then rename over the target. The temp file inherits the target's mode when
// one exists; a new file gets mode (default 0644).
func writeWithReplace(path, content string, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".phylax-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if mode == 0 {
		mode = 0o644
	}
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
		copyLabel(path, tmpName) // SELinux: inherit the target's label
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// readOrEmpty returns the file content, or "" when the file is absent.
func readOrEmpty(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(b), nil
}

// copyLabel is the SELinux half of file actions: copy the target's label to
// the replacement before rename. Best effort — a no-op when SELinux is not
// enforcing or the filesystem does not carry the xattr.
func copyLabel(src, dst string) {
	if _, err := os.Stat("/sys/fs/selinux/enforce"); err != nil {
		return
	}
	b, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err != nil || string(b) != "1" {
		return
	}
	raw := make([]byte, 128)
	if n, err := syscall.Getxattr(src, "security.selinux", raw); err == nil {
		_ = syscall.Setxattr(dst, "security.selinux", raw[:n], 0)
	}
}

// fileRollbackAction applies the rollbackFile helper as an action result.
func rollbackFileAction(path string, before []byte) (CheckResult, error) {
	if err := rollbackFile(path, before); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Done: true, Diff: "restored previous content"}, nil
}

// ---- file.write -----------------------------------------------------------

type fileWrite struct{}

func (fileWrite) Name() string        { return "file.write" }
func (fileWrite) Risk() Risk          { return RiskService }
func (fileWrite) Locks() []string     { return nil }
func (fileWrite) Check(p Params) (CheckResult, error) {
	path, content := p.Get("path", ""), p.Get("content", "")
	cur, err := readOrEmpty(path)
	if err != nil {
		return CheckResult{}, err
	}
	if cur == content {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Diff: fmt.Sprintf("write %d bytes to %s", len(content), path),
		Before: []byte(Enc(cur)), After: []byte(content)}, nil
}
func (fileWrite) Apply(p Params) (CheckResult, error) {
	path, content := p.Get("path", ""), p.Get("content", "")
	if path == "" {
		return CheckResult{}, fmt.Errorf("file.write: path required")
	}
	cur, err := readOrEmpty(path)
	if err != nil {
		return CheckResult{}, err
	}
	mode := parseMode(p.Get("mode", ""))
	if err := writeWithReplace(path, content, mode); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Before: []byte(Enc(cur)), After: []byte(content)}, nil
}
func (fileWrite) Verify(p Params) (CheckResult, error) {
	path, content := p.Get("path", ""), p.Get("content", "")
	cur, err := readOrEmpty(path)
	if err != nil {
		return CheckResult{}, err
	}
	if cur != content {
		return CheckResult{Diff: fmt.Sprintf("%s: content mismatch", path)}, nil
	}
	return CheckResult{Done: true, After: []byte(cur)}, nil
}
func (fileWrite) Rollback(p Params, before []byte) (CheckResult, error) {
	return rollbackFileAction(p.Get("path", ""), before)
}

// ---- file.template --------------------------------------------------------

type fileTemplate struct{}

func (fileTemplate) Name() string   { return "file.template" }
func (fileTemplate) Risk() Risk     { return RiskService }
func (fileTemplate) Locks() []string { return nil }

func renderTemplate(p Params) (string, error) {
	tpl, err := template.New("phylax").Parse(p.Get("template", ""))
	if err != nil {
		return "", err
	}
	var vars map[string]any
	if err := p.GetJSON("vars", &vars); err != nil {
		return "", err
	}
	var sb stringWriter
	if err := tpl.Execute(&sb, vars); err != nil {
		return "", err
	}
	return sb.s, nil
}

type stringWriter struct{ s string }

func (w *stringWriter) Write(b []byte) (int, error) { w.s += string(b); return len(b), nil }

func (a fileTemplate) Check(p Params) (CheckResult, error) {
	path := p.Get("path", "")
	want, err := renderTemplate(p)
	if err != nil {
		return CheckResult{}, err
	}
	cur, err := readOrEmpty(path)
	if err != nil {
		return CheckResult{}, err
	}
	if cur == want {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Diff: fmt.Sprintf("template %s", path),
		Before: []byte(Enc(cur)), After: []byte(want)}, nil
}
func (a fileTemplate) Apply(p Params) (CheckResult, error) {
	path := p.Get("path", "")
	want, err := renderTemplate(p)
	if err != nil {
		return CheckResult{}, err
	}
	cur, err := readOrEmpty(path)
	if err != nil {
		return CheckResult{}, err
	}
	if err := writeWithReplace(path, want, parseMode(p.Get("mode", ""))); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Before: []byte(Enc(cur)), After: []byte(want)}, nil
}
func (a fileTemplate) Verify(p Params) (CheckResult, error) {
	want, err := renderTemplate(p)
	if err != nil {
		return CheckResult{}, err
	}
	cur, err := readOrEmpty(p.Get("path", ""))
	if err != nil {
		return CheckResult{}, err
	}
	if cur != want {
		return CheckResult{Diff: "template content mismatch"}, nil
	}
	return CheckResult{Done: true}, nil
}
func (a fileTemplate) Rollback(p Params, before []byte) (CheckResult, error) {
	return rollbackFileAction(p.Get("path", ""), before)
}

// ---- file.perms -----------------------------------------------------------

type filePerms struct{}

func (filePerms) Name() string    { return "file.perms" }
func (filePerms) Risk() Risk      { return RiskService }
func (filePerms) Locks() []string { return nil }
func (filePerms) Check(p Params) (CheckResult, error) {
	path, mode := p.Get("path", ""), parseMode(p.Get("mode", ""))
	if mode == 0 {
		return CheckResult{}, fmt.Errorf("file.perms: mode required")
	}
	st, err := os.Stat(path)
	if err != nil {
		return CheckResult{}, err
	}
	if st.Mode().Perm() == mode {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Diff: fmt.Sprintf("%s: %03o -> %03o", path, st.Mode().Perm(), mode),
		Before: []byte(fmt.Sprintf("%03o", st.Mode().Perm())), After: []byte(fmt.Sprintf("%03o", mode))}, nil
}
func (filePerms) Apply(p Params) (CheckResult, error) {
	path, mode := p.Get("path", ""), parseMode(p.Get("mode", ""))
	if mode == 0 {
		return CheckResult{}, fmt.Errorf("file.perms: mode required")
	}
	st, err := os.Stat(path)
	if err != nil {
		return CheckResult{}, err
	}
	if err := os.Chmod(path, mode); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Before: []byte(fmt.Sprintf("%03o", st.Mode().Perm())),
		After: []byte(fmt.Sprintf("%03o", mode))}, nil
}
func (filePerms) Verify(p Params) (CheckResult, error) {
	path, mode := p.Get("path", ""), parseMode(p.Get("mode", ""))
	if mode == 0 {
		return CheckResult{}, fmt.Errorf("file.perms: mode required")
	}
	st, err := os.Stat(path)
	if err != nil {
		return CheckResult{}, err
	}
	if st.Mode().Perm() != mode {
		return CheckResult{Diff: fmt.Sprintf("%s is %03o", path, st.Mode().Perm())}, nil
	}
	return CheckResult{Done: true}, nil
}
func (filePerms) Rollback(p Params, before []byte) (CheckResult, error) {
	mode := parseMode(string(before))
	if mode == 0 {
		return CheckResult{Done: true}, nil
	}
	if err := os.Chmod(p.Get("path", ""), mode); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Done: true, Diff: "restored previous mode"}, nil
}

// ---- file.quarantine ------------------------------------------------------

type fileQuarantine struct{}

func (fileQuarantine) Name() string   { return "file.quarantine" }
func (fileQuarantine) Risk() Risk     { return RiskDestructive }
func (fileQuarantine) Locks() []string { return nil }

func quarantineDir(p Params) string { return p.Get("dir", "/var/lib/phylax/quarantine") }

func (a fileQuarantine) Check(p Params) (CheckResult, error) {
	path := p.Get("path", "")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return CheckResult{Done: true}, nil // nothing to quarantine
	}
	return CheckResult{Diff: fmt.Sprintf("move %s to quarantine", path), Before: []byte(path)}, nil
}
func (a fileQuarantine) Apply(p Params) (CheckResult, error) {
	path := p.Get("path", "")
	qd := quarantineDir(p)
	if err := os.MkdirAll(qd, 0o700); err != nil {
		return CheckResult{}, err
	}
	dst := filepath.Join(qd, filepath.Base(path)+".quarantined")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return CheckResult{Done: true}, nil
	}
	if err := os.Rename(path, dst); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Before: []byte(path), After: []byte(dst)}, nil
}
func (a fileQuarantine) Verify(p Params) (CheckResult, error) {
	if _, err := os.Stat(p.Get("path", "")); os.IsNotExist(err) {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Diff: "file still present"}, nil
}
func (a fileQuarantine) Rollback(p Params, before []byte) (CheckResult, error) {
	src := filepath.Join(quarantineDir(p), filepath.Base(string(before))+".quarantined")
	if err := os.Rename(src, string(before)); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Done: true, Diff: "restored from quarantine"}, nil
}

// ---- file.restore ---------------------------------------------------------

type fileRestore struct{}

func (fileRestore) Name() string   { return "file.restore" }
func (fileRestore) Risk() Risk     { return RiskService }
func (fileRestore) Locks() []string { return nil }
func (fileRestore) Check(p Params) (CheckResult, error) {
	path, content := p.Get("path", ""), p.Get("content", "")
	cur, err := readOrEmpty(path)
	if err != nil {
		return CheckResult{}, err
	}
	if cur == content {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Diff: fmt.Sprintf("restore %s from golden copy", path),
		Before: []byte(Enc(cur)), After: []byte(content)}, nil
}
func (fileRestore) Apply(p Params) (CheckResult, error) {
	path, content := p.Get("path", ""), p.Get("content", "")
	cur, err := readOrEmpty(path)
	if err != nil {
		return CheckResult{}, err
	}
	if err := writeWithReplace(path, content, parseMode(p.Get("mode", ""))); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Before: []byte(Enc(cur)), After: []byte(content)}, nil
}
func (fileRestore) Verify(p Params) (CheckResult, error) {
	cur, err := readOrEmpty(p.Get("path", ""))
	if err != nil {
		return CheckResult{}, err
	}
	if cur != p.Get("content", "") {
		return CheckResult{Diff: "content mismatch"}, nil
	}
	return CheckResult{Done: true}, nil
}
func (fileRestore) Rollback(p Params, before []byte) (CheckResult, error) {
	return rollbackFileAction(p.Get("path", ""), before)
}

// ---- file.hash --------------------------------------------------------------

type fileHash struct{}

func (fileHash) Name() string   { return "file.hash" }
func (fileHash) Risk() Risk     { return RiskNone }
func (fileHash) Locks() []string { return nil }
func (fileHash) Check(p Params) (CheckResult, error) {
	path := p.Get("path", "")
	b, err := os.ReadFile(path)
	if err != nil {
		return CheckResult{}, err
	}
	sum := HashBytes(b)
	want := p.Get("sha256", "")
	detail := fmt.Sprintf("%s sha256[:12]=%s", path, sum)
	if want != "" && fullSHA(b) != want {
		return CheckResult{Diff: fmt.Sprintf("%s: hash mismatch (want %s)", path, want[:12])}, nil
	}
	return CheckResult{Done: true, Diff: detail, After: b}, nil
}
func (a fileHash) Apply(p Params) (CheckResult, error) { return a.Check(p) }
func (a fileHash) Verify(p Params) (CheckResult, error) {
	return a.Check(p)
}
func (a fileHash) Rollback(_ Params, _ []byte) (CheckResult, error) {
	return CheckResult{Done: true}, nil
}

// ---- dir.snapshot -----------------------------------------------------------

// dirSnapshot captures a directory as a JSON file listing (path, size,
// sha256[:12]) — small enough to carry as node state, and enough to detect
// drift against the captured listing.
type dirSnapshot struct{}

func (dirSnapshot) Name() string   { return "dir.snapshot" }
func (dirSnapshot) Risk() Risk     { return RiskNone }
func (dirSnapshot) Locks() []string { return nil }

func snapList(path string) ([]byte, error) {
	type entry struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
		SHA  string `json:"sha"`
	}
	var entries []entry
	err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		st, err := d.Info()
		if err != nil {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		entries = append(entries, entry{Path: p, Size: st.Size(), SHA: HashBytes(b)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return marshalJSON(entries)
}

func (a dirSnapshot) Check(p Params) (CheckResult, error) {
	b, err := snapList(p.Get("path", ""))
	if err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Done: true, After: b}, nil
}
func (a dirSnapshot) Apply(p Params) (CheckResult, error) {
	b, err := snapList(p.Get("path", ""))
	if err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Before: b}, nil
}
func (a dirSnapshot) Verify(p Params) (CheckResult, error) {
	cur, err := snapList(p.Get("path", ""))
	if err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Done: true, After: cur}, nil
}
func (a dirSnapshot) Rollback(_ Params, _ []byte) (CheckResult, error) {
	return CheckResult{Done: true}, nil
}

func parseMode(s string) os.FileMode {
	if s == "" {
		return 0
	}
	var m os.FileMode
	if _, err := fmt.Sscanf(s, "%o", &m); err != nil {
		return 0
	}
	return m
}
