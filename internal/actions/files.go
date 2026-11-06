package actions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

const maxFileBytes = 16 << 20

func coreActions() []Action {
	acts := []Action{
		fileWrite{name: "file.write"}, fileWrite{name: "file.template", tmpl: true},
		filePerms{}, fileQuarantine{}, fileRestore{}, fileHash{},
		userSetPassword{}, userLock{}, userCreate{}, userDelete{}, groupMembers{}, sshAuthorizedKeys{},
		serviceState{name: "service.state"},
	}
	for _, op := range serviceOps {
		acts = append(acts, serviceState{name: "service." + op, op: op})
	}
	return acts
}

func pathTouch(path, op string) Touch { return Touch{Kind: TouchPath, Name: path, Op: op} }

func readBounded(path string) ([]byte, fs.FileInfo, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, st, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Size() > maxFileBytes {
		return nil, st, fmt.Errorf("%s larger than %d bytes", path, maxFileBytes)
	}
	b, err := os.ReadFile(path)
	return b, st, err
}

func snapshotRollback(paths ...string) (Rollback, error) {
	fr, err := deadman.SnapshotFiles(paths...)
	if err != nil {
		return Rollback{}, err
	}
	return Rollback{Kind: deadman.KindFileRestore, Data: fr}, nil
}

func applyOwner(path string, p Params) error {
	uid, hu := p.Int("uid")
	gid, hg := p.Int("gid")
	if !hu {
		uid = -1
	}
	if !hg {
		gid = -1
	}
	if !hu && !hg {
		return nil
	}
	return os.Lchown(path, uid, gid)
}

func ownerDiff(st fs.FileInfo, p Params) []string {
	var d []string
	u, g, ok := ownerOf(st)
	if !ok {
		return nil
	}
	if want, has := p.Int("uid"); has && want != u {
		d = append(d, fmt.Sprintf("uid %d -> %d", u, want))
	}
	if want, has := p.Int("gid"); has && want != g {
		d = append(d, fmt.Sprintf("gid %d -> %d", g, want))
	}
	return d
}

var (
	pathParam = ParamSpec{Name: "path", Type: Path, Required: true}
	modeParam = ParamSpec{Name: "mode", Type: Mode}
	uidParam  = ParamSpec{Name: "uid", Type: Int}
	gidParam  = ParamSpec{Name: "gid", Type: Int}
)

// ---- file.write / file.template ----

type fileWrite struct {
	name string
	tmpl bool
}

func (f fileWrite) Spec() Spec {
	s := Spec{Name: f.name, Risk: RiskService, Doc: "Atomically write a file (keeps owner, mode and SELinux label of an existing file)."}
	s.Params = []ParamSpec{pathParam, modeParam, uidParam, gidParam}
	if f.tmpl {
		s.Doc = "Render a text/template and write it atomically."
		s.Params = append(s.Params,
			ParamSpec{Name: "template", Type: String, Required: true, Max: maxFileBytes},
			ParamSpec{Name: "vars", Type: StringMap})
	} else {
		s.Params = append(s.Params,
			ParamSpec{Name: "content", Type: String, Max: maxFileBytes},
			ParamSpec{Name: "content_b64", Type: String, Max: maxFileBytes * 2},
		)
	}
	return s
}

func (fileWrite) Locks(p Params) []string  { return lockForPath(p.Str("path")) }
func (fileWrite) Touches(p Params) []Touch { return []Touch{pathTouch(p.Str("path"), OpModify)} }

func (f fileWrite) content(env *Env, p Params) ([]byte, error) {
	if f.tmpl {
		t, err := template.New("file").Option("missingkey=error").Parse(p.Str("template"))
		if err != nil {
			return nil, fmt.Errorf("template: %w", err)
		}
		data := map[string]any{"Host": env.Host, "Vars": p.Map("vars")}
		for k, v := range p.Map("vars") {
			data[k] = v
		}
		var buf bytes.Buffer
		if err := t.Execute(&limitedWriter{w: &buf, n: maxFileBytes}, data); err != nil {
			return nil, fmt.Errorf("template: %w", err)
		}
		return buf.Bytes(), nil
	}
	if p.Has("content") == p.Has("content_b64") {
		return nil, errors.New("exactly one of content and content_b64 is required")
	}
	if p.Has("content_b64") {
		return base64.StdEncoding.DecodeString(p.Str("content_b64"))
	}
	return []byte(p.Str("content")), nil
}

type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(b []byte) (int, error) {
	if len(b) > l.n {
		return 0, errors.New("output too large")
	}
	l.n -= len(b)
	return l.w.Write(b)
}

func (f fileWrite) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	want, err := f.content(env, p)
	if err != nil {
		return Plan{}, err
	}
	path := env.Resolve(p.Str("path"))
	old, st, err := readBounded(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Plan{Diff: "create " + p.Str("path") + "\n" + renderDiff(nil, want)}, nil
	}
	if err != nil {
		return Plan{}, err
	}
	var parts []string
	if !bytes.Equal(old, want) {
		parts = append(parts, renderDiff(old, want))
	}
	if m, ok := p.FileMode("mode"); ok && st.Mode().Perm() != m.Perm() {
		parts = append(parts, fmt.Sprintf("mode %04o -> %04o", st.Mode().Perm(), m.Perm()))
	}
	parts = append(parts, ownerDiff(st, p)...)
	if len(parts) == 0 {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: strings.Join(parts, "\n")}, nil
}

func renderDiff(old, new []byte) string {
	if !isText(old) || !isText(new) {
		return fmt.Sprintf("binary content: %d bytes (sha256 %x) -> %d bytes (sha256 %x)",
			len(old), sha256.Sum256(old), len(new), sha256.Sum256(new))
	}
	return lineDiff(string(old), string(new))
}

func (fileWrite) Capture(_ context.Context, env *Env, p Params) (Rollback, error) {
	return snapshotRollback(env.Resolve(p.Str("path")))
}

func (f fileWrite) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	want, err := f.content(env, p)
	if err != nil {
		return nil, err
	}
	path := env.Resolve(p.Str("path"))
	perm, hasMode := p.FileMode("mode")
	if !hasMode {
		perm = 0o644
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := atomicfile.WriteFile(path, want, perm.Perm()); err != nil {
		return nil, err
	}
	if hasMode {
		if err := os.Chmod(path, perm); err != nil {
			return nil, err
		}
	}
	return nil, applyOwner(path, p)
}

func (f fileWrite) Verify(_ context.Context, env *Env, p Params) error {
	want, err := f.content(env, p)
	if err != nil {
		return err
	}
	got, st, err := readBounded(env.Resolve(p.Str("path")))
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return errors.New("content differs after write")
	}
	if m, ok := p.FileMode("mode"); ok && st.Mode().Perm() != m.Perm() {
		return fmt.Errorf("mode is %04o, want %04o", st.Mode().Perm(), m.Perm())
	}
	return nil
}

// ---- file.perms ----

type filePerms struct{}

func (filePerms) Spec() Spec {
	return Spec{Name: "file.perms", Risk: RiskService, Doc: "Set mode and/or owner of a file or directory.",
		Params: []ParamSpec{pathParam, modeParam, uidParam, gidParam}}
}
func (filePerms) Locks(p Params) []string  { return lockForPath(p.Str("path")) }
func (filePerms) Touches(p Params) []Touch { return []Touch{pathTouch(p.Str("path"), OpModify)} }
func (filePerms) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	if !p.Has("mode") && !p.Has("uid") && !p.Has("gid") {
		return Plan{}, errors.New("one of mode, uid, gid is required")
	}
	st, err := os.Lstat(env.Resolve(p.Str("path")))
	if err != nil {
		return Plan{}, err
	}
	var d []string
	if m, ok := p.FileMode("mode"); ok && st.Mode()&(fs.ModePerm|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != permBits(m) {
		d = append(d, fmt.Sprintf("mode %04o -> %04o", permBits(st.Mode()), m))
	}
	d = append(d, ownerDiff(st, p)...)
	if len(d) == 0 {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: strings.Join(d, "\n")}, nil
}

// permBits converts the traditional octal mode (with 04000/02000/01000) to Go bits.
func permBits(m fs.FileMode) fs.FileMode {
	out := m & fs.ModePerm
	if m&0o4000 != 0 {
		out |= fs.ModeSetuid
	}
	if m&0o2000 != 0 {
		out |= fs.ModeSetgid
	}
	if m&0o1000 != 0 {
		out |= fs.ModeSticky
	}
	return out | (m & (fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky))
}

type permSnap struct {
	Path string      `json:"path"`
	Mode fs.FileMode `json:"mode"`
	UID  int         `json:"uid"`
	GID  int         `json:"gid"`
}

const kindPerms = "file.perms"

func (filePerms) Capture(_ context.Context, env *Env, p Params) (Rollback, error) {
	path := env.Resolve(p.Str("path"))
	st, err := os.Lstat(path)
	if err != nil {
		return Rollback{}, err
	}
	u, g, _ := ownerOf(st)
	return Rollback{Kind: kindPerms, Data: permSnap{Path: path, Mode: st.Mode() & (fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky), UID: u, GID: g}}, nil
}

func undoPerms(_ context.Context, e deadman.Entry) error {
	var s permSnap
	if err := json.Unmarshal(e.Data, &s); err != nil {
		return err
	}
	if err := os.Lchown(s.Path, s.UID, s.GID); err != nil {
		return err
	}
	return os.Chmod(s.Path, s.Mode)
}
func (filePerms) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	path := env.Resolve(p.Str("path"))
	if err := applyOwner(path, p); err != nil {
		return nil, err
	}
	if m, ok := p.FileMode("mode"); ok { // chmod after chown: chown clears setuid
		return nil, os.Chmod(path, permBits(m))
	}
	return nil, nil
}
func (filePerms) Verify(_ context.Context, env *Env, p Params) error {
	st, err := os.Stat(env.Resolve(p.Str("path")))
	if err != nil {
		return err
	}
	if m, ok := p.FileMode("mode"); ok && st.Mode()&(fs.ModePerm|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != permBits(m) {
		return errors.New("mode not applied")
	}
	if len(ownerDiff(st, p)) > 0 {
		return errors.New("owner not applied")
	}
	return nil
}

// ---- file.hash ----

type fileHash struct{}

func (fileHash) Spec() Spec {
	return Spec{Name: "file.hash", Risk: RiskNone, ReadOnly: true, Doc: "Hash a file; optionally require it to match `expect`.",
		Params: []ParamSpec{pathParam,
			{Name: "algorithm", Type: Enum, Enum: []string{"sha256", "sha512"}, Default: "sha256"},
			{Name: "expect", Type: String, Max: 256}}}
}
func (fileHash) Locks(Params) []string  { return nil }
func (fileHash) Touches(Params) []Touch { return nil }
func (fileHash) Plan(context.Context, *Env, Params) (Plan, error) {
	return Plan{Diff: "read-only"}, nil
}
func (fileHash) Capture(context.Context, *Env, Params) (Rollback, error) { return Rollback{}, nil }

func hashFile(path, alg string) (string, error) {
	var h hash.Hash = sha256.New()
	if alg == "sha512" {
		h = sha512.New()
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (fileHash) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	sum, err := hashFile(env.Resolve(p.Str("path")), p.Str("algorithm"))
	if err != nil {
		return nil, err
	}
	return Output{"hash": sum, "algorithm": p.Str("algorithm")}, nil
}
func (fileHash) Verify(ctx context.Context, env *Env, p Params) error {
	if !p.Has("expect") {
		return nil
	}
	sum, err := hashFile(env.Resolve(p.Str("path")), p.Str("algorithm"))
	if err != nil {
		return err
	}
	if !strings.EqualFold(sum, p.Str("expect")) {
		return fmt.Errorf("hash %s does not match expected %s", sum, p.Str("expect"))
	}
	return nil
}

// ---- file.quarantine / file.restore ----

// QuarantineMeta is the sidecar written next to every quarantined file.
type QuarantineMeta struct {
	OriginalPath  string      `json:"original_path"`
	Mode          fs.FileMode `json:"mode"`
	UID           int         `json:"uid"`
	GID           int         `json:"gid"`
	ModTime       time.Time   `json:"mod_time"`
	Size          int64       `json:"size"`
	SHA256        string      `json:"sha256,omitempty"`
	Symlink       string      `json:"symlink,omitempty"`
	IsDir         bool        `json:"is_dir,omitempty"`
	QuarantinedAt time.Time   `json:"quarantined_at"`
	Tag           Tag         `json:"tag"`
	Reason        string      `json:"reason,omitempty"`
}

const kindQuarantineUndo = "file.quarantine.undo"

type quarantineUndo struct {
	Original string `json:"original"`
	Payload  string `json:"payload"`
}

type fileQuarantine struct{}

func (fileQuarantine) Spec() Spec {
	return Spec{Name: "file.quarantine", Risk: RiskService, Doc: "Move a file into the quarantine directory with its metadata. Never deletes.",
		Params: []ParamSpec{pathParam, {Name: "reason", Type: String, Max: 1024}}}
}
func (fileQuarantine) Locks(p Params) []string { return lockForPath(p.Str("path")) }
func (fileQuarantine) Touches(p Params) []Touch {
	return []Touch{pathTouch(p.Str("path"), OpQuarantine)}
}
func (fileQuarantine) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	if env.QuarantineDir == "" {
		return Plan{}, errors.New("no quarantine directory configured")
	}
	_, err := os.Lstat(env.Resolve(p.Str("path")))
	if errors.Is(err, fs.ErrNotExist) {
		return Plan{Done: true}, nil // already gone from the original location
	}
	if err != nil {
		return Plan{}, err
	}
	return Plan{Diff: "quarantine " + p.Str("path")}, nil
}

// quarantineID is deterministic in the file's identity so Capture (which arms
// the dead-man) and Apply agree on the payload name without shared state.
func quarantineID(src string, st fs.FileInfo) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%d|%d|%d", src, st.Mode(), st.Size(), st.ModTime().UnixNano())
	if st.Mode().IsRegular() {
		if sum, err := hashFile(src, "sha256"); err == nil {
			h.Write([]byte(sum))
		}
	} else if st.Mode()&fs.ModeSymlink != 0 {
		l, _ := os.Readlink(src)
		h.Write([]byte(l))
	}
	return fmt.Sprintf("%s-%s", safeBase(src), hex.EncodeToString(h.Sum(nil)[:10]))
}

func safeBase(p string) string {
	b := filepath.Base(filepath.FromSlash(p))
	var sb strings.Builder
	for _, r := range b {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			sb.WriteRune(r)
		} else {
			sb.WriteByte('_')
		}
	}
	s := strings.TrimLeft(sb.String(), ".")
	if s == "" {
		s = "file"
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

func (fileQuarantine) Capture(_ context.Context, env *Env, p Params) (Rollback, error) {
	src := env.Resolve(p.Str("path"))
	st, err := os.Lstat(src)
	if err != nil {
		return Rollback{}, err
	}
	return Rollback{Kind: kindQuarantineUndo, Data: quarantineUndo{
		Original: src, Payload: filepath.Join(env.QuarantineDir, quarantineID(src, st))}}, nil
}

func (fileQuarantine) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	src := env.Resolve(p.Str("path"))
	st, err := os.Lstat(src)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(env.QuarantineDir, 0o700); err != nil {
		return nil, err
	}
	id := quarantineID(src, st)
	dst := filepath.Join(env.QuarantineDir, id)
	meta := QuarantineMeta{OriginalPath: p.Str("path"), Mode: st.Mode(), ModTime: st.ModTime(), Size: st.Size(),
		QuarantinedAt: env.Now(), Reason: p.Str("reason"), IsDir: st.IsDir()}
	meta.UID, meta.GID, _ = ownerOf(st)
	if st.Mode()&fs.ModeSymlink != 0 {
		meta.Symlink, _ = os.Readlink(src)
	} else if st.Mode().IsRegular() {
		meta.SHA256, _ = hashFile(src, "sha256")
	}
	// Metadata first: a payload without metadata would be unrecoverable.
	mb, _ := json.MarshalIndent(meta, "", "  ")
	if err := atomicfile.WriteFile(dst+".json", mb, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(src, dst); err != nil {
		if !errors.Is(err, syscall.EXDEV) || !st.Mode().IsRegular() {
			os.Remove(dst + ".json")
			return nil, err
		}
		// Cross-device: copy, fsync, then unlink the original (a move, not a delete).
		b, rerr := os.ReadFile(src)
		if rerr == nil {
			rerr = atomicfile.WriteFile(dst, b, 0o600)
		}
		if rerr == nil {
			if got, _ := hashFile(dst, "sha256"); got != meta.SHA256 {
				rerr = errors.New("copy verification failed")
			}
		}
		if rerr != nil {
			os.Remove(dst + ".json")
			return nil, rerr
		}
		if err := os.Remove(src); err != nil {
			return nil, err
		}
	}
	return Output{"id": id, "path": dst}, nil
}
func (fileQuarantine) Verify(_ context.Context, env *Env, p Params) error {
	if _, err := os.Lstat(env.Resolve(p.Str("path"))); err == nil {
		return errors.New("file still present at original path")
	}
	return nil
}

func undoQuarantine(_ context.Context, e deadman.Entry) error {
	var u quarantineUndo
	if err := json.Unmarshal(e.Data, &u); err != nil {
		return err
	}
	return moveBack(u.Payload, u.Original)
}

func moveBack(payload, orig string) error {
	if _, err := os.Lstat(payload); errors.Is(err, fs.ErrNotExist) {
		return nil // already restored
	}
	if _, err := os.Lstat(orig); err == nil {
		return fmt.Errorf("%s exists; not overwriting", orig)
	}
	if err := os.MkdirAll(filepath.Dir(orig), 0o755); err != nil {
		return err
	}
	return os.Rename(payload, orig)
}

type fileRestore struct{}

func (fileRestore) Spec() Spec {
	return Spec{Name: "file.restore", Risk: RiskService, Doc: "Restore a quarantined file (id from file.quarantine) to its original path.",
		Params: []ParamSpec{
			{Name: "id", Type: String, Required: true, Max: 200, Check: validQID},
			{Name: "to", Type: Path},
			{Name: "force", Type: Bool}}}
}

func validQID(v any) error {
	s := v.(string)
	if s == "" || strings.ContainsAny(s, `/\`) || strings.Contains(s, "..") || strings.HasSuffix(s, ".json") {
		return errors.New("invalid quarantine id")
	}
	return nil
}

func (fileRestore) loadMeta(env *Env, p Params) (QuarantineMeta, string, error) {
	var m QuarantineMeta
	payload := filepath.Join(env.QuarantineDir, p.Str("id"))
	b, err := os.ReadFile(payload + ".json")
	if err != nil {
		return m, "", fmt.Errorf("quarantine metadata: %w", err)
	}
	return m, payload, json.Unmarshal(b, &m)
}

func (r fileRestore) target(env *Env, p Params, m QuarantineMeta) string {
	if p.Has("to") {
		return p.Str("to")
	}
	return m.OriginalPath
}

func (r fileRestore) Locks(p Params) []string { return nil }
func (r fileRestore) Touches(p Params) []Touch {
	if p.Has("to") {
		return []Touch{pathTouch(p.Str("to"), OpModify)}
	}
	return nil // original path is only known from metadata; checked in Plan
}
func (r fileRestore) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	m, payload, err := r.loadMeta(env, p)
	if err != nil {
		return Plan{}, err
	}
	if err := env.guard().Allow(ctx, pathTouch(r.target(env, p, m), OpModify)); err != nil {
		return Plan{}, err
	}
	if _, err := os.Lstat(payload); errors.Is(err, fs.ErrNotExist) {
		if _, err := os.Lstat(env.Resolve(r.target(env, p, m))); err == nil {
			return Plan{Done: true}, nil
		}
		return Plan{}, errors.New("quarantined payload is missing")
	}
	if _, err := os.Lstat(env.Resolve(r.target(env, p, m))); err == nil && !p.Bool("force") {
		return Plan{}, fmt.Errorf("%s exists; use force to move it aside", r.target(env, p, m))
	}
	return Plan{Diff: fmt.Sprintf("restore %s -> %s", p.Str("id"), r.target(env, p, m))}, nil
}
func (fileRestore) Capture(context.Context, *Env, Params) (Rollback, error) { return Rollback{}, nil }
func (r fileRestore) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	m, payload, err := r.loadMeta(env, p)
	if err != nil {
		return nil, err
	}
	dst := env.Resolve(r.target(env, p, m))
	if _, err := os.Lstat(dst); err == nil { // force: never delete, set the current file aside
		aside := dst + ".phylax-" + env.Now().UTC().Format("20060102T150405")
		if err := os.Rename(dst, aside); err != nil {
			return nil, err
		}
	}
	if err := moveBack(payload, dst); err != nil {
		return nil, err
	}
	if m.Symlink == "" {
		_ = os.Chmod(dst, permBits(m.Mode))
		_ = os.Lchown(dst, m.UID, m.GID)
		_ = os.Chtimes(dst, m.ModTime, m.ModTime)
	}
	return Output{"path": dst}, nil
}
func (r fileRestore) Verify(_ context.Context, env *Env, p Params) error {
	m, _, err := r.loadMeta(env, p)
	if err != nil {
		return err
	}
	st, err := os.Lstat(env.Resolve(r.target(env, p, m)))
	if err != nil {
		return err
	}
	if m.SHA256 != "" && st.Mode().IsRegular() {
		if got, _ := hashFile(env.Resolve(r.target(env, p, m)), "sha256"); got != m.SHA256 {
			return errors.New("restored file hash differs from quarantine metadata")
		}
	}
	return nil
}
