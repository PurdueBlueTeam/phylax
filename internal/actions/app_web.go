package actions

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

// ---- web.remove_dir ----

var webRootNames = map[string]bool{"html": true, "www": true, "htdocs": true, "public_html": true, "wwwroot": true}

func checkWebDir(s string) error {
	if path.Clean(s) != s {
		return errors.New("path is not clean")
	}
	parts := strings.Split(strings.Trim(s, "/"), "/")
	if len(parts) < 3 || webRootNames[parts[len(parts)-1]] {
		return errors.New("refusing a top-level or document-root directory")
	}
	return nil
}

type webRemoveDir struct{}

func (webRemoveDir) Spec() Spec {
	return Spec{Name: "web.remove_dir", Risk: RiskService,
		Doc: "Move a web directory (e.g. OpenCart install/) to quarantine. Never deletes; never the document root; refused on scored content.",
		Params: []ParamSpec{{Name: "path", Type: Path, Required: true, Check: func(v any) error { return checkWebDir(v.(string)) }},
			{Name: "reason", Type: String, Max: 1024}}}
}
func (webRemoveDir) q(p Params) (Params, error) {
	reason := p.Str("reason")
	if reason == "" {
		reason = "web.remove_dir"
	}
	return fileQuarantine{}.Spec().Validate(map[string]any{"path": p.Str("path"), "reason": reason})
}
func (webRemoveDir) Locks(Params) []string { return nil }
func (webRemoveDir) Touches(p Params) []Touch {
	return []Touch{pathTouch(p.Str("path"), OpQuarantine)}
}
func (w webRemoveDir) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	st, err := os.Lstat(env.Resolve(p.Str("path")))
	if err == nil && !st.IsDir() {
		return Plan{}, errors.New("not a directory")
	}
	q, err := w.q(p)
	if err != nil {
		return Plan{}, err
	}
	return fileQuarantine{}.Plan(ctx, env, q)
}
func (w webRemoveDir) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	q, err := w.q(p)
	if err != nil {
		return Rollback{}, err
	}
	return fileQuarantine{}.Capture(ctx, env, q)
}
func (w webRemoveDir) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	q, err := w.q(p)
	if err != nil {
		return nil, err
	}
	return fileQuarantine{}.Apply(ctx, env, q)
}
func (w webRemoveDir) Verify(ctx context.Context, env *Env, p Params) error {
	q, err := w.q(p)
	if err != nil {
		return err
	}
	return fileQuarantine{}.Verify(ctx, env, q)
}

// ---- web.rename_dir ----

const kindRenameUndo = "web.rename.undo"

type renameUndo struct {
	From, To   string // real paths
	ConfigRel  string `json:"config_rel,omitempty"`
	ConfigData []byte `json:"config_data,omitempty"`
	ConfigMode fs.FileMode
}

type webRenameDir struct{}

func (webRenameDir) Spec() Spec {
	chk := func(v any) error { return checkWebDir(v.(string)) }
	return Spec{Name: "web.rename_dir", Risk: RiskService,
		Doc:    "Rename a web directory within its parent (e.g. the OpenCart admin directory) and fix HTTP_SERVER/HTTPS_SERVER and absolute-path references in its config.php. Refused when either path is scored content.",
		Params: []ParamSpec{{Name: "path", Type: Path, Required: true, Check: chk}, {Name: "to", Type: Path, Required: true, Check: chk}}}
}
func (webRenameDir) Locks(Params) []string { return nil }
func (webRenameDir) Touches(p Params) []Touch {
	return []Touch{pathTouch(p.Str("path"), OpRename), pathTouch(p.Str("to"), OpModify)}
}

func fixConfigRefs(src, oldAbs, newAbs, oldName, newName string) (string, int) {
	n := 0
	lines := strings.Split(src, "\n")
	for i, l := range lines {
		orig := l
		if strings.Contains(l, oldAbs) {
			l = strings.ReplaceAll(l, oldAbs, newAbs)
		}
		if strings.Contains(l, "'HTTP_SERVER'") || strings.Contains(l, "'HTTPS_SERVER'") || strings.Contains(l, `"HTTP_SERVER"`) || strings.Contains(l, `"HTTPS_SERVER"`) {
			if idx := strings.LastIndex(l, "/"+oldName+"/"); idx >= 0 {
				l = l[:idx] + "/" + newName + "/" + l[idx+len(oldName)+2:]
			}
		}
		if l != orig {
			lines[i] = l
			n++
		}
	}
	return strings.Join(lines, "\n"), n
}

func (webRenameDir) check(p Params) error {
	if path.Dir(p.Str("path")) != path.Dir(p.Str("to")) {
		return errors.New("rename must stay inside the same parent directory")
	}
	if p.Str("path") == p.Str("to") {
		return errors.New("path and to are the same")
	}
	return nil
}

func (w webRenameDir) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	if err := w.check(p); err != nil {
		return Plan{}, err
	}
	src, dst := env.Resolve(p.Str("path")), env.Resolve(p.Str("to"))
	sst, serr := os.Lstat(src)
	_, derr := os.Lstat(dst)
	switch {
	case errors.Is(serr, fs.ErrNotExist) && derr == nil:
		return Plan{Done: true}, nil
	case serr != nil:
		return Plan{}, serr
	case !sst.IsDir():
		return Plan{}, errors.New("not a directory")
	case derr == nil:
		return Plan{}, fmt.Errorf("%s already exists", p.Str("to"))
	}
	diff := fmt.Sprintf("rename %s -> %s", p.Str("path"), p.Str("to"))
	if b, _, err := readBounded(filepath.Join(src, "config.php")); err == nil {
		out, n := fixConfigRefs(string(b), p.Str("path"), p.Str("to"), path.Base(p.Str("path")), path.Base(p.Str("to")))
		if n > 0 {
			diff += fmt.Sprintf("\nupdate %d reference line(s) in %s/config.php:\n%s", n, p.Str("to"), lineDiff(string(b), out))
		}
	}
	return Plan{Diff: diff}, nil
}

func (webRenameDir) Capture(_ context.Context, env *Env, p Params) (Rollback, error) {
	u := renameUndo{From: env.Resolve(p.Str("path")), To: env.Resolve(p.Str("to"))}
	if b, st, err := readBounded(filepath.Join(u.From, "config.php")); err == nil {
		u.ConfigRel, u.ConfigData, u.ConfigMode = "config.php", b, st.Mode().Perm()
	}
	return Rollback{Kind: kindRenameUndo, Data: u}, nil
}

func undoRename(_ context.Context, e deadman.Entry) error {
	var u renameUndo
	if err := json.Unmarshal(e.Data, &u); err != nil {
		return err
	}
	if _, err := os.Lstat(u.To); err == nil {
		if _, err := os.Lstat(u.From); err == nil {
			return fmt.Errorf("%s exists; not overwriting", u.From)
		}
		if err := os.Rename(u.To, u.From); err != nil {
			return err
		}
	}
	if u.ConfigRel != "" {
		return atomicfile.WriteExactMode(filepath.Join(u.From, u.ConfigRel), u.ConfigData, u.ConfigMode)
	}
	return nil
}

func (webRenameDir) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	src, dst := env.Resolve(p.Str("path")), env.Resolve(p.Str("to"))
	if err := os.Rename(src, dst); err != nil {
		return nil, err
	}
	cfg := filepath.Join(dst, "config.php")
	b, st, err := readBounded(cfg)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Output{"references_fixed": "0"}, nil
		}
		return nil, err
	}
	out, n := fixConfigRefs(string(b), p.Str("path"), p.Str("to"), path.Base(p.Str("path")), path.Base(p.Str("to")))
	if n > 0 {
		if err := atomicfile.WriteExactMode(cfg, []byte(out), st.Mode().Perm()); err != nil {
			return nil, err
		}
	}
	return Output{"references_fixed": fmt.Sprint(n)}, nil
}

func (webRenameDir) Verify(_ context.Context, env *Env, p Params) error {
	if _, err := os.Lstat(env.Resolve(p.Str("path"))); err == nil {
		return errors.New("old directory still present")
	}
	st, err := os.Lstat(env.Resolve(p.Str("to")))
	if err != nil || !st.IsDir() {
		return errors.New("new directory missing")
	}
	if b, _, err := readBounded(filepath.Join(env.Resolve(p.Str("to")), "config.php")); err == nil && strings.Contains(string(b), p.Str("path")+"/") {
		return errors.New("config.php still references the old path")
	}
	return nil
}

// ---- web.opencart_audit ----

type webOpenCartAudit struct{}

func (webOpenCartAudit) Spec() Spec {
	return Spec{Name: "web.opencart_audit", Risk: RiskNone, ReadOnly: true,
		Doc: "Read-only OpenCart review: leftover install/, default admin directory, writable config, PHP files in upload directories, files that differ from the vendor release hashes, unknown extensions, and (optionally) admin users and installed extensions from the database.",
		Params: []ParamSpec{
			{Name: "docroot", Type: Path, Required: true},
			{Name: "admin_dir", Type: String, Default: "admin", Check: func(v any) error {
				if !identOnlyRe.MatchString(strings.ReplaceAll(v.(string), "-", "_")) {
					return errors.New("invalid directory name")
				}
				return nil
			}},
			{Name: "vendor_manifest", Type: Path},
			{Name: "known_extensions", Type: StringList, Max: 500},
			{Name: "database", Type: String, Max: 64, Check: func(v any) error {
				if v.(string) != "" && !identOnlyRe.MatchString(v.(string)) {
					return errors.New("invalid database name")
				}
				return nil
			}},
			{Name: "prefix", Type: String, Default: "oc_", Max: 32, Check: func(v any) error {
				if !identOnlyRe.MatchString(v.(string)) {
					return errors.New("invalid table prefix")
				}
				return nil
			}},
			socketParam,
			{Name: "fail_on_critical", Type: Bool}}}
}
func (webOpenCartAudit) Locks(Params) []string  { return nil }
func (webOpenCartAudit) Touches(Params) []Touch { return nil }
func (webOpenCartAudit) Plan(context.Context, *Env, Params) (Plan, error) {
	return Plan{Diff: "read-only"}, nil
}
func (webOpenCartAudit) Capture(context.Context, *Env, Params) (Rollback, error) {
	return Rollback{}, nil
}

var (
	codeExtRe      = regexp.MustCompile(`(?i)\.(php|phtml|phar|inc|php[3-8])$`)
	auditedExtRe   = regexp.MustCompile(`(?i)\.(php|phtml|phar|inc|twig|tpl|htaccess|js)$|^\.htaccess$`)
	uploadAreaRe   = regexp.MustCompile(`^(image|system/storage/(upload|download|cache|session|logs|vendor))(/|$)`)
	siteSpecificRe = regexp.MustCompile(`(^|/)config\.php$`)
	skipDirRe      = regexp.MustCompile(`^(system/storage|image/cache|\.git)(/|$)`)
)

const maxAuditFiles = 300000

func readVendorManifest(p string) (map[string]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		h, n, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		n = strings.TrimPrefix(strings.TrimSpace(n), "*")
		n = strings.TrimPrefix(n, "./")
		if ok && sha256Re.MatchString(h) && n != "" {
			m[n] = strings.ToLower(h)
		}
	}
	return m, sc.Err()
}

func (a webOpenCartAudit) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	root := env.Resolve(p.Str("docroot"))
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("docroot %s is not a directory", p.Str("docroot"))
	}
	var finds []dbFinding
	add := func(sev, what, issue string) { finds = append(finds, dbFinding{sev, what, issue}) }

	if _, err := os.Stat(filepath.Join(root, "install")); err == nil {
		add("critical", "install/", "installer directory still present")
	}
	admin := p.Str("admin_dir")
	if admin == "admin" {
		add("warning", "admin/", "default admin directory name")
	}
	for _, cfg := range []string{"config.php", admin + "/config.php"} {
		if st, err := os.Stat(filepath.Join(root, cfg)); err == nil && st.Mode().Perm()&0o022 != 0 {
			add("critical", cfg, fmt.Sprintf("group/world-writable (mode %04o)", st.Mode().Perm()))
		}
	}
	var vendor map[string]string
	if p.Has("vendor_manifest") {
		if vendor, err = readVendorManifest(env.Resolve(p.Str("vendor_manifest"))); err != nil {
			return nil, fmt.Errorf("vendor manifest: %w", err)
		}
		if len(vendor) == 0 {
			return nil, errors.New("vendor manifest is empty")
		}
	}
	seen := map[string]bool{}
	nfiles, modified, extra := 0, 0, 0
	err = filepath.WalkDir(root, func(fp string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil // unreadable entries are skipped, not fatal
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel, _ := filepath.Rel(root, fp)
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if skipDirRe.MatchString(rel) && !uploadAreaRe.MatchString(rel) {
				return fs.SkipDir
			}
			return nil
		}
		nfiles++
		if nfiles > maxAuditFiles {
			return errors.New("too many files under docroot")
		}
		if uploadAreaRe.MatchString(rel) && codeExtRe.MatchString(rel) {
			add("critical", rel, "executable script in an upload/cache directory (possible web shell)")
			return nil
		}
		if skipDirRe.MatchString(rel) {
			return nil
		}
		if vendor == nil || !auditedExtRe.MatchString(rel) || siteSpecificRe.MatchString(rel) {
			return nil
		}
		seen[rel] = true
		want, known := vendor[rel]
		if !known {
			if !strings.HasPrefix(rel, "extension/") && !strings.HasPrefix(rel, admin+"/") || codeExtRe.MatchString(rel) {
				extra++
				add("warning", rel, "not in the vendor release")
			}
			return nil
		}
		got, herr := hashFile(fp, "sha256")
		if herr == nil && got != want {
			modified++
			add("critical", rel, "differs from the vendor release")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	missing := 0
	for rel := range vendor {
		if !seen[rel] && !siteSpecificRe.MatchString(rel) && !strings.HasPrefix(rel, "install/") && auditedExtRe.MatchString(rel) {
			missing++
		}
	}
	// installed extension directories
	var exts []string
	if ents, err := os.ReadDir(filepath.Join(root, "extension")); err == nil {
		known := map[string]bool{}
		for _, k := range p.List("known_extensions") {
			known[k] = true
		}
		for _, e := range ents {
			if e.IsDir() {
				exts = append(exts, e.Name())
				if len(known) > 0 && !known[e.Name()] {
					add("warning", "extension/"+e.Name(), "extension not in the known list")
				}
			}
		}
	}
	out := Output{"files_checked": fmt.Sprint(nfiles), "modified": fmt.Sprint(modified), "unknown_files": fmt.Sprint(extra),
		"missing_vendor_files": fmt.Sprint(missing), "extensions_fs": strings.Join(exts, ",")}

	if p.Str("database") != "" {
		if err := a.dbChecks(ctx, env, p, out, add); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(finds, func(i, j int) bool {
		if finds[i].Severity != finds[j].Severity {
			return finds[i].Severity < finds[j].Severity
		}
		return finds[i].Account < finds[j].Account
	})
	crit := 0
	var lines []string
	for _, f := range finds {
		if f.Severity == "critical" {
			crit++
		}
		lines = append(lines, f.Severity+" "+f.Account+": "+f.Issue)
	}
	if len(lines) > 300 {
		lines = append(lines[:300], fmt.Sprintf("... %d more", len(lines)-300))
	}
	out["critical"], out["findings"] = fmt.Sprint(crit), strings.Join(lines, "\n")
	if crit > 0 && p.Bool("fail_on_critical") {
		return out, fmt.Errorf("%d critical finding(s)", crit)
	}
	return out, nil
}

func (webOpenCartAudit) dbChecks(ctx context.Context, env *Env, p Params, out Output, add func(sev, what, issue string)) error {
	c, err := env.mysqlDial(ctx, p)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer c.Close()
	db, pre := p.Str("database"), p.Str("prefix")
	r, err := c.Query(ctx, fmt.Sprintf("SELECT user_id, username, email, status, date_added FROM `%s`.`%suser` ORDER BY user_id", db, pre))
	if err != nil {
		return fmt.Errorf("admin users: %w", err)
	}
	var users []string
	for _, row := range r.Rows {
		users = append(users, row[1])
		if row[3] == "1" && (row[1] == "admin" || row[1] == "administrator") {
			add("warning", "user "+row[1], "default-named active admin account")
		}
	}
	out["admin_users"] = strings.Join(users, ",")
	if len(r.Rows) > 3 {
		add("warning", "users", fmt.Sprintf("%d admin accounts; review for unexpected ones", len(r.Rows)))
	}
	e, err := c.Query(ctx, fmt.Sprintf("SELECT type, code FROM `%s`.`%sextension` ORDER BY type, code", db, pre))
	if err != nil {
		return fmt.Errorf("extensions: %w", err)
	}
	var codes []string
	for _, row := range e.Rows {
		codes = append(codes, row[0]+"/"+row[1])
	}
	out["extensions_db"] = strings.Join(codes, ",")
	return nil
}

func (webOpenCartAudit) Verify(_ context.Context, _ *Env, _ Params) error { return nil }
