package actions

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Package actions (design: Execution, "Packages"; Egress, "Patch windows and
// the cache"). The host's package manager runs through host.exec only inside
// a declared patch window, with versions pinned, from a hash-verified file in
// the local depot or through the window's loopback proxy. Dry-run shows the
// package manager's own simulated transaction.

type pkgOp int

const (
	pkgInstall pkgOp = iota
	pkgUpgrade
	pkgRemove
)

var (
	pkgNameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._\-]{0,127}$`)
	pkgVersionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+~:_\-]{0,63}$`)
	sha256Re     = regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)
)

type pkgAction struct {
	name string
	op   pkgOp
}

func (a pkgAction) Spec() Spec {
	ps := []ParamSpec{{Name: "name", Type: String, Required: true, Max: 128, Check: func(v any) error {
		if !pkgNameRe.MatchString(v.(string)) {
			return errors.New("invalid package name")
		}
		return nil
	}}}
	doc := "Remove a package, keeping its configuration. Runs the host package manager inside a patch window."
	if a.op != pkgRemove {
		ps = append(ps,
			ParamSpec{Name: "version", Type: String, Required: a.op == pkgUpgrade, Max: 64, Check: func(v any) error {
				if !pkgVersionRe.MatchString(v.(string)) {
					return errors.New("invalid version")
				}
				return nil
			}},
			ParamSpec{Name: "source", Type: String, Max: 512, Check: func(v any) error {
				_, err := parseDepotSource(v.(string))
				return err
			}},
			ParamSpec{Name: "sha256", Type: String, Max: 64, Check: func(v any) error {
				if !sha256Re.MatchString(v.(string)) {
					return errors.New("sha256 must be 64 hex characters")
				}
				return nil
			}})
		doc = "Install a pinned package version from the local depot (hash-verified) or via the patch-window proxy. Never downloads outside a window."
		if a.op == pkgUpgrade {
			doc = "Upgrade a package to a pinned version, same rules as pkg.install."
		}
	}
	return Spec{Name: a.name, Risk: RiskService, Doc: doc, Params: ps}
}

func (pkgAction) Locks(Params) []string  { return []string{LockPackages} }
func (pkgAction) Touches(Params) []Touch { return nil }

func parseDepotSource(s string) (string, error) {
	rel, ok := strings.CutPrefix(s, "depot:")
	if !ok {
		return "", errors.New(`source must be "depot:<path>"`)
	}
	if rel == "" || strings.ContainsRune(rel, 0) || strings.Contains(rel, "\\") || path.IsAbs(rel) ||
		path.Clean(rel) != strings.TrimSuffix(rel, "/") || rel == "." || strings.HasPrefix(rel, "..") {
		return "", errors.New("invalid depot path")
	}
	return path.Clean(rel), nil
}

type pkgMgr struct {
	kind string // apt | dnf
}

func (a pkgAction) manager(env *Env) (pkgMgr, error) {
	switch pm := env.lx().PackageManager; pm {
	case "apt", "dnf":
		return pkgMgr{pm}, nil
	case "":
	default:
		return pkgMgr{}, fmt.Errorf("unknown package manager %q", pm)
	}
	for _, c := range []struct{ bin, kind string }{{"/usr/bin/apt-get", "apt"}, {"/usr/bin/dnf", "dnf"}} {
		if _, err := os.Stat(env.Resolve(c.bin)); err == nil {
			return pkgMgr{c.kind}, nil
		}
	}
	return pkgMgr{}, errors.New("no supported package manager (apt-get, dnf) found")
}

func (m pkgMgr) queryArgv(name string) []string {
	if m.kind == "apt" {
		return []string{"/usr/bin/dpkg-query", "-W", "-f=${Status}|${Version}", name}
	}
	return []string{"/usr/bin/rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", name}
}

// installed returns the installed version ("" = not installed).
func (m pkgMgr) installed(ctx context.Context, env *Env, name string) (string, error) {
	res, err := env.lx().runner().Run(ctx, Cmd{Argv: m.queryArgv(name), Timeout: 30 * time.Second})
	if err != nil {
		return "", err
	}
	out := strings.TrimSpace(res.Stdout)
	if res.ExitCode != 0 {
		return "", nil // not installed
	}
	if m.kind == "apt" {
		st, ver, _ := strings.Cut(out, "|")
		if !strings.HasSuffix(st, " installed") {
			return "", nil
		}
		return ver, nil
	}
	return out, nil
}

func versionMatches(have, want string) bool {
	if want == "" {
		return have != ""
	}
	if have == want {
		return true
	}
	// 4.14.9 matches 4.14.9-1 and 1:4.14.9-1ubuntu1 (epoch); not 4.14.90.
	h := have
	if i := strings.Index(h, ":"); i >= 0 && !strings.Contains(want, ":") {
		h = h[i+1:]
	}
	if !strings.HasPrefix(h, want) {
		return false
	}
	rest := h[len(want):]
	return rest == "" || strings.ContainsRune("-~+.", rune(rest[0])) && !(rest[0] == '.' && len(rest) > 1 && rest[1] >= '0' && rest[1] <= '9')
}

// depotFile resolves and hash-verifies the package file named by source.
func (m pkgMgr) depotFile(env *Env, p Params) (file, sum string, err error) {
	rel, err := parseDepotSource(p.Str("source"))
	if err != nil {
		return "", "", err
	}
	root := env.lx().DepotDir
	if root == "" {
		return "", "", errors.New("no depot directory configured")
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", err
	}
	target, err := filepath.EvalSymlinks(filepath.Join(realRoot, filepath.FromSlash(rel)))
	if err != nil {
		return "", "", fmt.Errorf("depot source %s: %w", p.Str("source"), err)
	}
	if target != realRoot && !strings.HasPrefix(target, realRoot+string(filepath.Separator)) {
		return "", "", errors.New("depot source escapes the depot")
	}
	st, err := os.Stat(target)
	if err != nil {
		return "", "", err
	}
	file = target
	if st.IsDir() {
		ext, sep := ".rpm", "-"
		if m.kind == "apt" {
			ext, sep = ".deb", "_"
		}
		ents, err := os.ReadDir(target)
		if err != nil {
			return "", "", err
		}
		var cands []string
		prefix := p.Str("name") + sep + p.Str("version")
		for _, e := range ents {
			n := e.Name()
			if e.Type().IsRegular() && strings.HasSuffix(n, ext) && strings.HasPrefix(n, prefix) {
				cands = append(cands, n)
			}
		}
		sort.Strings(cands)
		switch len(cands) {
		case 0:
			return "", "", fmt.Errorf("no %s for %s %s in %s", ext, p.Str("name"), p.Str("version"), p.Str("source"))
		case 1:
			file = filepath.Join(target, cands[0])
		default:
			return "", "", fmt.Errorf("ambiguous depot content: %v", cands)
		}
	} else if !st.Mode().IsRegular() {
		return "", "", errors.New("depot source is not a regular file")
	}
	want := strings.ToLower(p.Str("sha256"))
	if want == "" {
		want, err = sumFromList(filepath.Dir(file), filepath.Base(file))
		if err != nil {
			return "", "", err
		}
	}
	got, err := hashFile(file, "sha256")
	if err != nil {
		return "", "", err
	}
	if got != want {
		return "", "", fmt.Errorf("depot file %s sha256 %s does not match expected %s", filepath.Base(file), got, want)
	}
	return file, got, nil
}

func sumFromList(dir, base string) (string, error) {
	f, err := os.Open(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return "", errors.New("no sha256 given and no SHA256SUMS next to the package; refusing to install an unverified file")
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		h, n, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		n = strings.TrimPrefix(strings.TrimSpace(n), "*")
		if ok && n == base && sha256Re.MatchString(h) {
			return strings.ToLower(h), nil
		}
	}
	return "", fmt.Errorf("%s is not listed in SHA256SUMS", base)
}

// argv builds the transaction command. sim selects the dry-run form.
func (a pkgAction) argv(m pkgMgr, p Params, file string, sim bool, proxy string) []string {
	name, ver := p.Str("name"), p.Str("version")
	target := name
	switch {
	case file != "":
		target = file
	case ver != "" && m.kind == "apt":
		target = name + "=" + ver
	case ver != "":
		target = name + "-" + ver
	}
	var v []string
	if m.kind == "apt" {
		v = []string{"/usr/bin/apt-get"}
		if sim {
			v = append(v, "-s")
		}
		if proxy != "" {
			v = append(v, "-o", "Acquire::http::Proxy="+proxy, "-o", "Acquire::https::Proxy="+proxy)
		}
		if a.op == pkgRemove {
			return append(v, "remove", "-y", name)
		}
		if file != "" && !strings.HasPrefix(file, "/") {
			file = "./" + file
		}
		return append(v, "install", "-y", "--no-install-recommends", target)
	}
	v = []string{"/usr/bin/dnf"}
	if proxy != "" {
		v = append(v, "--setopt=proxy="+proxy)
	}
	verb := "install"
	if a.op == pkgRemove {
		verb = "remove"
	}
	if sim {
		return append(v, verb, "--assumeno", name)
	}
	if a.op == pkgRemove {
		return append(v, "remove", "-y", name)
	}
	return append(v, "install", "-y", target)
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = append([]string{"..."}, lines[len(lines)-n:]...)
	}
	return strings.Join(lines, "\n")
}

var pkgScoredAliases = map[string][]string{
	"openssh-server": {"sshd", "ssh"}, "openssh": {"sshd", "ssh"}, "httpd": {"httpd"}, "apache2": {"apache2"},
	"mariadb-server": {"mariadb", "mysqld", "mysql"}, "mysql-server": {"mysqld", "mysql"}, "mysql-community-server": {"mysqld", "mysql"},
	"postfix": {"postfix"}, "dovecot": {"dovecot"}, "splunk": {"splunk", "Splunkd"}, "bind9": {"named", "bind9"}, "bind": {"named"},
}

func (a pkgAction) scoredRemoval(env *Env, name string) error {
	if a.op != pkgRemove {
		return nil
	}
	si := env.scoredInfo()
	if si == nil {
		return nil
	}
	names := append([]string{name}, pkgScoredAliases[name]...)
	if si.ServiceScored(names...) {
		return unsafeConf("package %s provides a scored service; removing it is refused", name)
	}
	return nil
}

func (a pkgAction) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	if a.op == pkgInstall && !p.Has("version") && !p.Has("source") {
		return Plan{}, errors.New("pkg.install needs a pinned version (or a depot source)")
	}
	if err := a.scoredRemoval(env, p.Str("name")); err != nil {
		return Plan{}, err
	}
	m, err := a.manager(env)
	if err != nil {
		return Plan{}, err
	}
	have, err := m.installed(ctx, env, p.Str("name"))
	if err != nil {
		return Plan{}, err
	}
	switch {
	case a.op == pkgRemove && have == "":
		return Plan{Done: true}, nil
	case a.op != pkgRemove && p.Has("version") && versionMatches(have, p.Str("version")):
		return Plan{Done: true}, nil
	case a.op == pkgUpgrade && have == "":
		return Plan{}, fmt.Errorf("%s is not installed; use pkg.install", p.Str("name"))
	}
	var file, sum string
	if p.Has("source") && a.op != pkgRemove {
		if file, sum, err = m.depotFile(env, p); err != nil {
			return Plan{}, err
		}
	}
	res, err := env.lx().runner().Run(ctx, Cmd{Argv: a.argv(m, p, file, true, ""), Timeout: 2 * time.Minute})
	if err != nil {
		return Plan{}, err
	}
	out := res.Stdout + res.Stderr
	if (m.kind == "apt" && res.ExitCode != 0) || (m.kind == "dnf" && !strings.Contains(out, "Transaction Summary")) {
		return Plan{}, fmt.Errorf("simulated transaction failed (exit %d): %s", res.ExitCode, tail(out, 8))
	}
	head := fmt.Sprintf("%s %s %s -> %s", strings.TrimPrefix(a.name, "pkg."), p.Str("name"), orNone(have), orNone(p.Str("version")))
	if a.op == pkgRemove {
		head = fmt.Sprintf("remove %s %s (configuration kept)", p.Str("name"), have)
	}
	if file != "" {
		head += fmt.Sprintf("\nfrom depot file %s (sha256 %s verified)", filepath.Base(file), sum)
	}
	pl := Plan{Diff: head + "\ntransaction:\n" + tail(out, 40),
		Notes: []string{"package changes are not rolled back automatically; reinstall the previous version in a patch window"}}
	if w, werr := env.requireWindow(ctx); werr != nil {
		pl.Notes = append(pl.Notes, "apply will be refused: "+werr.Error())
	} else {
		pl.Notes = append(pl.Notes, "patch window "+w.ID+" is open")
	}
	return pl, nil
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func (pkgAction) Capture(context.Context, *Env, Params) (Rollback, error) { return Rollback{}, nil }

func (a pkgAction) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	w, err := env.requireWindow(ctx)
	if err != nil {
		return nil, err
	}
	m, err := a.manager(env)
	if err != nil {
		return nil, err
	}
	var file string
	if p.Has("source") && a.op != pkgRemove {
		if file, _, err = m.depotFile(env, p); err != nil { // re-verify right before use
			return nil, err
		}
	}
	var cenv []string
	if w.Proxy != "" {
		cenv = []string{"http_proxy=" + w.Proxy, "https_proxy=" + w.Proxy, "HTTP_PROXY=" + w.Proxy, "HTTPS_PROXY=" + w.Proxy}
	}
	res, err := env.lx().runner().Run(ctx, Cmd{Argv: a.argv(m, p, file, false, w.Proxy), Env: cenv, Timeout: 10 * time.Minute})
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("%s exited %d: %s", m.kind, res.ExitCode, tail(res.Stderr+res.Stdout, 10))
	}
	return Output{"window": w.ID, "window_tag": w.Tag}, nil
}

func (a pkgAction) Verify(ctx context.Context, env *Env, p Params) error {
	m, err := a.manager(env)
	if err != nil {
		return err
	}
	have, err := m.installed(ctx, env, p.Str("name"))
	if err != nil {
		return err
	}
	if a.op == pkgRemove {
		if have != "" {
			return fmt.Errorf("%s %s is still installed", p.Str("name"), have)
		}
		return nil
	}
	if !versionMatches(have, p.Str("version")) {
		return fmt.Errorf("%s is %q after the transaction, want %q", p.Str("name"), have, p.Str("version"))
	}
	return nil
}
