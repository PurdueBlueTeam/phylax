package actions

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
)

// ---- ini.set / conf.set ----

type confSet struct {
	name  string
	style confStyle // styleAuto: from the path / the style param
}

func (c confSet) Spec() Spec {
	ps := []ParamSpec{osPathParam,
		{Name: "key", Type: String, Required: true, Max: 128, Check: func(v any) error {
			if !confKeyRe.MatchString(v.(string)) {
				return errors.New("invalid key")
			}
			return nil
		}},
		{Name: "value", Type: String, Required: true, Max: 4096, Check: func(v any) error { return checkConfText("value", v.(string)) }},
		{Name: "stanza", Type: String, Required: c.style == styleINI, Max: 256, Check: func(v any) error { return checkConfText("stanza", v.(string)) }},
	}
	doc := "Set one key in an INI/stanza file (php.ini, Splunk .conf), keeping comments and order, atomically."
	if c.style != styleINI {
		ps = append(ps, ParamSpec{Name: "style", Type: Enum, Enum: []string{"auto", "ini", "space", "equals"}, Default: "auto"})
		doc = "Set one key in sshd_config, main.cf, dovecot.conf, php.ini or an INI file, keeping comments and order, atomically. Refuses scoring-unsafe values."
	}
	return Spec{Name: c.name, Risk: RiskService, Doc: doc, Params: ps}
}

func (c confSet) styleOf(p Params) confStyle {
	if c.style != styleAuto {
		return c.style
	}
	if s := styleNames[p.Str("style")]; s != styleAuto {
		return s
	}
	return detectStyle(p.Str("path"))
}

func (confSet) Locks(p Params) []string  { return lockForPath(p.Str("path")) }
func (confSet) Touches(p Params) []Touch { return []Touch{pathTouch(p.Str("path"), OpModify)} }

func (c confSet) edit(env *Env, p Params) (old, new []byte, exists, changed bool, err error) {
	path := env.Resolve(p.Str("path"))
	old, exists, err = readFileIfExists(path)
	if err != nil {
		return
	}
	var out string
	out, changed, err = editConf(string(old), c.styleOf(p), p.Str("stanza"), p.Str("key"), p.Str("value"))
	new = []byte(out)
	return
}

func (c confSet) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	warn, err := env.lintConf(p.Str("path"), p.Str("stanza"), p.Str("key"), p.Str("value"))
	if err != nil {
		return Plan{}, err
	}
	old, new, exists, changed, err := c.edit(env, p)
	if err != nil {
		return Plan{}, err
	}
	if exists && !changed {
		return Plan{Done: true, Notes: warn}, nil
	}
	diff := renderDiff(old, new)
	if !exists {
		diff = "create " + p.Str("path") + "\n" + diff
	}
	return Plan{Diff: diff, Notes: warn}, nil
}

func (confSet) Capture(_ context.Context, env *Env, p Params) (Rollback, error) {
	return snapshotRollback(env.Resolve(p.Str("path")))
}

func (c confSet) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	path := env.Resolve(p.Str("path"))
	return nil, atomicfile.Modify(path, 0o644, func(old []byte, _ bool) ([]byte, error) {
		out, _, err := editConf(string(old), c.styleOf(p), p.Str("stanza"), p.Str("key"), p.Str("value"))
		return []byte(out), err
	})
}

func (c confSet) Verify(ctx context.Context, env *Env, p Params) error {
	b, _, err := readBounded(env.Resolve(p.Str("path")))
	if err != nil {
		return err
	}
	got := getConf(string(b), c.styleOf(p), p.Str("stanza"), p.Str("key"))
	if len(got) == 0 {
		return fmt.Errorf("%s not set after write", p.Str("key"))
	}
	for _, g := range got {
		if g != p.Str("value") {
			return fmt.Errorf("%s reads back as %q", p.Str("key"), g)
		}
	}
	return env.validateConf(ctx, p.Str("path"))
}

// confValidator returns the argv that syntax-checks the service config that
// path belongs to, or nil when there is no known checker.
func (e *Env) confValidator(p string) []string {
	lp := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	switch {
	case strings.Contains(lp, "/etc/ssh/sshd_config"):
		return []string{"/usr/sbin/sshd", "-t", "-f", e.Resolve("/etc/ssh/sshd_config")}
	case strings.HasSuffix(lp, "/postfix/main.cf"):
		return []string{"/usr/sbin/postfix", "check"}
	case strings.Contains(lp, "/etc/dovecot/"):
		return []string{"/usr/bin/doveconf", "-n", "-c", e.Resolve("/etc/dovecot/dovecot.conf")}
	}
	return nil
}

func isRealRoot(e *Env) bool { return e.Root == "" || e.Root == "/" }

// validateConf runs the service's own syntax check when a runner is
// configured (or on a real host). A failure makes Verify fail, which fires
// the dead-man rollback.
func (e *Env) validateConf(ctx context.Context, p string) error {
	argv := e.confValidator(p)
	if argv == nil {
		return nil
	}
	l := e.lx()
	if l.Exec == nil && !isRealRoot(e) {
		return nil
	}
	res, err := l.runner().Run(ctx, Cmd{Argv: argv})
	if err != nil {
		return fmt.Errorf("config check: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("config check %s failed: %s", argv[0], strings.TrimSpace(res.Stderr+res.Stdout))
	}
	return nil
}
