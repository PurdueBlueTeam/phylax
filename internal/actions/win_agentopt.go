package actions

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
)

var optKeyRe = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)+$`)
var optValRe = regexp.MustCompile(`^[A-Za-z0-9_./:-]{0,200}$`)

// agentopt.set writes key=value lines into a Wazuh local_internal_options.conf
// (Windows or Linux). The path is validated platform-independently on the
// controller (Path parameters accept drive and UNC paths), and only that file
// name is accepted, so the action cannot be used as a general file writer.
type agentOpt struct{}

func (agentOpt) Spec() Spec {
	return Spec{Name: "agentopt.set", Risk: RiskService,
		Doc: "Set key=value options in a Wazuh local_internal_options.conf (Windows or Linux path), atomically, keeping all other lines.",
		Params: []ParamSpec{
			{Name: "path", Type: Path, Required: true, Check: func(v any) error {
				s := strings.ReplaceAll(v.(string), `\`, "/")
				if s[strings.LastIndex(s, "/")+1:] != "local_internal_options.conf" {
					return errors.New("only local_internal_options.conf may be written")
				}
				return nil
			}},
			{Name: "keys", Type: String, Required: true, Max: 4096}}}
}

type optKV struct{ k, v string }

func parseOptKeys(s string) ([]optKV, error) {
	var out []optKV
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' }) {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		k, v, ok := strings.Cut(f, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || !optKeyRe.MatchString(k) || !optValRe.MatchString(v) {
			return nil, fmt.Errorf("invalid option %q (want lower_snake.key=value)", f)
		}
		out = append(out, optKV{k, v})
	}
	if len(out) == 0 {
		return nil, errors.New("no options given")
	}
	return out, nil
}

func (agentOpt) Locks(Params) []string { return nil }
func (agentOpt) Touches(p Params) []Touch {
	return []Touch{pathTouch(p.Str("path"), OpModify)}
}

func setOptions(src string, kvs []optKV, crlfDefault bool) string {
	crlf := crlfDefault
	if strings.Contains(src, "\r\n") {
		crlf = true
	} else if strings.Contains(src, "\n") {
		crlf = false
	}
	nl := "\n"
	if crlf {
		nl = "\r\n"
	}
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for _, kv := range kvs {
		set := false
		for i, l := range lines {
			t := strings.TrimSpace(l)
			if t == "" || t[0] == '#' {
				continue
			}
			if k, _, ok := strings.Cut(t, "="); ok && strings.TrimSpace(k) == kv.k {
				lines[i] = kv.k + "=" + kv.v
				set = true
				break
			}
		}
		if !set {
			lines = append(lines, kv.k+"="+kv.v)
		}
	}
	return strings.Join(lines, nl) + nl
}

func isWinPath(p string) bool { return strings.Contains(p, `\`) || len(p) > 1 && p[1] == ':' }

func (a agentOpt) next(env *Env, p Params) (path string, old, nw []byte, perm os.FileMode, err error) {
	kvs, err := parseOptKeys(p.Str("keys"))
	if err != nil {
		return
	}
	path = env.Resolve(p.Str("path"))
	perm = 0o640
	old, st, rerr := readBounded(path)
	switch {
	case rerr == nil:
		perm = st.Mode().Perm()
	case !os.IsNotExist(rerr):
		err = rerr
		return
	}
	nw = []byte(setOptions(string(old), kvs, isWinPath(p.Str("path"))))
	return
}

func (a agentOpt) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	_, old, nw, _, err := a.next(env, p)
	if err != nil {
		return Plan{}, err
	}
	if string(old) == string(nw) {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: lineDiff(string(old), string(nw)), Notes: []string{"the Wazuh agent service must restart to read the options"}}, nil
}
func (a agentOpt) Capture(_ context.Context, env *Env, p Params) (Rollback, error) {
	return snapshotRollback(env.Resolve(p.Str("path")))
}
func (a agentOpt) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	path, _, nw, perm, err := a.next(env, p)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return nil, atomicfile.WriteFile(path, nw, perm)
}
func (a agentOpt) Verify(_ context.Context, env *Env, p Params) error {
	kvs, err := parseOptKeys(p.Str("keys"))
	if err != nil {
		return err
	}
	b, _, err := readBounded(env.Resolve(p.Str("path")))
	if err != nil {
		return err
	}
	have := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			have[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	for _, kv := range kvs {
		if have[kv.k] != kv.v {
			return fmt.Errorf("%s is %q, want %q", kv.k, have[kv.k], kv.v)
		}
	}
	return nil
}
