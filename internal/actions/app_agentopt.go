package actions

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
)

// agentopt.set writes key=value lines into a Wazuh local_internal_options.conf.
// Unlike file.write it accepts Windows paths (C:\...), because the controller
// cannot validate those as POSIX.

// osPathParam is an absolute path on either OS family (POSIX or drive-letter),
// for actions whose target may be a Windows host edited from the controller.
var osPathParam = ParamSpec{Name: "path", Type: String, Required: true, Max: 1024, Check: func(v any) error { return checkOSPath(v.(string)) }}

func checkOSPath(s string) error {
	if strings.ContainsRune(s, 0) || !(strings.HasPrefix(s, "/") || (len(s) > 2 && s[1] == ':' && (s[2] == '\\' || s[2] == '/'))) {
		return errors.New("path must be absolute (POSIX or drive-letter)")
	}
	return nil
}

var agentOptKeyRe = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)+$`)

type agentOptSet struct{}

func parseAgentKeys(s string) ([][2]string, error) {
	var out [][2]string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || !agentOptKeyRe.MatchString(k) || v == "" || strings.ContainsAny(v, "\x00\r\n") {
			return nil, fmt.Errorf("invalid option %q (want key.name=value)", part)
		}
		out = append(out, [2]string{k, v})
	}
	if len(out) == 0 {
		return nil, errors.New("no options given")
	}
	return out, nil
}

func (agentOptSet) Spec() Spec {
	return Spec{Name: "agentopt.set", Risk: RiskService,
		Doc: "Set key=value lines in a Wazuh local_internal_options.conf atomically (POSIX or Windows path).",
		Params: []ParamSpec{
			{Name: "path", Type: String, Required: true, Max: 1024, Check: func(v any) error {
				if err := checkOSPath(v.(string)); err != nil {
					return err
				}
				if !strings.HasSuffix(strings.ToLower(v.(string)), "local_internal_options.conf") {
					return errors.New("only local_internal_options.conf may be edited")
				}
				return nil
			}},
			{Name: "keys", Type: String, Required: true, Max: 4096, Check: func(v any) error { _, err := parseAgentKeys(v.(string)); return err }},
		}}
}
func (agentOptSet) Locks(Params) []string    { return nil }
func (agentOptSet) Touches(p Params) []Touch { return []Touch{pathTouch(p.Str("path"), OpModify)} }

func applyAgentOpts(src string, kv [][2]string) (string, bool) {
	changed := false
	for _, e := range kv {
		var c bool
		src, c, _ = editConfSep(src, styleEquals, "", e[0], e[1], "=")
		changed = changed || c
	}
	return src, changed
}

func (agentOptSet) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	kv, _ := parseAgentKeys(p.Str("keys"))
	old, exists, err := readFileIfExists(env.resolveAny(p.Str("path")))
	if err != nil {
		return Plan{}, err
	}
	out, changed := applyAgentOpts(string(old), kv)
	if exists && !changed {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: renderDiff(old, []byte(out))}, nil
}
func (agentOptSet) Capture(_ context.Context, env *Env, p Params) (Rollback, error) {
	return snapshotRollback(env.resolveAny(p.Str("path")))
}
func (agentOptSet) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	kv, _ := parseAgentKeys(p.Str("keys"))
	return nil, atomicfile.Modify(env.resolveAny(p.Str("path")), 0o640, func(old []byte, _ bool) ([]byte, error) {
		out, _ := applyAgentOpts(string(old), kv)
		return []byte(out), nil
	})
}
func (agentOptSet) Verify(_ context.Context, env *Env, p Params) error {
	kv, _ := parseAgentKeys(p.Str("keys"))
	b, _, err := readBounded(env.resolveAny(p.Str("path")))
	if err != nil {
		return err
	}
	var bad []string
	for _, e := range kv {
		if got := getConf(string(b), styleEquals, "", e[0]); len(got) == 0 || got[len(got)-1] != e[1] {
			bad = append(bad, e[0])
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		return fmt.Errorf("options not applied: %v", bad)
	}
	return nil
}
