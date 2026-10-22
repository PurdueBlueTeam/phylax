package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

const (
	sysctlFile        = "/etc/sysctl.d/99-phylax.conf"
	kindSysctlRestore = "sysctl.restore"
)

var sysctlKeyRe = regexp.MustCompile(`^[a-z0-9_\-]+(\.[a-z0-9_\-]+)+$`)

type sysctlSet struct{}

func (sysctlSet) Spec() Spec {
	return Spec{Name: "sysctl.set", Risk: RiskService, Doc: "Set a sysctl at runtime and persist it in /etc/sysctl.d/99-phylax.conf.",
		Params: []ParamSpec{
			{Name: "key", Type: String, Required: true, Max: 200, Check: func(v any) error {
				if !sysctlKeyRe.MatchString(v.(string)) {
					return errors.New("invalid sysctl key (dotted lowercase name)")
				}
				return nil
			}},
			{Name: "value", Type: String, Required: true, Max: 256, Check: func(v any) error { return checkConfText("value", v.(string)) }},
		}}
}
func (sysctlSet) Locks(Params) []string  { return nil }
func (sysctlSet) Touches(Params) []Touch { return []Touch{pathTouch(sysctlFile, OpModify)} }

func sysctlProc(env *Env, key string) string {
	return env.Resolve("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
}

func lintSysctl(key, value string) (warn []string, err error) {
	v := strings.TrimSpace(value)
	switch {
	case strings.HasSuffix(key, "icmp_echo_ignore_all") && v != "0":
		return nil, unsafeConf("%s=%s blocks ICMP echo; the ping check needs it", key, v)
	case strings.HasSuffix(key, "icmp_echo_ignore_broadcasts"):
		return nil, nil
	case key == "user.max_user_namespaces" && v == "0", key == "kernel.unprivileged_userns_clone" && v == "0":
		warn = append(warn, "disabling user namespaces breaks rootless containers, flatpak and some browsers; confirm they are unused")
	}
	return warn, nil
}

func (sysctlSet) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	warn, err := lintSysctl(p.Str("key"), p.Str("value"))
	if err != nil {
		return Plan{}, err
	}
	cur, err := os.ReadFile(sysctlProc(env, p.Str("key")))
	if err != nil {
		return Plan{}, fmt.Errorf("sysctl %s: %w", p.Str("key"), err)
	}
	old, _, err := readFileIfExists(env.Resolve(sysctlFile))
	if err != nil {
		return Plan{}, err
	}
	out, fileChanged, err := editConf(string(old), styleEquals, "", p.Str("key"), p.Str("value"))
	if err != nil {
		return Plan{}, err
	}
	rtChanged := normWS(string(cur)) != normWS(p.Str("value"))
	if !fileChanged && !rtChanged {
		return Plan{Done: true, Notes: warn}, nil
	}
	var parts []string
	if rtChanged {
		parts = append(parts, fmt.Sprintf("runtime %s: %s -> %s", p.Str("key"), normWS(string(cur)), normWS(p.Str("value"))))
	}
	if fileChanged {
		parts = append(parts, sysctlFile+":\n"+renderDiff(old, []byte(out)))
	}
	return Plan{Diff: strings.Join(parts, "\n"), Notes: warn}, nil
}

func normWS(s string) string { return strings.Join(strings.Fields(s), " ") }

type sysctlSnap struct {
	Proc   string              `json:"proc"`
	Old    string              `json:"old"`
	HadOld bool                `json:"had_old"`
	Files  deadman.FileRestore `json:"files"`
}

func (sysctlSet) Capture(_ context.Context, env *Env, p Params) (Rollback, error) {
	proc := sysctlProc(env, p.Str("key"))
	s := sysctlSnap{Proc: proc}
	if b, err := os.ReadFile(proc); err == nil {
		s.Old, s.HadOld = strings.TrimRight(string(b), "\n"), true
	}
	fr, err := deadman.SnapshotFiles(env.Resolve(sysctlFile))
	if err != nil {
		return Rollback{}, err
	}
	s.Files = fr
	return Rollback{Kind: kindSysctlRestore, Data: s}, nil
}

func undoSysctl(_ context.Context, _ *Env, e deadman.Entry) error {
	var s sysctlSnap
	if err := json.Unmarshal(e.Data, &s); err != nil {
		return err
	}
	errs := []error{restoreSnapshots(s.Files)}
	if s.HadOld {
		errs = append(errs, os.WriteFile(s.Proc, []byte(s.Old+"\n"), 0o644))
	}
	return errors.Join(errs...)
}

func (sysctlSet) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	file := env.Resolve(sysctlFile)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return nil, err
	}
	err := atomicfile.Modify(file, 0o644, func(old []byte, _ bool) ([]byte, error) {
		out, _, err := editConf(string(old), styleEquals, "", p.Str("key"), p.Str("value"))
		return []byte(out), err
	})
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(sysctlProc(env, p.Str("key")), []byte(p.Str("value")+"\n"), 0o644); err != nil {
		return nil, fmt.Errorf("set runtime value: %w", err)
	}
	return nil, nil
}

func (sysctlSet) Verify(_ context.Context, env *Env, p Params) error {
	cur, err := os.ReadFile(sysctlProc(env, p.Str("key")))
	if err != nil {
		return err
	}
	if normWS(string(cur)) != normWS(p.Str("value")) {
		return fmt.Errorf("runtime %s is %q, want %q", p.Str("key"), normWS(string(cur)), p.Str("value"))
	}
	b, _, err := readBounded(env.Resolve(sysctlFile))
	if err != nil {
		return err
	}
	if g := getConf(string(b), styleEquals, "", p.Str("key")); len(g) == 0 || g[len(g)-1] != p.Str("value") {
		return errors.New("value not persisted")
	}
	return nil
}
