package actions

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var kbRe = regexp.MustCompile(`^(?i:KB)?(\d{6,8})$`)

// windows.hotfix installs a cached .msu from the depot with wusa. It never
// downloads. A reboot (reboot=true) takes DNS and WinRM down briefly, so the
// action is lockout class and plans put an approval gate before it.
type winHotfix struct{}

func (winHotfix) Spec() Spec {
	return Spec{Name: "windows.hotfix", Risk: RiskLockout,
		Doc: "Install the cached KB<n>.msu from <depot>\\windows with wusa (quiet, no automatic restart); with reboot=true schedule a restart in 60 seconds. Skips when the KB is already installed. Never downloads.",
		Params: []ParamSpec{
			{Name: "kb", Type: String, Required: true, Max: 64, Check: func(v any) error {
				s := v.(string)
				if !kbRe.MatchString(s) && s != "cached-latest-cu" {
					return errors.New(`kb must look like KB4571694 (or "cached-latest-cu")`)
				}
				return nil
			}},
			{Name: "reboot", Type: Bool}}}
}
func (winHotfix) Locks(Params) []string  { return []string{LockPackages} }
func (winHotfix) Touches(Params) []Touch { return nil }

// msu resolves the cached package path.
func (winHotfix) msu(env *Env, p Params) (kb, path string, err error) {
	if env.Win.DepotDir == "" {
		return "", "", errors.New("no depot directory configured")
	}
	kb = p.Str("kb")
	if kb == "cached-latest-cu" {
		kb = "latest-cu"
	} else {
		kb = "KB" + kbRe.FindStringSubmatch(kb)[1]
	}
	sep := `\`
	if !strings.Contains(env.Win.DepotDir, `\`) {
		sep = "/"
	}
	return kb, strings.TrimRight(env.Win.DepotDir, `/\`) + sep + "windows" + sep + kb + ".msu", nil
}

func (winHotfix) installed(ctx context.Context, env *Env, kb string) (bool, error) {
	if env.Win.Exec == nil {
		return false, Unsupported("exec")
	}
	if !strings.HasPrefix(kb, "KB") || kb == "latest-cu" {
		return false, nil
	}
	out, code, err := env.Win.Exec.Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("$ErrorActionPreference='SilentlyContinue'; (Get-HotFix -Id '%s').HotFixID", kb))
	if err != nil {
		return false, err
	}
	return code == 0 && strings.Contains(strings.ToUpper(out), kb), nil
}

func (a winHotfix) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	kb, path, err := a.msu(env, p)
	if err != nil {
		return Plan{}, err
	}
	inst, err := a.installed(ctx, env, kb)
	if err != nil {
		return Plan{}, err
	}
	if inst {
		return Plan{Done: true, Notes: []string{kb + " is already installed"}}, nil
	}
	notes := []string{"updates cannot be rolled back automatically"}
	if p.Bool("reboot") {
		notes = append(notes, "restart in 60 seconds: DNS and WinRM go down briefly")
	}
	return Plan{Diff: fmt.Sprintf("install %s from %s", kb, filepath.ToSlash(path)), Notes: notes}, nil
}
func (winHotfix) Capture(context.Context, *Env, Params) (Rollback, error) { return Rollback{}, nil }
func (a winHotfix) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	kb, path, err := a.msu(env, p)
	if err != nil {
		return nil, err
	}
	out, code, err := env.Win.Exec.Run(ctx, "wusa.exe", path, "/quiet", "/norestart")
	if err != nil {
		return nil, err
	}
	res := Output{"kb": kb, "exit": fmt.Sprint(code)}
	switch code {
	case 0:
	case 3010: // reboot required
		res["reboot_required"] = "true"
	case 2359302: // already installed
		res["already_installed"] = "true"
	default:
		return res, fmt.Errorf("wusa exited %d: %s", code, clip(strings.TrimSpace(out), 300))
	}
	if p.Bool("reboot") {
		if o, c, err := env.Win.Exec.Run(ctx, "shutdown.exe", "/r", "/t", "60", "/c", "phylax: installing "+kb); err != nil || c != 0 {
			return res, fmt.Errorf("schedule reboot: %v %s", err, clip(strings.TrimSpace(o), 200))
		}
		res["reboot_scheduled"] = "true"
	}
	return res, nil
}

// Verify has nothing to check beyond Apply's exit-code handling: wusa reports
// success (or 3010, restart pending) and Get-HotFix lists the KB only after the
// restart, so a later windows.hotfix run reports "already installed".
func (winHotfix) Verify(context.Context, *Env, Params) error { return nil }
