package actions

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

const kindDefender = "win.defender"

// Defender exclusion registry keys. Exclusions set by Group Policy live under
// Policies and cannot be removed with Remove-MpPreference; they are reported.
var defenderExclKeys = []struct{ kind, key string }{
	{ExclPath, `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`},
	{ExclExtension, `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions`},
	{ExclProcess, `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes`},
}

// ExecDefender implements DefenderBackend: exclusions are read from the
// registry (native) and changed with the Defender cmdlets through the
// allowlisted Executor, because tamper protection blocks direct registry edits.
type ExecDefender struct {
	Reg  RegistryStore
	Exec Executor
}

func (d ExecDefender) Exclusions(ctx context.Context) ([]Exclusion, error) {
	var out []Exclusion
	for _, k := range defenderExclKeys {
		names, err := d.Reg.ValueNames(ctx, k.key)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			out = append(out, Exclusion{Kind: k.kind, Value: n})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Value < out[j].Value
	})
	return out, nil
}

func psQuote(s string) (string, error) {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("control character in value")
		}
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'", nil
}

func (d ExecDefender) mp(ctx context.Context, cmdlet, param, value string) error {
	q, err := psQuote(value)
	if err != nil {
		return err
	}
	cmd := fmt.Sprintf("$ErrorActionPreference='Stop'; %s %s %s", cmdlet, param, q)
	out, code, err := d.Exec.Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("%s exited %d: %s", cmdlet, code, clip(strings.TrimSpace(out), 300))
	}
	return nil
}

var exclParam = map[string]string{ExclPath: "-ExclusionPath", ExclExtension: "-ExclusionExtension", ExclProcess: "-ExclusionProcess"}

func (d ExecDefender) AddExclusion(ctx context.Context, e Exclusion) error {
	return d.mp(ctx, "Add-MpPreference", exclParam[e.Kind], e.Value)
}
func (d ExecDefender) RemoveExclusion(ctx context.Context, e Exclusion) error {
	return d.mp(ctx, "Remove-MpPreference", exclParam[e.Kind], e.Value)
}

func (d ExecDefender) RealtimeEnabled(ctx context.Context) (bool, error) {
	n, ok, err := regUint(ctx, d.Reg, `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`, "DisableRealtimeMonitoring")
	if err != nil {
		return false, err
	}
	return !ok || n == 0, nil
}
func (d ExecDefender) SetRealtime(ctx context.Context, on bool) error {
	cmd := fmt.Sprintf("$ErrorActionPreference='Stop'; Set-MpPreference -DisableRealtimeMonitoring $%v", !on)
	out, code, err := d.Exec.Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("Set-MpPreference exited %d: %s", code, clip(strings.TrimSpace(out), 300))
	}
	return nil
}

func defenderOrErr(env *Env) (DefenderBackend, error) {
	if env.Win.Defender == nil {
		return nil, unsupported("windows defender")
	}
	return env.Win.Defender, nil
}

type defUndo struct {
	Removed  []Exclusion `json:"removed"`
	Realtime *bool       `json:"realtime,omitempty"`
}

func init() {
	registerUndo(kindDefender, func(ctx context.Context, env *Env, e deadman.Entry) error {
		var u defUndo
		if err := jsonUndo(e, &u); err != nil {
			return err
		}
		d, err := defenderOrErr(env)
		if err != nil {
			return err
		}
		var errs []error
		for _, x := range u.Removed {
			errs = append(errs, d.AddExclusion(ctx, x))
		}
		if u.Realtime != nil {
			errs = append(errs, d.SetRealtime(ctx, *u.Realtime))
		}
		return errors.Join(errs...)
	})
}

func (e Exclusion) String() string { return e.Kind + ":" + e.Value }

func kept(e Exclusion, keep []string) bool {
	for _, k := range keep {
		k = strings.TrimRight(strings.ToLower(strings.ReplaceAll(k, "/", `\`)), `\`)
		v := strings.TrimRight(strings.ToLower(strings.ReplaceAll(e.Value, "/", `\`)), `\`)
		if e.Kind == ExclPath && (v == k || strings.HasPrefix(v, k+`\`)) || e.Kind != ExclPath && v == k {
			return true
		}
	}
	return false
}

// ---- win.defender.audit (read-only) ----

type defenderAudit struct{}

func (defenderAudit) Spec() Spec {
	return Spec{Name: "win.defender.audit", Risk: RiskNone, ReadOnly: true,
		Doc:    "List Defender exclusions (paths, extensions, processes) and real-time protection state. Anything beyond the allowed list is reported as unexpected (design: exactly one exclusion, the agent's install directory).",
		Params: []ParamSpec{{Name: "keep", Type: StringList, Max: 64}}}
}
func (defenderAudit) Locks(Params) []string  { return nil }
func (defenderAudit) Touches(Params) []Touch { return nil }
func (defenderAudit) Plan(_ context.Context, env *Env, _ Params) (Plan, error) {
	if _, err := defenderOrErr(env); err != nil {
		return Plan{}, err
	}
	return Plan{Diff: "read Defender exclusions"}, nil
}
func (defenderAudit) Capture(context.Context, *Env, Params) (Rollback, error) { return Rollback{}, nil }
func (defenderAudit) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	d, err := defenderOrErr(env)
	if err != nil {
		return nil, err
	}
	ex, err := d.Exclusions(ctx)
	if err != nil {
		return nil, err
	}
	var all, bad []string
	for _, e := range ex {
		all = append(all, e.String())
		if !kept(e, p.List("keep")) {
			bad = append(bad, e.String())
		}
	}
	rt, err := d.RealtimeEnabled(ctx)
	if err != nil {
		return nil, err
	}
	return Output{"exclusions": clip(strings.Join(all, "; "), 4096), "unexpected": clip(strings.Join(bad, "; "), 4096),
		"unexpected_count": fmt.Sprint(len(bad)), "realtime": fmt.Sprint(rt)}, nil
}
func (defenderAudit) Verify(context.Context, *Env, Params) error { return nil }

// ---- win.defender ----

type winDefender struct{}

func (winDefender) Spec() Spec {
	return Spec{Name: "win.defender", Risk: RiskService,
		Doc: "Remove Defender exclusions other than the kept ones (the agent's install directory) and make sure real-time protection is on. Removed exclusions are restored on rollback.",
		Params: []ParamSpec{
			{Name: "keep", Type: StringList, Max: 64},
			{Name: "ensure_realtime", Type: Bool, Default: true}}}
}
func (winDefender) Locks(Params) []string  { return []string{"defender"} }
func (winDefender) Touches(Params) []Touch { return nil }

func (winDefender) todo(ctx context.Context, env *Env, p Params) (rm []Exclusion, rtOff bool, err error) {
	d, err := defenderOrErr(env)
	if err != nil {
		return nil, false, err
	}
	ex, err := d.Exclusions(ctx)
	if err != nil {
		return nil, false, err
	}
	for _, e := range ex {
		if !kept(e, p.List("keep")) {
			rm = append(rm, e)
		}
	}
	if p.Bool("ensure_realtime") {
		on, err := d.RealtimeEnabled(ctx)
		if err != nil {
			return nil, false, err
		}
		rtOff = !on
	}
	return rm, rtOff, nil
}

func (a winDefender) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	rm, rtOff, err := a.todo(ctx, env, p)
	if err != nil {
		return Plan{}, err
	}
	var d []string
	for _, e := range rm {
		d = append(d, "- exclusion "+e.String())
	}
	if rtOff {
		d = append(d, "~ real-time protection: off -> on")
	}
	if len(d) == 0 {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: strings.Join(d, "\n")}, nil
}
func (a winDefender) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	rm, rtOff, err := a.todo(ctx, env, p)
	if err != nil {
		return Rollback{}, err
	}
	u := defUndo{Removed: rm}
	if rtOff {
		off := false
		u.Realtime = &off
	}
	return Rollback{Kind: kindDefender, Data: u}, nil
}
func (a winDefender) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	rm, rtOff, err := a.todo(ctx, env, p)
	if err != nil {
		return nil, err
	}
	d := env.Win.Defender
	for _, e := range rm {
		if err := d.RemoveExclusion(ctx, e); err != nil {
			return nil, fmt.Errorf("remove %s: %w", e, err)
		}
	}
	if rtOff {
		if err := d.SetRealtime(ctx, true); err != nil {
			return nil, err
		}
	}
	return Output{"removed": fmt.Sprint(len(rm))}, nil
}
func (a winDefender) Verify(ctx context.Context, env *Env, p Params) error {
	rm, rtOff, err := a.todo(ctx, env, p)
	if err != nil {
		return err
	}
	if len(rm) > 0 {
		return fmt.Errorf("%d exclusion(s) remain (policy-managed exclusions cannot be removed locally): %s", len(rm), rm[0])
	}
	if rtOff {
		return errors.New("real-time protection is still off")
	}
	return nil
}
