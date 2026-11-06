package actions

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

const kindRegistry = "win.registry"

// ParseRegValue converts the textual form used in plan params to a RegValue.
// dword/qword take decimal or 0x hex; multi_sz separates strings by newlines;
// binary is hex (spaces and commas ignored).
func ParseRegValue(typ, s string) (RegValue, error) {
	switch typ {
	case "dword":
		n, err := strconv.ParseUint(strings.TrimSpace(s), 0, 32)
		if err != nil {
			return RegValue{}, fmt.Errorf("dword: %w", err)
		}
		return RegValue{Type: typ, Num: n}, nil
	case "qword":
		n, err := strconv.ParseUint(strings.TrimSpace(s), 0, 64)
		if err != nil {
			return RegValue{}, fmt.Errorf("qword: %w", err)
		}
		return RegValue{Type: typ, Num: n}, nil
	case "sz", "expand_sz":
		if len(s) > 32<<10 || strings.ContainsRune(s, 0) {
			return RegValue{}, errors.New("string value too long or contains NUL")
		}
		return RegValue{Type: typ, Str: s}, nil
	case "multi_sz":
		if len(s) > 32<<10 || strings.ContainsRune(s, 0) {
			return RegValue{}, errors.New("multi_sz value too long or contains NUL")
		}
		var m []string
		for _, l := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
			if l != "" {
				m = append(m, l)
			}
		}
		return RegValue{Type: typ, Multi: m}, nil
	case "binary":
		c := strings.NewReplacer(" ", "", ",", "", ":", "").Replace(s)
		b, err := hex.DecodeString(c)
		if err != nil || len(b) > 64<<10 {
			return RegValue{}, errors.New("binary: want hex, at most 64 KiB")
		}
		return RegValue{Type: typ, Bin: b}, nil
	}
	return RegValue{}, fmt.Errorf("unknown registry type %q", typ)
}

// String renders a value for diffs.
func (v RegValue) String() string {
	switch v.Type {
	case "dword", "qword":
		return fmt.Sprintf("%s %d", v.Type, v.Num)
	case "sz", "expand_sz":
		return fmt.Sprintf("%s %q", v.Type, v.Str)
	case "multi_sz":
		return fmt.Sprintf("multi_sz %q", v.Multi)
	case "binary":
		return "binary " + hex.EncodeToString(v.Bin)
	}
	return v.Type
}

func (v RegValue) equal(o RegValue) bool {
	return v.Type == o.Type && v.Num == o.Num && v.Str == o.Str &&
		reflect.DeepEqual(append([]string(nil), v.Multi...), append([]string(nil), o.Multi...)) &&
		hex.EncodeToString(v.Bin) == hex.EncodeToString(o.Bin)
}

// regEdit is one wanted registry change; Val nil deletes the value.
type regEdit struct {
	Key, Name string
	Val       *RegValue
}

// regPrior records a value as it was before an edit.
type regPrior struct {
	Key     string   `json:"key"`
	Name    string   `json:"name"`
	Existed bool     `json:"existed"`
	Val     RegValue `json:"val"`
}

type regRollback struct {
	Priors []regPrior `json:"priors"`
}

func regStore(env *Env) (RegistryStore, error) {
	if env.Win.Reg == nil {
		return nil, Unsupported("registry")
	}
	return env.Win.Reg, nil
}

// planRegEdits returns the edits still needed and a diff of them.
func planRegEdits(ctx context.Context, rs RegistryStore, edits []regEdit) (pending []regEdit, diff string, err error) {
	var lines []string
	for _, e := range edits {
		cur, ok, err := rs.Get(ctx, e.Key, e.Name)
		if err != nil {
			return nil, "", fmt.Errorf("read %s\\%s: %w", e.Key, e.Name, err)
		}
		label := e.Key + `\` + e.Name
		switch {
		case e.Val == nil && !ok:
			continue
		case e.Val == nil:
			lines = append(lines, fmt.Sprintf("- %s = %s (delete)", label, cur))
		case ok && cur.equal(*e.Val):
			continue
		case ok:
			lines = append(lines, fmt.Sprintf("~ %s: %s -> %s", label, cur, *e.Val))
		default:
			lines = append(lines, fmt.Sprintf("+ %s = %s", label, *e.Val))
		}
		pending = append(pending, e)
	}
	return pending, strings.Join(lines, "\n"), nil
}

func capturePriors(ctx context.Context, rs RegistryStore, edits []regEdit) ([]regPrior, error) {
	var out []regPrior
	seen := map[string]bool{}
	for _, e := range edits {
		if seen[regPath(e.Key, e.Name)] {
			continue
		}
		seen[regPath(e.Key, e.Name)] = true
		v, ok, err := rs.Get(ctx, e.Key, e.Name)
		if err != nil {
			return nil, err
		}
		out = append(out, regPrior{Key: e.Key, Name: e.Name, Existed: ok, Val: v})
	}
	return out, nil
}

func applyRegEdits(ctx context.Context, rs RegistryStore, edits []regEdit) error {
	for _, e := range edits {
		var err error
		if e.Val == nil {
			err = rs.Delete(ctx, e.Key, e.Name)
		} else {
			err = rs.Set(ctx, e.Key, e.Name, *e.Val)
		}
		if err != nil {
			return fmt.Errorf("%s\\%s: %w", e.Key, e.Name, err)
		}
	}
	return nil
}

func verifyRegEdits(ctx context.Context, rs RegistryStore, edits []regEdit) error {
	pending, diff, err := planRegEdits(ctx, rs, edits)
	if err != nil {
		return err
	}
	if len(pending) > 0 {
		return fmt.Errorf("registry not in the wanted state:\n%s", diff)
	}
	return nil
}

func regRollbackOf(ctx context.Context, rs RegistryStore, edits []regEdit) (Rollback, error) {
	pr, err := capturePriors(ctx, rs, edits)
	if err != nil {
		return Rollback{}, err
	}
	return Rollback{Kind: kindRegistry, Data: regRollback{Priors: pr}}, nil
}

func init() {
	RegisterUndo(kindRegistry, func(ctx context.Context, env *Env, e deadman.Entry) error {
		var r regRollback
		if err := jsonUndo(e, &r); err != nil {
			return err
		}
		rs, err := regStore(env)
		if err != nil {
			return err
		}
		var errs []error
		for i := len(r.Priors) - 1; i >= 0; i-- {
			p := r.Priors[i]
			if p.Existed {
				errs = append(errs, rs.Set(ctx, p.Key, p.Name, p.Val))
			} else {
				errs = append(errs, rs.Delete(ctx, p.Key, p.Name))
			}
		}
		return errors.Join(errs...)
	})
}

// ---- scoring-aware registry policy ----

var (
	servicesKeyRe   = regexp.MustCompile(`(?i)^HKLM\\SYSTEM\\(?:CurrentControlSet|ControlSet001)\\Services\\([^\\]+)$`)
	lockoutNameRe   = regexp.MustCompile(`(?i)lockout|MaxDevicePasswordFailedAttempts`)
	persistenceKeys = []string{
		`\microsoft\windows\currentversion\run`, `\microsoft\windows\currentversion\runonce`,
		`\microsoft\windows nt\currentversion\image file execution options`,
		`\microsoft\windows nt\currentversion\winlogon`, `\microsoft\windows nt\currentversion\windows`,
		`\control\session manager\bootexecute`, `\control\lsa\notification packages`, `\control\lsa\security packages`,
	}
)

// regNumeric extracts a numeric value for policy checks.
func regNumeric(v RegValue) (uint64, bool) {
	if v.Type == "dword" || v.Type == "qword" {
		return v.Num, true
	}
	return 0, false
}

// registryPolicy applies the scoring-safety rules to a value write (nil value
// = delete). It returns a refusal, and the service touches the write implies
// so the scoring guard can refuse them where the service is scored.
func registryPolicy(key, name string, v *RegValue, write bool) (touches []Touch, err error) {
	lk, ln := strings.ToLower(key), strings.ToLower(name)
	refuse := func(why string) error {
		return fmt.Errorf("%w: registry %s\\%s: %s", ErrScoringUnsafe, key, name, why)
	}
	if strings.HasPrefix(lk, `hklm\sam`) || strings.HasPrefix(lk, `hklm\security`) {
		return nil, fmt.Errorf("registry %s: the SAM and SECURITY hives are not editable here", key)
	}
	if !write || v == nil {
		return nil, nil // deletes may clean anything (e.g. a planted Run value)
	}
	for _, p := range persistenceKeys {
		if strings.Contains(lk, p) {
			return nil, fmt.Errorf("registry %s: autostart and logon locations are not writable from plans (clean-up is registry.delete)", key)
		}
	}
	if lockoutNameRe.MatchString(ln) {
		return nil, refuse("lockout policy is never set on scored accounts")
	}
	n, isNum := regNumeric(*v)
	switch {
	case strings.HasSuffix(lk, `\control\lsa`) && ln == "lmcompatibilitylevel" && isNum && n < 3:
		return nil, refuse("LmCompatibilityLevel below 3 weakens NTLM; the scorer needs NTLMv2")
	case strings.HasSuffix(lk, `\control\lsa\msv1_0`) && (ln == "restrictreceivingntlmtraffic" || ln == "restrictsendingntlmtraffic") && isNum && n == 2:
		return nil, refuse("denying NTLM breaks the scorer's NTLM transport")
	case strings.HasSuffix(lk, `\control\lsa\msv1_0`) && (ln == "ntlmminserversec" || ln == "ntlmminclientsec") && isNum && n&0x30 != 0:
		return nil, refuse("requiring NTLM message integrity or confidentiality is untested against the scorer")
	case strings.Contains(lk, `\policies\microsoft\windows\winrm\`) && ln == "allowunencrypted" && isNum && n == 0:
		return nil, refuse("WinRM AllowUnencrypted=false breaks plain NTLM over 5985")
	case strings.HasSuffix(lk, `\services\lanmanserver\parameters`) && ln == "encryptdata" && isNum && n != 0:
		return nil, refuse("SMB encryption is untested against go-smb2")
	case strings.Contains(lk, `\supersocketnetlib`) && ln == "forceencryption" && isNum && n == 1:
		return nil, refuse("MSSQL ForceEncryption needs a scorer-mimic pass")
	case strings.HasSuffix(lk, `\control\terminal server`) && ln == "fdenytsconnections" && isNum && n == 1:
		touches = append(touches, Touch{Kind: TouchService, Name: "TermService", Op: OpDisable})
	case strings.HasSuffix(lk, `\policies\microsoft\windows\winrm\service`) && ln == "allowautoconfig" && isNum && n == 0:
		touches = append(touches, Touch{Kind: TouchService, Name: "WinRM", Op: OpDisable})
	case strings.HasSuffix(lk, `\services\lanmanserver\parameters`) && ln == "smb2" && isNum && n == 0:
		touches = append(touches, Touch{Kind: TouchService, Name: "LanmanServer", Op: OpDisable})
	}
	if m := servicesKeyRe.FindStringSubmatch(key); m != nil && ln == "start" && isNum && n == 4 {
		touches = append(touches, Touch{Kind: TouchService, Name: m[1], Op: OpDisable})
	}
	return touches, nil
}

// ---- registry.set / registry.delete ----

var regTypes = []string{"dword", "qword", "sz", "expand_sz", "multi_sz", "binary"}

func checkRegKey(v any) error {
	_, err := normRegKey(v.(string))
	return err
}

type registrySet struct{ del bool }

func (r registrySet) Spec() Spec {
	ps := []ParamSpec{
		{Name: "key", Type: String, Required: true, Max: 600, Check: checkRegKey},
		{Name: "name", Type: String, Required: true, Max: 255}, // "" is the (Default) value
	}
	name, doc := "registry.set", "Set an HKLM registry value; the prior value is captured for rollback (scoring-aware: refuses NTLM, lockout, encryption-required and autostart writes)."
	if r.del {
		name, doc = "registry.delete", "Delete an HKLM registry value; the prior value is captured for rollback."
	} else {
		ps = append(ps,
			ParamSpec{Name: "type", Type: Enum, Required: true, Enum: regTypes},
			ParamSpec{Name: "value", Type: String, Required: true, Max: 64 << 10})
	}
	return Spec{Name: name, Risk: RiskService, Params: ps, Doc: doc}
}

func (r registrySet) edit(p Params) (regEdit, error) {
	key, err := normRegKey(p.Str("key"))
	if err != nil {
		return regEdit{}, err
	}
	e := regEdit{Key: key, Name: p.Str("name")}
	if !r.del {
		v, err := ParseRegValue(p.Str("type"), p.Str("value"))
		if err != nil {
			return regEdit{}, err
		}
		e.Val = &v
	}
	return e, nil
}

func (r registrySet) Locks(Params) []string { return []string{"registry"} }
func (r registrySet) Touches(p Params) []Touch {
	e, err := r.edit(p)
	if err != nil {
		return nil
	}
	t, _ := registryPolicy(e.Key, e.Name, e.Val, !r.del)
	return t
}

func (r registrySet) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	e, err := r.edit(p)
	if err != nil {
		return Plan{}, err
	}
	if _, err := registryPolicy(e.Key, e.Name, e.Val, !r.del); err != nil {
		return Plan{}, err
	}
	rs, err := regStore(env)
	if err != nil {
		return Plan{}, err
	}
	pend, diff, err := planRegEdits(ctx, rs, []regEdit{e})
	if err != nil {
		return Plan{}, err
	}
	if len(pend) == 0 {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: diff}, nil
}

func (r registrySet) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	e, err := r.edit(p)
	if err != nil {
		return Rollback{}, err
	}
	rs, err := regStore(env)
	if err != nil {
		return Rollback{}, err
	}
	return regRollbackOf(ctx, rs, []regEdit{e})
}

func (r registrySet) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	e, _ := r.edit(p)
	if _, err := registryPolicy(e.Key, e.Name, e.Val, !r.del); err != nil {
		return nil, err // defence in depth: Plan already refused
	}
	return nil, applyRegEdits(ctx, env.Win.Reg, []regEdit{e})
}

func (r registrySet) Verify(ctx context.Context, env *Env, p Params) error {
	e, _ := r.edit(p)
	return verifyRegEdits(ctx, env.Win.Reg, []regEdit{e})
}
