package actions

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

const kindAudit = "win.audit"

const (
	auditCmdlineKey  = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`
	auditCmdlineName = "ProcessCreationIncludeCmdLine_Enabled"
	lsaKey           = `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
)

// auditSubcategories are the subcategories plans may set (exact English names
// as auditpol prints them); a closed list keeps arguments out of auditpol's
// command line that are not audit subcategories.
var auditSubcategories = map[string]bool{}

func init() {
	for _, s := range []string{
		"Process Creation", "Process Termination", "Logon", "Logoff", "Account Lockout", "Special Logon",
		"Other Logon/Logoff Events", "User Account Management", "Computer Account Management",
		"Security Group Management", "Other Account Management Events", "Directory Service Access",
		"Directory Service Changes", "Directory Service Replication", "Credential Validation",
		"Kerberos Authentication Service", "Kerberos Service Ticket Operations", "Other Account Logon Events",
		"Sensitive Privilege Use", "Audit Policy Change", "Authentication Policy Change", "Authorization Policy Change",
		"Security System Extension", "System Integrity", "Security State Change", "Registry", "File System",
		"Other Object Access Events", "Scheduled Tasks", "Detailed File Share", "File Share", "Filtering Platform Connection",
		"Plug and Play Events", "Network Policy Server",
	} {
		auditSubcategories[strings.ToLower(s)] = true
	}
	registerUndo(kindAudit, func(ctx context.Context, env *Env, e deadman.Entry) error {
		var u auditUndo
		if err := jsonUndo(e, &u); err != nil {
			return err
		}
		if env.Win.Audit == nil {
			return unsupported("audit policy")
		}
		var errs []error
		for name, s := range u.Prior {
			errs = append(errs, env.Win.Audit.Set(ctx, name, s))
		}
		if len(u.Reg.Priors) > 0 {
			rs, err := regStore(env)
			if err != nil {
				return errors.Join(append(errs, err)...)
			}
			for i := len(u.Reg.Priors) - 1; i >= 0; i-- {
				p := u.Reg.Priors[i]
				if p.Existed {
					errs = append(errs, rs.Set(ctx, p.Key, p.Name, p.Val))
				} else {
					errs = append(errs, rs.Delete(ctx, p.Key, p.Name))
				}
			}
		}
		return errors.Join(errs...)
	})
}

type auditUndo struct {
	Prior map[string]AuditSetting `json:"prior"`
	Reg   regRollback             `json:"reg"`
}

// auditProfiles are presets matching the detection catalog (4688 with command
// line, account and group changes 4720-4781, directory changes 5136/5137/4662,
// Kerberos 4768/4769, policy changes).
var auditProfiles = map[string]map[string]string{
	"member": {
		"Process Creation": "success", "Logon": "success,failure", "Special Logon": "success",
		"User Account Management": "success,failure", "Security Group Management": "success,failure",
		"Audit Policy Change": "success", "Security State Change": "success", "Scheduled Tasks": "success",
		"Other Object Access Events": "success", "Credential Validation": "success,failure",
	},
	"dc": {
		"Process Creation": "success", "Logon": "success,failure", "Special Logon": "success",
		"User Account Management": "success,failure", "Security Group Management": "success,failure",
		"Computer Account Management": "success", "Directory Service Changes": "success",
		"Directory Service Access": "success", "Kerberos Authentication Service": "success,failure",
		"Kerberos Service Ticket Operations": "success,failure", "Credential Validation": "success,failure",
		"Audit Policy Change": "success", "Authentication Policy Change": "success", "Sensitive Privilege Use": "success,failure",
		"Scheduled Tasks": "success", "Other Object Access Events": "success", "Security State Change": "success",
	},
}

// ParseAuditSetting parses "success", "failure", "success,failure" or "none".
func ParseAuditSetting(s string) (AuditSetting, error) {
	var a AuditSetting
	for _, f := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return r == ',' || r == ' ' || r == '+' }) {
		switch f {
		case "success":
			a.Success = true
		case "failure":
			a.Failure = true
		case "none", "no", "disable":
		default:
			return a, fmt.Errorf("unknown audit setting %q (success, failure, success,failure or none)", f)
		}
	}
	return a, nil
}

// ExecAudit implements AuditPolicy with auditpol.exe through an Executor (the
// documented fallback to the AuditSetSystemPolicy API). English output only.
type ExecAudit struct{ Exec Executor }

const auditpolExe = "auditpol.exe"

func (a ExecAudit) Get(ctx context.Context, sub string) (AuditSetting, error) {
	if !auditSubcategories[strings.ToLower(sub)] {
		return AuditSetting{}, fmt.Errorf("unknown audit subcategory %q", sub)
	}
	out, code, err := a.Exec.Run(ctx, auditpolExe, "/get", "/subcategory:"+sub, "/r")
	if err != nil {
		return AuditSetting{}, err
	}
	if code != 0 {
		return AuditSetting{}, fmt.Errorf("auditpol /get exited %d: %s", code, clip(strings.TrimSpace(out), 200))
	}
	rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		return AuditSetting{}, fmt.Errorf("auditpol output: %w", err)
	}
	for _, r := range rows {
		if len(r) >= 5 && strings.EqualFold(strings.TrimSpace(r[2]), sub) {
			v := strings.ToLower(r[4])
			return AuditSetting{Success: strings.Contains(v, "success"), Failure: strings.Contains(v, "failure")}, nil
		}
	}
	return AuditSetting{}, fmt.Errorf("auditpol did not report %q", sub)
}

func (a ExecAudit) Set(ctx context.Context, sub string, s AuditSetting) error {
	if !auditSubcategories[strings.ToLower(sub)] {
		return fmt.Errorf("unknown audit subcategory %q", sub)
	}
	en := func(b bool) string {
		if b {
			return "enable"
		}
		return "disable"
	}
	out, code, err := a.Exec.Run(ctx, auditpolExe, "/set", "/subcategory:"+sub, "/success:"+en(s.Success), "/failure:"+en(s.Failure))
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("auditpol /set exited %d: %s", code, clip(strings.TrimSpace(out), 200))
	}
	return nil
}

type winAudit struct{}

func (winAudit) Spec() Spec {
	return Spec{Name: "win.audit_policy.set", Risk: RiskService,
		Doc: "Set advanced audit policy subcategories (auditpol) and process-creation command-line logging (event 4688 command line). profile dc|member applies the detection catalog's baseline; subcategories overrides single entries (success, failure, success,failure, none).",
		Params: []ParamSpec{
			{Name: "profile", Type: Enum, Enum: []string{"dc", "member"}},
			{Name: "subcategories", Type: StringMap},
			{Name: "cmdline", Type: Bool, Default: true}}}
}
func (winAudit) Locks(Params) []string  { return []string{LockAudit} }
func (winAudit) Touches(Params) []Touch { return nil }

// wanted merges the profile and explicit subcategories.
func (winAudit) wanted(p Params) (map[string]AuditSetting, error) {
	raw := map[string]string{}
	for k, v := range auditProfiles[p.Str("profile")] {
		raw[k] = v
	}
	for k, v := range p.Map("subcategories") {
		raw[k] = v
	}
	out := map[string]AuditSetting{}
	for k, v := range raw {
		if !auditSubcategories[strings.ToLower(k)] {
			return nil, fmt.Errorf("unknown audit subcategory %q", k)
		}
		s, err := ParseAuditSetting(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		out[k] = s
	}
	return out, nil
}

func (a winAudit) regEdits(p Params, adv bool) []regEdit {
	var es []regEdit
	if p.Bool("cmdline") {
		es = append(es, regEdit{Key: auditCmdlineKey, Name: auditCmdlineName, Val: dword(1)})
	}
	if adv {
		// Make advanced audit policy override the legacy category policy.
		es = append(es, regEdit{Key: lsaKey, Name: "SCENoApplyLegacyAuditPolicy", Val: dword(1)})
	}
	return es
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func (a winAudit) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	want, err := a.wanted(p)
	if err != nil {
		return Plan{}, err
	}
	if len(want) == 0 && !p.Bool("cmdline") {
		return Plan{}, errors.New("nothing requested")
	}
	var d []string
	if len(want) > 0 {
		if env.Win.Audit == nil {
			return Plan{}, unsupported("audit policy")
		}
		for _, k := range sortedKeys(want) {
			cur, err := env.Win.Audit.Get(ctx, k)
			if err != nil {
				return Plan{}, err
			}
			if cur != want[k] {
				d = append(d, fmt.Sprintf("~ audit %s: %s -> %s", k, cur, want[k]))
			}
		}
	}
	if es := a.regEdits(p, len(want) > 0); len(es) > 0 {
		rs, err := regStore(env)
		if err != nil {
			return Plan{}, err
		}
		pend, diff, err := planRegEdits(ctx, rs, es)
		if err != nil {
			return Plan{}, err
		}
		if len(pend) > 0 {
			d = append(d, diff)
		}
	}
	if len(d) == 0 {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: strings.Join(d, "\n")}, nil
}

func (a winAudit) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	want, err := a.wanted(p)
	if err != nil {
		return Rollback{}, err
	}
	u := auditUndo{Prior: map[string]AuditSetting{}}
	for k := range want {
		cur, err := env.Win.Audit.Get(ctx, k)
		if err != nil {
			return Rollback{}, err
		}
		u.Prior[k] = cur
	}
	if es := a.regEdits(p, len(want) > 0); len(es) > 0 {
		rs, err := regStore(env)
		if err != nil {
			return Rollback{}, err
		}
		pr, err := capturePriors(ctx, rs, es)
		if err != nil {
			return Rollback{}, err
		}
		u.Reg = regRollback{Priors: pr}
	}
	return Rollback{Kind: kindAudit, Data: u}, nil
}

func (a winAudit) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	want, _ := a.wanted(p)
	for _, k := range sortedKeys(want) {
		if err := env.Win.Audit.Set(ctx, k, want[k]); err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
	}
	if es := a.regEdits(p, len(want) > 0); len(es) > 0 {
		return nil, applyRegEdits(ctx, env.Win.Reg, es)
	}
	return nil, nil
}

func (a winAudit) Verify(ctx context.Context, env *Env, p Params) error {
	want, _ := a.wanted(p)
	for _, k := range sortedKeys(want) {
		cur, err := env.Win.Audit.Get(ctx, k)
		if err != nil {
			return err
		}
		if cur != want[k] {
			return fmt.Errorf("audit %s is %s, want %s", k, cur, want[k])
		}
	}
	return verifyRegEdits(ctx, env.Win.Reg, a.regEdits(p, len(want) > 0))
}
