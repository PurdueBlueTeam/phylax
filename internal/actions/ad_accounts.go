package actions

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

// Domain account actions, run by the DC's agent. Guard rules (scoring-safety
// lint): scored accounts are never disabled, locked or stripped of access
// groups, scored passwords change only in a PCR transaction, no lockout
// machinery is ever set, and the built-in Administrator and the last domain
// admin are never removed or disabled.

const kindADUndo = "ad.restore"

// adProtectedGroups are the groups AdminSDHolder/SDProp protects; objects with
// adminCount=1 that are not (nested) members of one of them are stale.
var adProtectedGroups = []string{
	"Account Operators", "Administrators", "Backup Operators", "Domain Admins", "Domain Controllers",
	"Enterprise Admins", "Print Operators", "Read-only Domain Controllers", "Replicator", "Schema Admins", "Server Operators",
}

type adUndoOp struct {
	Op    string `json:"op"` // enable | disable | admincount | addmember | rmmember
	DN    string `json:"dn"`
	Group string `json:"group,omitempty"`
	N     int    `json:"n,omitempty"`
}

type adUndo struct {
	Ops []adUndoOp `json:"ops"`
}

func init() {
	RegisterUndo(kindADUndo, func(ctx context.Context, env *Env, e deadman.Entry) error {
		var u adUndo
		if err := jsonUndo(e, &u); err != nil {
			return err
		}
		ad, err := adOrErr(env)
		if err != nil {
			return err
		}
		var errs []error
		for i := len(u.Ops) - 1; i >= 0; i-- {
			o := u.Ops[i]
			switch o.Op {
			case "enable":
				errs = append(errs, ad.SetEnabled(ctx, o.DN, true))
			case "disable":
				errs = append(errs, ad.SetEnabled(ctx, o.DN, false))
			case "admincount":
				errs = append(errs, ad.SetAdminCount(ctx, o.DN, o.N))
			case "addmember":
				errs = append(errs, ad.AddMember(ctx, o.Group, o.DN))
			case "rmmember":
				errs = append(errs, ad.RemoveMember(ctx, o.Group, o.DN))
			}
		}
		return errors.Join(errs...)
	})
}

func isRID500(o ADObject) bool { return strings.HasSuffix(o.SID, "-500") }
func isKrbtgt(o ADObject) bool { return strings.EqualFold(o.SAM, "krbtgt") }

func samListCheck(v any) error {
	for _, s := range v.([]string) {
		if !nameRe.MatchString(s) && !strings.ContainsAny(s, " ") {
			return fmt.Errorf("invalid account name %q", s)
		}
		if len(s) > 64 {
			return fmt.Errorf("name %q too long", s)
		}
	}
	return nil
}

func resolveUsers(ctx context.Context, ad ADBackend, names []string) ([]ADObject, error) {
	var out []ADObject
	for _, n := range names {
		o, ok, err := ad.Find(ctx, n)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("no such account %q", n)
		}
		if o.Class == "group" {
			return nil, fmt.Errorf("%q is a group, not an account", n)
		}
		out = append(out, o)
	}
	return out, nil
}

// effectiveAdmins returns the enabled leaf members of Domain Admins, nested.
func effectiveMembers(ctx context.Context, ad ADBackend, group string) ([]Member, error) {
	g, ok, err := ad.Find(ctx, group)
	if err != nil || !ok {
		return nil, err
	}
	m, _, err := ResolveMembers(ctx, ad, g)
	return m, err
}

// ---- ad.account.audit_groups (read-only) ----

type adAuditGroups struct{}

func (adAuditGroups) Spec() Spec {
	return Spec{Name: "ad.account.audit_groups", Risk: RiskNone, ReadOnly: true,
		Doc: "Audit membership of privileged groups, resolving nested groups recursively (cycles and depth bounded), and report members not in the allow list. fail_on_unexpected turns findings into a failed step.",
		Params: []ParamSpec{
			{Name: "groups", Type: StringList, Max: 64},
			{Name: "allow", Type: StringList, Max: 4096, Check: samListCheck},
			{Name: "fail_on_unexpected", Type: Bool}}}
}
func (adAuditGroups) Locks(Params) []string  { return nil }
func (adAuditGroups) Touches(Params) []Touch { return nil }
func (adAuditGroups) Plan(_ context.Context, env *Env, _ Params) (Plan, error) {
	if _, err := adOrErr(env); err != nil {
		return Plan{}, err
	}
	return Plan{Diff: "read privileged group membership"}, nil
}
func (adAuditGroups) Capture(context.Context, *Env, Params) (Rollback, error) { return Rollback{}, nil }

type auditFinding struct {
	out        Output
	unexpected []string
}

func (a adAuditGroups) audit(ctx context.Context, env *Env, p Params) (auditFinding, error) {
	ad, err := adOrErr(env)
	if err != nil {
		return auditFinding{}, err
	}
	groups := p.List("groups")
	if len(groups) == 0 {
		groups = PrivilegedGroups
	}
	allow := map[string]bool{}
	for _, s := range p.List("allow") {
		allow[strings.ToLower(s)] = true
	}
	f := auditFinding{out: Output{}}
	var missing []string
	seenUnexpected := map[string]bool{}
	for _, name := range groups {
		g, ok, err := ad.Find(ctx, name)
		if err != nil {
			return f, err
		}
		if !ok || g.Class != "group" {
			missing = append(missing, name)
			continue
		}
		leaves, nested, err := ResolveMembers(ctx, ad, g)
		if err != nil {
			return f, err
		}
		var ms []string
		for _, m := range leaves {
			state := ""
			if m.Obj.Class != "other" && !m.Obj.Enabled {
				state = " [disabled]"
			}
			ms = append(ms, m.Path+state)
			if !allow[strings.ToLower(m.SAM)] {
				k := strings.ToLower(m.DN)
				if !seenUnexpected[k] {
					seenUnexpected[k] = true
					f.unexpected = append(f.unexpected, fmt.Sprintf("%s (%s)", m.SAM, m.Path))
				}
			}
		}
		sort.Strings(ms)
		f.out["members."+name] = clip(strings.Join(ms, "; "), 4096)
		if len(nested) > 1 {
			f.out["nested_groups."+name] = strings.Join(nested[1:], ",")
		}
	}
	sort.Strings(f.unexpected)
	f.out["unexpected"] = clip(strings.Join(f.unexpected, "; "), 4096)
	f.out["unexpected_count"] = fmt.Sprint(len(f.unexpected))
	if len(missing) > 0 {
		f.out["groups_not_found"] = strings.Join(missing, ",")
	}
	return f, nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func (a adAuditGroups) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	f, err := a.audit(ctx, env, p)
	return f.out, err
}
func (a adAuditGroups) Verify(ctx context.Context, env *Env, p Params) error {
	if !p.Bool("fail_on_unexpected") {
		return nil
	}
	f, err := a.audit(ctx, env, p)
	if err != nil {
		return err
	}
	if len(f.unexpected) > 0 {
		return fmt.Errorf("%d unexpected privileged member(s): %s", len(f.unexpected), clip(strings.Join(f.unexpected, "; "), 600))
	}
	return nil
}

// ---- ad.account.admincount_sweep ----

type adAdminCount struct{}

func (adAdminCount) Spec() Spec {
	return Spec{Name: "ad.account.admincount_sweep", Risk: RiskService,
		Doc:    "Find objects with adminCount=1 that are no longer (nested) members of a protected group and clear the flag. Reports only with report_only. ACL inheritance on the objects is not repaired here.",
		Params: []ParamSpec{{Name: "report_only", Type: Bool}}}
}
func (adAdminCount) Locks(Params) []string  { return []string{LockAccounts} }
func (adAdminCount) Touches(Params) []Touch { return nil }

func (adAdminCount) stale(ctx context.Context, env *Env) ([]ADObject, error) {
	ad, err := adOrErr(env)
	if err != nil {
		return nil, err
	}
	protected := map[string]bool{}
	for _, name := range adProtectedGroups {
		g, ok, err := ad.Find(ctx, name)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		protected[strings.ToLower(g.DN)] = true
		leaves, _, err := ResolveMembers(ctx, ad, g)
		if err != nil {
			return nil, err
		}
		// ResolveMembers reports leaves only; nested groups are protected too.
		for _, m := range leaves {
			protected[strings.ToLower(m.DN)] = true
		}
		if err := markNestedGroups(ctx, ad, g, protected, 0); err != nil {
			return nil, err
		}
	}
	all, err := ad.AdminCountSet(ctx)
	if err != nil {
		return nil, err
	}
	var out []ADObject
	for _, o := range all {
		if protected[strings.ToLower(o.DN)] || isKrbtgt(o) || isRID500(o) {
			continue
		}
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DN < out[j].DN })
	return out, nil
}

func markNestedGroups(ctx context.Context, ad ADBackend, g ADObject, set map[string]bool, depth int) error {
	if depth > maxNestDepth {
		return nil
	}
	for _, dn := range g.Members {
		o, ok, err := ad.Get(ctx, dn)
		if err != nil {
			return err
		}
		if ok && o.Class == "group" && !set[strings.ToLower(o.DN)+"#g"] {
			set[strings.ToLower(o.DN)+"#g"] = true
			set[strings.ToLower(o.DN)] = true
			if err := markNestedGroups(ctx, ad, o, set, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a adAdminCount) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	st, err := a.stale(ctx, env)
	if err != nil {
		return Plan{}, err
	}
	if len(st) == 0 {
		return Plan{Done: true}, nil
	}
	var d []string
	for _, o := range st {
		d = append(d, fmt.Sprintf("~ %s: adminCount 1 -> 0", o.DN))
	}
	if p.Bool("report_only") {
		return Plan{Done: true, Notes: append([]string{"report only; stale adminCount objects:"}, d...)}, nil
	}
	return Plan{Diff: strings.Join(d, "\n"), Notes: []string{"object ACL inheritance stays disabled until re-enabled"}}, nil
}
func (a adAdminCount) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	st, err := a.stale(ctx, env)
	if err != nil {
		return Rollback{}, err
	}
	var u adUndo
	for _, o := range st {
		u.Ops = append(u.Ops, adUndoOp{Op: "admincount", DN: o.DN, N: o.AdminCount})
	}
	return Rollback{Kind: kindADUndo, Data: u}, nil
}
func (a adAdminCount) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	st, err := a.stale(ctx, env)
	if err != nil {
		return nil, err
	}
	for _, o := range st {
		if err := env.Win.AD.SetAdminCount(ctx, o.DN, 0); err != nil {
			return nil, fmt.Errorf("%s: %w", o.DN, err)
		}
	}
	return Output{"cleared": fmt.Sprint(len(st))}, nil
}
func (a adAdminCount) Verify(ctx context.Context, env *Env, _ Params) error {
	st, err := a.stale(ctx, env)
	if err != nil {
		return err
	}
	if len(st) > 0 {
		return fmt.Errorf("%d stale adminCount object(s) remain", len(st))
	}
	return nil
}

// ---- ad.account.disable ----

type adDisable struct{}

func (adDisable) Spec() Spec {
	return Spec{Name: "ad.account.disable", Risk: RiskLockout,
		Doc:    "Disable domain accounts (unexpected admins, stale service accounts). Scored accounts, the built-in Administrator, krbtgt and the last enabled domain admin are refused.",
		Params: []ParamSpec{{Name: "users", Type: StringList, Required: true, Max: 256, Check: samListCheck}}}
}
func (adDisable) Locks(Params) []string { return []string{LockAccounts} }
func (adDisable) Touches(p Params) []Touch {
	var ts []Touch
	for _, u := range p.List("users") {
		ts = append(ts, acctTouch(u, OpLock))
	}
	return ts
}
func (adDisable) targets(ctx context.Context, env *Env, p Params) ([]ADObject, error) {
	ad, err := adOrErr(env)
	if err != nil {
		return nil, err
	}
	objs, err := resolveUsers(ctx, ad, p.List("users"))
	if err != nil {
		return nil, err
	}
	for _, o := range objs {
		if isRID500(o) || isKrbtgt(o) {
			return nil, fmt.Errorf("%w: %s is the built-in Administrator or krbtgt", ErrScoringUnsafe, o.SAM)
		}
	}
	// The last enabled domain admin must survive.
	das, err := effectiveMembers(ctx, ad, "Domain Admins")
	if err != nil {
		return nil, err
	}
	gone := map[string]bool{}
	for _, o := range objs {
		gone[strings.ToLower(o.DN)] = true
	}
	left := 0
	for _, m := range das {
		if m.Obj.Enabled && !gone[strings.ToLower(m.DN)] {
			left++
		}
	}
	if len(das) > 0 && left == 0 {
		return nil, errors.New("refusing: this would disable the last enabled Domain Admin")
	}
	return objs, nil
}
func (a adDisable) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	objs, err := a.targets(ctx, env, p)
	if err != nil {
		return Plan{}, err
	}
	var d []string
	for _, o := range objs {
		if o.Enabled {
			d = append(d, "~ "+o.SAM+": enabled -> disabled")
		}
	}
	if len(d) == 0 {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: strings.Join(d, "\n")}, nil
}
func (a adDisable) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	objs, err := a.targets(ctx, env, p)
	if err != nil {
		return Rollback{}, err
	}
	var u adUndo
	for _, o := range objs {
		if o.Enabled {
			u.Ops = append(u.Ops, adUndoOp{Op: "enable", DN: o.DN})
		}
	}
	return Rollback{Kind: kindADUndo, Data: u}, nil
}
func (a adDisable) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	objs, err := a.targets(ctx, env, p)
	if err != nil {
		return nil, err
	}
	for _, o := range objs {
		if o.Enabled {
			if err := env.Win.AD.SetEnabled(ctx, o.DN, false); err != nil {
				return nil, fmt.Errorf("%s: %w", o.SAM, err)
			}
		}
	}
	return nil, nil
}
func (adDisable) Verify(ctx context.Context, env *Env, p Params) error {
	objs, err := resolveUsers(ctx, env.Win.AD, p.List("users"))
	if err != nil {
		return err
	}
	for _, o := range objs {
		if o.Enabled {
			return fmt.Errorf("%s is still enabled", o.SAM)
		}
	}
	return nil
}

// ---- ad.account.reset_password ----

type adResetPassword struct{}

func (adResetPassword) Spec() Spec {
	return Spec{Name: "ad.account.reset_password", Risk: RiskLockout,
		Doc: "Reset a domain account's password (non-scored accounts; scored ones only in a PCR transaction). krbtgt has its own guarded action.",
		Params: []ParamSpec{
			{Name: "user", Type: String, Required: true, Max: 64, Check: func(v any) error { return samListCheck([]string{v.(string)}) }},
			{Name: "password", Type: String, Required: true, Secret: true, Max: 256},
			{Name: "must_change", Type: Bool}}}
}
func (adResetPassword) Locks(Params) []string { return []string{LockAccounts} }
func (adResetPassword) Touches(p Params) []Touch {
	return []Touch{acctTouch(p.Str("user"), OpSetPassword)}
}
func (adResetPassword) target(ctx context.Context, env *Env, p Params) (ADObject, error) {
	ad, err := adOrErr(env)
	if err != nil {
		return ADObject{}, err
	}
	objs, err := resolveUsers(ctx, ad, []string{p.Str("user")})
	if err != nil {
		return ADObject{}, err
	}
	if isKrbtgt(objs[0]) {
		return ADObject{}, errors.New("krbtgt is reset with ad.account.krbtgt_reset")
	}
	return objs[0], nil
}
func (a adResetPassword) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	o, err := a.target(ctx, env, p)
	if err != nil {
		return Plan{}, err
	}
	return Plan{Diff: "reset password of " + o.SAM + ": <redacted>", Notes: []string{"not reversible: the old password is unknown to the agent"}}, nil
}
func (adResetPassword) Capture(context.Context, *Env, Params) (Rollback, error) {
	return Rollback{}, nil
}
func (a adResetPassword) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	o, err := a.target(ctx, env, p)
	if err != nil {
		return nil, err
	}
	if err := env.Win.AD.SetPassword(ctx, o.DN, p.Str("password"), p.Bool("must_change")); err != nil {
		return nil, redactErr(err, p.Str("password"))
	}
	return nil, nil
}
func (a adResetPassword) Verify(ctx context.Context, env *Env, p Params) error {
	o, err := a.target(ctx, env, p)
	if err != nil {
		return err
	}
	if o.PwdLastSet.IsZero() {
		return nil
	}
	if env.Now().Sub(o.PwdLastSet) > time.Hour && !p.Bool("must_change") {
		return errors.New("pwdLastSet did not move after the reset")
	}
	return nil
}

// ---- ad.account.group_remove ----

type adGroupRemove struct{}

func (adGroupRemove) Spec() Spec {
	return Spec{Name: "ad.account.group_remove", Risk: RiskLockout,
		Doc: "Remove direct members from a (privileged) group. Members only nested through another group are reported so the nesting group can be dealt with. The built-in Administrator and the last enabled Domain Admin are refused; scored accounts keep their access groups.",
		Params: []ParamSpec{
			{Name: "group", Type: String, Required: true, Max: 64, Check: func(v any) error { return samListCheck([]string{v.(string)}) }},
			{Name: "members", Type: StringList, Required: true, Max: 256, Check: samListCheck}}}
}
func (adGroupRemove) Locks(Params) []string { return []string{LockAccounts} }
func (adGroupRemove) Touches(p Params) []Touch {
	var ts []Touch
	for _, m := range p.List("members") {
		ts = append(ts, Touch{Kind: TouchAccount, Name: m, Op: OpRemoveFromGroup, Group: p.Str("group")})
	}
	return ts
}

func (adGroupRemove) targets(ctx context.Context, env *Env, p Params) (g ADObject, objs []ADObject, direct []bool, err error) {
	ad, err := adOrErr(env)
	if err != nil {
		return
	}
	g, ok, err := ad.Find(ctx, p.Str("group"))
	if err != nil {
		return
	}
	if !ok || g.Class != "group" {
		err = fmt.Errorf("no such group %q", p.Str("group"))
		return
	}
	objs, err = resolveUsers(ctx, ad, p.List("members"))
	if err != nil {
		return
	}
	in := map[string]bool{}
	for _, m := range g.Members {
		in[strings.ToLower(m)] = true
	}
	leaves, _, rerr := ResolveMembers(ctx, ad, g)
	if rerr != nil {
		err = rerr
		return
	}
	via := map[string]string{}
	for _, m := range leaves {
		via[strings.ToLower(m.DN)] = m.Path
	}
	for _, o := range objs {
		d := in[strings.ToLower(o.DN)]
		direct = append(direct, d)
		if !d {
			if path, nested := via[strings.ToLower(o.DN)]; nested {
				err = fmt.Errorf("%s is a member of %s only through nesting (%s); remove the nesting group or the member from it", o.SAM, g.SAM, path)
				return
			}
		}
		if d && isRID500(o) {
			err = fmt.Errorf("%w: the built-in Administrator stays in %s", ErrScoringUnsafe, g.SAM)
			return
		}
	}
	if strings.EqualFold(g.SAM, "Domain Admins") {
		gone := map[string]bool{}
		for i, o := range objs {
			if direct[i] {
				gone[strings.ToLower(o.DN)] = true
			}
		}
		left := 0
		for _, m := range leaves {
			if m.Obj.Enabled && !gone[strings.ToLower(m.DN)] {
				left++
			}
		}
		if left == 0 {
			err = errors.New("refusing: this would leave Domain Admins without an enabled member")
		}
	}
	return
}
func (a adGroupRemove) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	g, objs, direct, err := a.targets(ctx, env, p)
	if err != nil {
		return Plan{}, err
	}
	var d []string
	for i, o := range objs {
		if direct[i] {
			d = append(d, fmt.Sprintf("- %s from %s", o.SAM, g.SAM))
		}
	}
	if len(d) == 0 {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: strings.Join(d, "\n")}, nil
}
func (a adGroupRemove) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	g, objs, direct, err := a.targets(ctx, env, p)
	if err != nil {
		return Rollback{}, err
	}
	var u adUndo
	for i, o := range objs {
		if direct[i] {
			u.Ops = append(u.Ops, adUndoOp{Op: "addmember", DN: o.DN, Group: g.DN})
		}
	}
	return Rollback{Kind: kindADUndo, Data: u}, nil
}
func (a adGroupRemove) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	g, objs, direct, err := a.targets(ctx, env, p)
	if err != nil {
		return nil, err
	}
	for i, o := range objs {
		if direct[i] {
			if err := env.Win.AD.RemoveMember(ctx, g.DN, o.DN); err != nil {
				return nil, fmt.Errorf("%s: %w", o.SAM, err)
			}
		}
	}
	return nil, nil
}
func (a adGroupRemove) Verify(ctx context.Context, env *Env, p Params) error {
	g, ok, err := env.Win.AD.Find(ctx, p.Str("group"))
	if err != nil || !ok {
		return fmt.Errorf("group %q: %v", p.Str("group"), err)
	}
	objs, err := resolveUsers(ctx, env.Win.AD, p.List("members"))
	if err != nil {
		return err
	}
	for _, o := range objs {
		for _, m := range g.Members {
			if strings.EqualFold(m, o.DN) {
				return fmt.Errorf("%s is still a member of %s", o.SAM, g.SAM)
			}
		}
	}
	return nil
}

// ---- ad.account.krbtgt_reset (destructive, two steps) ----

// DefaultKrbtgtGap is the wait between the two resets: the maximum Kerberos
// ticket lifetime (10 hours by default) so tickets from before step 1 expire.
const DefaultKrbtgtGap = 10 * time.Hour

type adKrbtgt struct{}

func (adKrbtgt) Spec() Spec {
	return Spec{Name: "ad.account.krbtgt_reset", Risk: RiskDestructive,
		Doc: "Reset the krbtgt password. Run step 1, wait at least gap_minutes (default 600, the ticket lifetime), then step 2; both are needed to invalidate golden tickets. Not reversible. confirm must be krbtgt@<domain DN>.",
		Params: []ParamSpec{
			{Name: "step", Type: Int, Required: true, Check: func(v any) error {
				if n := v.(int); n != 1 && n != 2 {
					return errors.New("step must be 1 or 2")
				}
				return nil
			}},
			{Name: "confirm", Type: String, Required: true, Max: 512},
			{Name: "gap_minutes", Type: Int, Default: int(DefaultKrbtgtGap / time.Minute), Check: func(v any) error {
				if n := v.(int); n < 1 || n > 24*60 {
					return errors.New("gap_minutes must be 1-1440")
				}
				return nil
			}}}}
}
func (adKrbtgt) Locks(Params) []string { return []string{LockAccounts} }
func (adKrbtgt) Touches(Params) []Touch {
	return []Touch{acctTouch("krbtgt", OpSetPassword)}
}

func (adKrbtgt) check(ctx context.Context, env *Env, p Params) (ADObject, error) {
	ad, err := adOrErr(env)
	if err != nil {
		return ADObject{}, err
	}
	dn, err := ad.DomainDN(ctx)
	if err != nil {
		return ADObject{}, err
	}
	if p.Str("confirm") != "krbtgt@"+dn {
		return ADObject{}, fmt.Errorf("confirm must be %q", "krbtgt@"+dn)
	}
	k, ok, err := ad.Find(ctx, "krbtgt")
	if err != nil {
		return ADObject{}, err
	}
	if !ok {
		return ADObject{}, errors.New("krbtgt not found")
	}
	gap, _ := p.Int("gap_minutes")
	age := env.Now().Sub(k.PwdLastSet)
	switch p.Int2("step") {
	case 1:
		if !k.PwdLastSet.IsZero() && age < time.Duration(gap)*time.Minute {
			return k, fmt.Errorf("krbtgt was reset %s ago (< %d min): that is step 1 already done; run step 2 once the gap has passed", age.Round(time.Second), gap)
		}
	case 2:
		if age < time.Duration(gap)*time.Minute {
			return k, fmt.Errorf("step 2 is %s too early: krbtgt was last reset %s ago, the gap is %d min", (time.Duration(gap)*time.Minute - age).Round(time.Second), age.Round(time.Second), gap)
		}
	}
	return k, nil
}

func (a adKrbtgt) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	k, err := a.check(ctx, env, p)
	if err != nil {
		return Plan{}, err
	}
	return Plan{Diff: fmt.Sprintf("reset krbtgt password (step %d); last set %s", p.Int2("step"), k.PwdLastSet.UTC().Format(time.RFC3339)),
		Notes: []string{"destructive and not reversible", "services with Kerberos tickets older than the first reset must re-authenticate"}}, nil
}
func (adKrbtgt) Capture(context.Context, *Env, Params) (Rollback, error) { return Rollback{}, nil }
func (a adKrbtgt) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	k, err := a.check(ctx, env, p)
	if err != nil {
		return nil, err
	}
	pw, err := RandomPassword(64)
	if err != nil {
		return nil, err
	}
	if err := env.Win.AD.SetPassword(ctx, k.DN, pw, false); err != nil {
		return nil, redactErr(err, pw)
	}
	return Output{"step": fmt.Sprint(p.Int2("step"))}, nil
}
func (adKrbtgt) Verify(ctx context.Context, env *Env, _ Params) error {
	k, ok, err := env.Win.AD.Find(ctx, "krbtgt")
	if err != nil || !ok {
		return fmt.Errorf("krbtgt lookup: %v", err)
	}
	if !k.PwdLastSet.IsZero() && env.Now().Sub(k.PwdLastSet) > 5*time.Minute {
		return errors.New("krbtgt pwdLastSet did not move")
	}
	return nil
}

// Int2 returns an integer parameter (0 if absent).
func (p Params) Int2(k string) int { n, _ := p.Int(k); return n }

// RandomPassword returns n random characters with all four classes present.
func RandomPassword(n int) (string, error) {
	if n < 12 {
		n = 12
	}
	const lower, upper, digit, sym = "abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!#$%&*+-=?@^_"
	all := lower + upper + digit + sym
	pick := func(set string) (byte, error) {
		i, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			return 0, err
		}
		return set[i.Int64()], nil
	}
	b := make([]byte, n)
	for i := range b {
		set := all
		if i < 4 {
			set = []string{lower, upper, digit, sym}[i]
		}
		c, err := pick(set)
		if err != nil {
			return "", err
		}
		b[i] = c
	}
	for i := len(b) - 1; i > 0; i-- { // shuffle
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		b[i], b[j.Int64()] = b[j.Int64()], b[i]
	}
	return string(b), nil
}
