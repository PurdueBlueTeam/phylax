package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

const kindMSSQLUndo = "mssql.undo"

// mssqlUndo is the rollback data of mssql.lock. It never holds credentials.
type mssqlUndo struct {
	Server   string          `json:"server"`
	Port     int             `json:"port"`
	Features []mssqlFeatUndo `json:"features,omitempty"`
	// ShowAdvanced is the prior 'show advanced options' value, restored last.
	ShowAdvanced int      `json:"show_advanced"`
	Logins       []string `json:"enable_logins,omitempty"`
	Sysadmins    []string `json:"readd_sysadmins,omitempty"`
}

type mssqlFeatUndo struct {
	Option string `json:"option"` // sp_configure name
	Prior  int    `json:"prior"`
}

// mssqlChanges is what a lock run would do, computed identically by Plan,
// Capture and Apply.
type mssqlChanges struct {
	Features  []mssqlFeatUndo // option + prior value (all are set to 0)
	Logins    []string
	Sysadmins []string
	Notes     []string
	ShowAdv   int
	Self      string
}

func (c *mssqlChanges) empty() bool {
	return len(c.Features)+len(c.Logins)+len(c.Sysadmins) == 0
}

type mssqlLock struct{}

func (mssqlLock) Spec() Spec {
	return Spec{Name: "mssql.lock", Risk: RiskLockout,
		Doc: "Harden the local SQL Server, reversibly: set xp_cmdshell / Ole Automation / CLR (default) or other features off via sp_configure, " +
			"disable named logins, remove named members from sysadmin. disable_unscored / sysadmin_sweep extend that to every login or sysadmin member " +
			"that is not scored, not the agent's own connection, not a system principal and not in keep (they need a scoring guard to be configured). " +
			"Never touches a scored login or database, never sets ForceEncryption. Rollback restores the prior values, re-enables logins and re-adds members.",
		Params: []ParamSpec{mssqlServerParam, mssqlPortParam,
			{Name: "features", Type: StringList, Max: 16},
			{Name: "disable_logins", Type: StringList, Max: 256},
			{Name: "remove_sysadmins", Type: StringList, Max: 256},
			{Name: "disable_unscored", Type: Bool},
			{Name: "sysadmin_sweep", Type: Bool},
			{Name: "keep", Type: StringList, Max: 256}}}
}

func (mssqlLock) Locks(Params) []string { return nil }

func (mssqlLock) Touches(p Params) []Touch {
	var t []Touch
	for _, l := range p.List("disable_logins") {
		t = append(t, Touch{Kind: TouchAccount, Name: l, Op: OpLock})
	}
	for _, l := range p.List("remove_sysadmins") {
		t = append(t, Touch{Kind: TouchAccount, Name: l, Op: OpRemoveFromGroup, Group: "sysadmin"})
	}
	return t
}

func mssqlFeatureList(p Params) ([]string, error) {
	l := p.List("features")
	if len(l) == 0 {
		l = mssqlDefaultFeatures
	}
	var out []string
	for _, f := range l {
		if _, ok := mssqlFeatures[f]; !ok {
			return nil, fmt.Errorf("unknown feature %q (known: %s)", f, strings.Join(mssqlFeatureNames(), ", "))
		}
		out = append(out, f)
	}
	return out, nil
}

func inFold(list []string, s string) bool {
	for _, e := range list {
		if strings.EqualFold(e, s) {
			return true
		}
	}
	return false
}

// computeMSSQLChanges decides what to change from a live snapshot. Explicitly
// named targets that are protected are refusals; swept ones are skipped with
// a note.
func computeMSSQLChanges(ctx context.Context, env *Env, p Params, t MSSQLTarget, st *mssqlState) (*mssqlChanges, error) {
	ch := &mssqlChanges{Self: st.Self, ShowAdv: st.Config["show advanced options"]}
	feats, err := mssqlFeatureList(p)
	if err != nil {
		return nil, err
	}
	for _, f := range feats {
		opt := mssqlFeatures[f]
		cur, ok := st.Config[opt]
		if !ok {
			return nil, fmt.Errorf("sp_configure option %q not present on this server", opt)
		}
		if cur != 0 {
			ch.Features = append(ch.Features, mssqlFeatUndo{Option: opt, Prior: cur})
		}
	}

	protected := func(name string) bool {
		return strings.EqualFold(name, st.Self) || (t.User != "" && strings.EqualFold(name, t.User))
	}
	sweepNeedsGuard := func() error {
		if _, open := env.Guard.(AllowAll); env.Guard == nil || open {
			return errors.New("sweeps need a scoring guard configured on this agent (refusing to guess which logins are scored)")
		}
		return nil
	}
	keep := p.List("keep")
	byName := map[string]mssqlPrincipal{}
	for _, l := range st.Logins {
		byName[strings.ToLower(l.Name)] = l
	}
	adminDirect := false
	for _, m := range st.Sysadmins {
		if strings.EqualFold(m.Name, st.Self) {
			adminDirect = true
		}
	}

	// logins to disable
	seen := map[string]bool{}
	addLogin := func(l mssqlPrincipal, explicit bool) error {
		if seen[strings.ToLower(l.Name)] {
			return nil
		}
		seen[strings.ToLower(l.Name)] = true
		if l.Disabled {
			return nil
		}
		why := ""
		switch {
		case protected(l.Name):
			why = "it is the agent's own connection login"
		case mssqlSystemPrincipal(l.Name):
			why = "system principal"
		case l.Type == "G" && !adminDirect && !explicit:
			why = "Windows group (the agent may connect through it)"
		case inFold(keep, l.Name):
			why = "in keep"
		}
		if why == "" {
			if err := env.guard().Allow(ctx, Touch{Kind: TouchAccount, Name: l.Name, Op: OpLock}); err != nil {
				if explicit {
					return err
				}
				why = "scoring guard"
			}
		}
		if why != "" {
			if explicit {
				return fmt.Errorf("refusing to disable login %q: %s", l.Name, why)
			}
			ch.Notes = append(ch.Notes, fmt.Sprintf("skip login %s: %s", l.Name, why))
			return nil
		}
		ch.Logins = append(ch.Logins, l.Name)
		return nil
	}
	for _, n := range p.List("disable_logins") {
		l, ok := byName[strings.ToLower(n)]
		if !ok {
			return nil, fmt.Errorf("login %q not found", n)
		}
		if err := addLogin(l, true); err != nil {
			return nil, err
		}
	}
	if p.Bool("disable_unscored") {
		if err := sweepNeedsGuard(); err != nil {
			return nil, err
		}
		for _, l := range st.Logins {
			if err := addLogin(l, false); err != nil {
				return nil, err
			}
		}
	}

	// sysadmin members to remove
	sa := map[string]mssqlPrincipal{}
	for _, m := range st.Sysadmins {
		sa[strings.ToLower(m.Name)] = m
	}
	seenSA := map[string]bool{}
	addSA := func(m mssqlPrincipal, explicit bool) error {
		if seenSA[strings.ToLower(m.Name)] {
			return nil
		}
		seenSA[strings.ToLower(m.Name)] = true
		why := ""
		switch {
		case protected(m.Name):
			why = "it is the agent's own connection login"
		case mssqlSystemPrincipal(m.Name):
			why = "system principal (the service needs it)"
		case strings.EqualFold(m.Name, "sa"):
			why = "sa cannot leave sysadmin"
		case m.Type == "G" && !adminDirect:
			why = "Windows group while the agent is not a direct sysadmin member (lockout risk)"
		case inFold(keep, m.Name):
			why = "in keep"
		}
		if why == "" {
			// A scored login must keep its role: refuse both a lock and a
			// group removal decision of the guard.
			g := env.guard()
			if err := g.Allow(ctx, Touch{Kind: TouchAccount, Name: m.Name, Op: OpLock}); err != nil {
				why = "scored login keeps its role"
			} else if err := g.Allow(ctx, Touch{Kind: TouchAccount, Name: m.Name, Op: OpRemoveFromGroup, Group: "sysadmin"}); err != nil {
				why = "scoring guard"
			}
		}
		if why != "" {
			if explicit {
				return fmt.Errorf("refusing to remove %q from sysadmin: %s", m.Name, why)
			}
			ch.Notes = append(ch.Notes, fmt.Sprintf("skip sysadmin %s: %s", m.Name, why))
			return nil
		}
		ch.Sysadmins = append(ch.Sysadmins, m.Name)
		return nil
	}
	for _, n := range p.List("remove_sysadmins") {
		m, ok := sa[strings.ToLower(n)]
		if !ok {
			continue // already not a member: idempotent
		}
		if err := addSA(m, true); err != nil {
			return nil, err
		}
	}
	if p.Bool("sysadmin_sweep") {
		if err := sweepNeedsGuard(); err != nil {
			return nil, err
		}
		for _, m := range st.Sysadmins {
			if err := addSA(m, false); err != nil {
				return nil, err
			}
		}
	}
	if len(ch.Sysadmins) > 0 && !st.SelfSysadmin {
		return nil, errors.New("the agent's connection is not sysadmin; refusing to change roles")
	}
	for _, l := range ch.Logins {
		if _, err := mssqlQuoteIdent(l); err != nil {
			return nil, err
		}
	}
	for _, l := range ch.Sysadmins {
		if _, err := mssqlQuoteIdent(l); err != nil {
			return nil, err
		}
	}
	sort.Strings(ch.Logins)
	sort.Strings(ch.Sysadmins)
	return ch, nil
}

func (m mssqlLock) snapshot(ctx context.Context, env *Env, p Params) (*mssqlChanges, MSSQLTarget, error) {
	c, t, err := mssqlConnect(ctx, p)
	if err != nil {
		return nil, t, err
	}
	defer c.Close()
	st, err := mssqlRead(ctx, c)
	if err != nil {
		return nil, t, err
	}
	ch, err := computeMSSQLChanges(ctx, env, p, t, st)
	return ch, t, err
}

func (m mssqlLock) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	ch, _, err := m.snapshot(ctx, env, p)
	if err != nil {
		return Plan{}, err
	}
	if ch.empty() {
		return Plan{Done: true, Notes: ch.Notes}, nil
	}
	var d []string
	for _, f := range ch.Features {
		d = append(d, fmt.Sprintf("sp_configure '%s' %d -> 0", f.Option, f.Prior))
	}
	for _, l := range ch.Logins {
		d = append(d, "disable login "+l)
	}
	for _, l := range ch.Sysadmins {
		d = append(d, "remove "+l+" from sysadmin")
	}
	return Plan{Diff: strings.Join(d, "\n"), Notes: ch.Notes}, nil
}

func (m mssqlLock) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	ch, t, err := m.snapshot(ctx, env, p)
	if err != nil {
		return Rollback{}, err
	}
	if ch.empty() {
		return Rollback{}, nil
	}
	return Rollback{Kind: kindMSSQLUndo, Data: mssqlUndo{Server: t.Server, Port: t.Port, Features: ch.Features,
		ShowAdvanced: ch.ShowAdv, Logins: ch.Logins, Sysadmins: ch.Sysadmins}}, nil
}

// mssqlSetConfig sets sp_configure options, toggling 'show advanced options'
// on for the duration and restoring prior to it.
func mssqlSetConfig(ctx context.Context, c MSSQLConn, vals []mssqlFeatUndo, showPrior int) error {
	if len(vals) == 0 {
		return nil
	}
	set := func(opt string, v int) error {
		_, err := c.Exec(ctx, fmt.Sprintf("EXEC sp_configure N'%s', %d; RECONFIGURE WITH OVERRIDE", opt, v))
		return err
	}
	if showPrior == 0 {
		if err := set("show advanced options", 1); err != nil {
			return err
		}
		defer func() { _ = set("show advanced options", 0) }()
	}
	for _, f := range vals {
		if err := set(f.Option, f.Prior); err != nil { // Prior carries the value to set
			return fmt.Errorf("sp_configure %s: %w", f.Option, err)
		}
	}
	return nil
}

func mssqlAlterRole(ctx context.Context, c MSSQLConn, name string, add bool) error {
	id, err := mssqlQuoteIdent(name)
	if err != nil {
		return err
	}
	lit, _ := mssqlQuoteString(name)
	want, verb := "1", "DROP"
	if add {
		want, verb = "0", "ADD"
	}
	_, err = c.Exec(ctx, fmt.Sprintf("IF IS_SRVROLEMEMBER('sysadmin', %s) = %s ALTER SERVER ROLE [sysadmin] %s MEMBER %s", lit, want, verb, id))
	return err
}

func mssqlAlterLogin(ctx context.Context, c MSSQLConn, name string, enable bool) error {
	id, err := mssqlQuoteIdent(name)
	if err != nil {
		return err
	}
	verb := "DISABLE"
	if enable {
		verb = "ENABLE"
	}
	_, err = c.Exec(ctx, "ALTER LOGIN "+id+" "+verb)
	return err
}

func (m mssqlLock) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	c, t, err := mssqlConnect(ctx, p)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	st, err := mssqlRead(ctx, c)
	if err != nil {
		return nil, err
	}
	ch, err := computeMSSQLChanges(ctx, env, p, t, st)
	if err != nil {
		return nil, err
	}
	zero := make([]mssqlFeatUndo, len(ch.Features))
	for i, f := range ch.Features {
		zero[i] = mssqlFeatUndo{Option: f.Option}
	}
	if err := mssqlSetConfig(ctx, c, zero, ch.ShowAdv); err != nil {
		return nil, err
	}
	for _, l := range ch.Logins {
		if err := mssqlAlterLogin(ctx, c, l, false); err != nil {
			return nil, fmt.Errorf("disable %s: %w", l, err)
		}
	}
	for _, l := range ch.Sysadmins {
		if err := mssqlAlterRole(ctx, c, l, false); err != nil {
			return nil, fmt.Errorf("remove %s from sysadmin: %w", l, err)
		}
	}
	return Output{"features_off": fmt.Sprint(len(ch.Features)), "logins_disabled": strings.Join(ch.Logins, ","),
		"sysadmins_removed": strings.Join(ch.Sysadmins, ","), "skipped": strings.Join(ch.Notes, "\n")}, nil
}

// Verify re-reads the server: every requested thing is in its target state
// and the agent's own connection is still sysadmin.
func (m mssqlLock) Verify(ctx context.Context, env *Env, p Params) error {
	c, _, err := mssqlConnect(ctx, p)
	if err != nil {
		return err
	}
	defer c.Close()
	st, err := mssqlRead(ctx, c)
	if err != nil {
		return err
	}
	feats, _ := mssqlFeatureList(p)
	for _, f := range feats {
		if v := st.Config[mssqlFeatures[f]]; v != 0 {
			return fmt.Errorf("%s still enabled after sp_configure", f)
		}
	}
	login := map[string]mssqlPrincipal{}
	for _, l := range st.Logins {
		login[strings.ToLower(l.Name)] = l
	}
	for _, n := range p.List("disable_logins") {
		if l, ok := login[strings.ToLower(n)]; ok && !l.Disabled {
			return fmt.Errorf("login %s is still enabled", n)
		}
	}
	for _, n := range p.List("remove_sysadmins") {
		for _, s := range st.Sysadmins {
			if strings.EqualFold(s.Name, n) {
				return fmt.Errorf("%s is still a sysadmin member", n)
			}
		}
	}
	if !st.SelfSysadmin {
		return errors.New("the agent's connection lost sysadmin; roll back")
	}
	return nil
}

func undoMSSQL(ctx context.Context, _ *Env, e deadman.Entry) error {
	var u mssqlUndo
	if err := json.Unmarshal(e.Data, &u); err != nil {
		return err
	}
	t, err := mssqlTarget(ctx, Params{})
	if err != nil {
		return err
	}
	t.Server, t.Port = u.Server, u.Port
	var d MSSQLDialer = driverMSSQLDialer{}
	if cd := getMSSQLConfig().Dialer; cd != nil {
		d = cd
	}
	c, err := d.Dial(ctx, t)
	if err != nil {
		return err
	}
	defer c.Close()
	var errs []error
	// roles and logins first: they are what the agent's access may depend on
	for _, l := range u.Sysadmins {
		errs = append(errs, mssqlAlterRole(ctx, c, l, true))
	}
	for _, l := range u.Logins {
		errs = append(errs, mssqlAlterLogin(ctx, c, l, true))
	}
	errs = append(errs, mssqlSetConfig(ctx, c, u.Features, u.ShowAdvanced))
	return errors.Join(errs...)
}
