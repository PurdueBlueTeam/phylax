package actions

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Account is the platform-neutral view of a local account.
type Account struct {
	Name   string
	UID    int
	GID    int
	Home   string
	Shell  string
	Locked bool
}

// CreateSpec describes a new local account.
type CreateSpec struct {
	Name       string
	UID        int // -1 = allocate
	GID        int // -1 = new private group with the same name
	Home       string
	Shell      string
	Comment    string
	System     bool
	CreateHome bool
	Hash       string // optional pre-hashed password (Linux)
	Password   string // optional plaintext (Windows)
}

// AccountBackend does the platform work for the user.* and group.* actions.
// The Linux implementation edits the account files under Root; the Windows one
// uses NetUserSetInfo / NetLocalGroup*.
type AccountBackend interface {
	Lookup(ctx context.Context, name string) (Account, bool, error)
	// PasswordIs reports whether the account's password already is plain.
	PasswordIs(ctx context.Context, name, plain string) (bool, error)
	// SetPassword sets the password from plain (hashed by the backend) or from
	// hash (Linux only). mustChange forces a change at next login.
	SetPassword(ctx context.Context, name, plain, hash string, mustChange bool) error
	SetLocked(ctx context.Context, name string, locked bool) error
	Create(ctx context.Context, c CreateSpec) error
	Delete(ctx context.Context, name string) error
	Members(ctx context.Context, group string) ([]string, bool, error)
	// SetMembers adds and removes members of an existing group.
	SetMembers(ctx context.Context, group string, add, remove []string) error
	// Snapshot returns the rollback for a change touching these accounts/groups
	// (zero Rollback = cannot be undone).
	Snapshot(ctx context.Context) (Rollback, error)
}

var nameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.@$-]{0,63}$`)

func validName(v any) error {
	if !nameRe.MatchString(v.(string)) {
		return errors.New("invalid account or group name")
	}
	return nil
}

func accountsOrErr(env *Env) (AccountBackend, error) {
	if env.Accounts == nil {
		return nil, fmt.Errorf("local accounts: %w", ErrUnsupported)
	}
	return env.Accounts, nil
}

func acctTouch(name, op string) Touch { return Touch{Kind: TouchAccount, Name: name, Op: op} }

// ---- user.set_password ----

type userSetPassword struct{}

func (userSetPassword) Spec() Spec {
	return Spec{Name: "user.set_password", Risk: RiskLockout,
		Doc: "Set a local account password (Linux: /etc/shadow edit keeping aging fields; Windows: NetUserSetInfo).",
		Params: []ParamSpec{
			{Name: "user", Type: String, Required: true, Check: validName},
			{Name: "password", Type: String, Secret: true, Max: 512},
			{Name: "hash", Type: String, Secret: true, Max: 512},
			{Name: "must_change", Type: Bool}}}
}
func (userSetPassword) Locks(Params) []string { return []string{LockAccounts} }
func (userSetPassword) Touches(p Params) []Touch {
	return []Touch{acctTouch(p.Str("user"), OpSetPassword)}
}
func (userSetPassword) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	if p.Has("password") == p.Has("hash") {
		return Plan{}, errors.New("exactly one of password and hash is required")
	}
	be, err := accountsOrErr(env)
	if err != nil {
		return Plan{}, err
	}
	if _, ok, err := be.Lookup(ctx, p.Str("user")); err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("no such user %q", p.Str("user"))
		}
		return Plan{}, err
	}
	if p.Has("password") && !p.Bool("must_change") {
		if same, err := be.PasswordIs(ctx, p.Str("user"), p.Str("password")); err == nil && same {
			return Plan{Done: true}, nil
		}
	}
	return Plan{Diff: fmt.Sprintf("set password of %s: <redacted>", p.Str("user"))}, nil
}
func (userSetPassword) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	be, err := accountsOrErr(env)
	if err != nil {
		return Rollback{}, err
	}
	return be.Snapshot(ctx)
}
func (userSetPassword) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	return nil, env.Accounts.SetPassword(ctx, p.Str("user"), p.Str("password"), p.Str("hash"), p.Bool("must_change"))
}

// passwordVerifier is implemented by backends whose post-change check differs
// from the pre-change idempotence check (Windows: a logon attempt).
type passwordVerifier interface {
	VerifyPassword(ctx context.Context, name, plain string) (bool, error)
}

func (userSetPassword) Verify(ctx context.Context, env *Env, p Params) error {
	if !p.Has("password") {
		return nil
	}
	check := env.Accounts.PasswordIs
	if v, ok := env.Accounts.(passwordVerifier); ok {
		check = v.VerifyPassword
	}
	ok, err := check(ctx, p.Str("user"), p.Str("password"))
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("password does not verify after change")
	}
	return nil
}

// ---- user.lock ----

type userLock struct{}

func (userLock) Spec() Spec {
	return Spec{Name: "user.lock", Risk: RiskLockout, Doc: "Lock (or with unlock=true unlock) a local account's password login.",
		Params: []ParamSpec{{Name: "user", Type: String, Required: true, Check: validName}, {Name: "unlock", Type: Bool}}}
}
func (userLock) Locks(Params) []string { return []string{LockAccounts} }
func (userLock) Touches(p Params) []Touch {
	if p.Bool("unlock") {
		return nil
	}
	return []Touch{acctTouch(p.Str("user"), OpLock)}
}
func (userLock) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	be, err := accountsOrErr(env)
	if err != nil {
		return Plan{}, err
	}
	a, ok, err := be.Lookup(ctx, p.Str("user"))
	if err != nil {
		return Plan{}, err
	}
	if !ok {
		return Plan{}, fmt.Errorf("no such user %q", p.Str("user"))
	}
	want := !p.Bool("unlock")
	if a.Locked == want {
		return Plan{Done: true}, nil
	}
	if want && a.UID == 0 {
		return Plan{Diff: "lock " + a.Name + " (uid 0)", Notes: []string{"locking a uid-0 account"}}, nil
	}
	return Plan{Diff: fmt.Sprintf("locked %v -> %v for %s", a.Locked, want, a.Name)}, nil
}
func (userLock) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	return env.Accounts.Snapshot(ctx)
}
func (userLock) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	return nil, env.Accounts.SetLocked(ctx, p.Str("user"), !p.Bool("unlock"))
}
func (userLock) Verify(ctx context.Context, env *Env, p Params) error {
	a, _, err := env.Accounts.Lookup(ctx, p.Str("user"))
	if err != nil {
		return err
	}
	if a.Locked != !p.Bool("unlock") {
		return errors.New("lock state not applied")
	}
	return nil
}

// ---- user.create ----

type userCreate struct{}

func (userCreate) Spec() Spec {
	return Spec{Name: "user.create", Risk: RiskService, Doc: "Create a local account (tagged in its comment field).",
		Params: []ParamSpec{
			{Name: "user", Type: String, Required: true, Check: validName},
			{Name: "uid", Type: Int}, {Name: "gid", Type: Int},
			{Name: "home", Type: Path}, {Name: "shell", Type: Path},
			{Name: "comment", Type: String, Max: 200, Check: noColon},
			{Name: "system", Type: Bool}, {Name: "create_home", Type: Bool},
			{Name: "password", Type: String, Secret: true, Max: 512},
			{Name: "hash", Type: String, Secret: true, Max: 512}}}
}

func noColon(v any) error {
	if strings.ContainsAny(v.(string), ":\n\r") {
		return errors.New("must not contain ':' or newlines")
	}
	return nil
}

func (userCreate) Locks(Params) []string { return []string{LockAccounts} }
func (userCreate) Touches(p Params) []Touch {
	return []Touch{acctTouch(p.Str("user"), OpModify)}
}
func (userCreate) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	be, err := accountsOrErr(env)
	if err != nil {
		return Plan{}, err
	}
	if p.Has("password") && p.Has("hash") {
		return Plan{}, errors.New("password and hash are mutually exclusive")
	}
	if _, ok, err := be.Lookup(ctx, p.Str("user")); err != nil {
		return Plan{}, err
	} else if ok {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: "create user " + p.Str("user")}, nil
}
func (userCreate) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	return env.Accounts.Snapshot(ctx)
}
func (userCreate) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	c := CreateSpec{Name: p.Str("user"), UID: -1, GID: -1, Home: p.Str("home"), Shell: p.Str("shell"),
		Comment: p.Str("comment"), System: p.Bool("system"), CreateHome: p.Bool("create_home"),
		Hash: p.Str("hash"), Password: p.Str("password")}
	if v, ok := p.Int("uid"); ok {
		c.UID = v
	}
	if v, ok := p.Int("gid"); ok {
		c.GID = v
	}
	if c.Comment == "" {
		c.Comment = TagFrom(ctx).String()
	}
	return nil, env.Accounts.Create(ctx, c)
}
func (userCreate) Verify(ctx context.Context, env *Env, p Params) error {
	_, ok, err := env.Accounts.Lookup(ctx, p.Str("user"))
	if err == nil && !ok {
		err = errors.New("user missing after create")
	}
	return err
}

// ---- user.delete ----

type userDelete struct{}

func (userDelete) Spec() Spec {
	return Spec{Name: "user.delete", Risk: RiskDestructive, Doc: "Delete a local account entry. The home directory is never removed.",
		Params: []ParamSpec{{Name: "user", Type: String, Required: true, Check: validName}}}
}
func (userDelete) Locks(Params) []string { return []string{LockAccounts} }
func (userDelete) Touches(p Params) []Touch {
	return []Touch{acctTouch(p.Str("user"), OpDelete)}
}
func (userDelete) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	be, err := accountsOrErr(env)
	if err != nil {
		return Plan{}, err
	}
	a, ok, err := be.Lookup(ctx, p.Str("user"))
	if err != nil {
		return Plan{}, err
	}
	if !ok {
		return Plan{Done: true}, nil
	}
	if a.UID == 0 {
		return Plan{}, errors.New("refusing to delete a uid-0 account")
	}
	return Plan{Diff: fmt.Sprintf("delete user %s (uid %d); home %s kept", a.Name, a.UID, a.Home)}, nil
}
func (userDelete) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	return env.Accounts.Snapshot(ctx)
}
func (userDelete) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	return nil, env.Accounts.Delete(ctx, p.Str("user"))
}
func (userDelete) Verify(ctx context.Context, env *Env, p Params) error {
	_, ok, err := env.Accounts.Lookup(ctx, p.Str("user"))
	if err == nil && ok {
		err = errors.New("user still present")
	}
	return err
}

// ---- group.members ----

type groupMembers struct{}

func (groupMembers) Spec() Spec {
	return Spec{Name: "group.members", Risk: RiskLockout, Doc: "Add and/or remove members of a local group, or set the exact member list.",
		Params: []ParamSpec{
			{Name: "group", Type: String, Required: true, Check: validName},
			{Name: "add", Type: StringList, Max: 1000}, {Name: "remove", Type: StringList, Max: 1000},
			{Name: "members", Type: StringList, Max: 1000}}}
}
func (groupMembers) Locks(Params) []string { return []string{LockAccounts} }
func (groupMembers) Touches(p Params) []Touch {
	var ts []Touch
	for _, u := range p.List("remove") {
		ts = append(ts, Touch{Kind: TouchAccount, Name: u, Op: OpRemoveFromGroup, Group: p.Str("group")})
	}
	return ts
}

// delta computes who to add and remove given the current members.
func (groupMembers) delta(p Params, cur []string) (add, remove []string) {
	have := map[string]bool{}
	for _, m := range cur {
		have[m] = true
	}
	if p.Has("members") {
		want := map[string]bool{}
		for _, m := range p.List("members") {
			want[m] = true
			if !have[m] {
				add = append(add, m)
			}
		}
		for _, m := range cur {
			if !want[m] {
				remove = append(remove, m)
			}
		}
		return
	}
	for _, m := range p.List("add") {
		if !have[m] {
			add = append(add, m)
		}
	}
	for _, m := range p.List("remove") {
		if have[m] {
			remove = append(remove, m)
		}
	}
	return
}

func (g groupMembers) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	be, err := accountsOrErr(env)
	if err != nil {
		return Plan{}, err
	}
	if p.Has("members") && (p.Has("add") || p.Has("remove")) {
		return Plan{}, errors.New("members is exclusive with add and remove")
	}
	cur, ok, err := be.Members(ctx, p.Str("group"))
	if err != nil {
		return Plan{}, err
	}
	if !ok {
		return Plan{}, fmt.Errorf("no such group %q", p.Str("group"))
	}
	add, rm := g.delta(p, cur)
	for _, u := range rm { // removals derived from an exact member list
		if err := env.guard().Allow(ctx, Touch{Kind: TouchAccount, Name: u, Op: OpRemoveFromGroup, Group: p.Str("group")}); err != nil {
			return Plan{}, err
		}
	}
	if len(add)+len(rm) == 0 {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: fmt.Sprintf("group %s: +%v -%v", p.Str("group"), add, rm)}, nil
}
func (groupMembers) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	return env.Accounts.Snapshot(ctx)
}
func (g groupMembers) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	cur, _, err := env.Accounts.Members(ctx, p.Str("group"))
	if err != nil {
		return nil, err
	}
	add, rm := g.delta(p, cur)
	return nil, env.Accounts.SetMembers(ctx, p.Str("group"), add, rm)
}
func (g groupMembers) Verify(ctx context.Context, env *Env, p Params) error {
	cur, _, err := env.Accounts.Members(ctx, p.Str("group"))
	if err != nil {
		return err
	}
	if add, rm := g.delta(p, cur); len(add)+len(rm) > 0 {
		return errors.New("membership differs after change")
	}
	return nil
}
