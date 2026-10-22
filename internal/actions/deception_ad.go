package actions

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// HoneyAccount is a honey Active Directory account. The account owns no
// rights: no group memberships beyond the domain default, no logon rights
// worth having, a long random password nobody is meant to know.
type HoneyAccount struct {
	Name        string // sAMAccountName
	OU          string // distinguished name of the OU to create it in
	Description string
	Password    string
	SPN         string // set for kerberoast bait
	// DontRequirePreauth makes the account AS-REP roastable.
	DontRequirePreauth bool
	Enabled            bool
}

// HoneyADBackend is the directory layer ad.honey_account needs: creation of one
// account, which the general ADBackend (queries and edits) does not offer. The
// Windows ADSI backend implements it (deception_ad_windows.go), so an agent
// whose Env.Win.AD is ADSI needs no further wiring; SetHoneyADBackend overrides
// it (tests, other directories).
type HoneyADBackend interface {
	HoneyAccountExists(ctx context.Context, name string) (bool, error)
	CreateHoneyAccount(ctx context.Context, a HoneyAccount) error
}

var (
	adMu      sync.RWMutex
	adBackend HoneyADBackend
)

// SetHoneyADBackend binds the directory layer (nil unbinds).
func SetHoneyADBackend(b HoneyADBackend) {
	adMu.Lock()
	adBackend = b
	adMu.Unlock()
}

// ErrNoADBackend is returned when no directory layer can create accounts.
var ErrNoADBackend = errors.New("ad.honey_account: no directory backend that can create accounts on this agent (not a domain controller, or no AD layer)")

func honeyBackend(env *Env) (HoneyADBackend, error) {
	adMu.RLock()
	b := adBackend
	adMu.RUnlock()
	if b != nil {
		return b, nil
	}
	if env != nil {
		if hb, ok := env.Win.AD.(HoneyADBackend); ok && hb != nil {
			return hb, nil
		}
	}
	return nil, ErrNoADBackend
}

type adHoneyAccount struct{}

func (adHoneyAccount) Spec() Spec {
	return Spec{Name: "ad.honey_account", Risk: RiskService,
		Doc: "Create a honey AD account (kerberoast SPN, AS-REP roastable, or admin lookalike) with no rights.",
		Params: []ParamSpec{
			{Name: "name", Type: String, Required: true, Max: 20, Check: checkSAM},
			{Name: "ou", Type: String, Required: true, Max: 512},
			{Name: "description", Type: String, Max: 1024},
			{Name: "spn", Type: String, Max: 512},
			{Name: "enabled", Type: Bool, Default: true},
			{Name: "dont_require_preauth", Type: Bool},
			{Name: "logon_rights", Type: Enum, Enum: []string{"none"}, Default: "none"},
			{Name: "secret_params", Type: StringList, Max: 2},
			{Name: "secret_refs", Type: StringMap},
		}}
}

func checkSAM(v any) error {
	s, _ := v.(string)
	if s == "" || strings.ContainsAny(s, "\"/\\[]:;|=,+*?<>@ \x00\r\n\t") {
		return errors.New("not a valid sAMAccountName")
	}
	return nil
}

func (adHoneyAccount) Locks(Params) []string { return []string{"ad:honey"} }

func (adHoneyAccount) Touches(p Params) []Touch {
	return []Touch{{Kind: TouchAccount, Name: p.Str("name"), Op: OpModify}}
}

func (adHoneyAccount) password(ctx context.Context, p Params) (string, error) {
	names, err := secretNames(p, "password")
	if err != nil {
		return "", err
	}
	if !isSecret(names, "password") {
		// There is deliberately no plaintext password parameter: a plan that
		// carried one would put it in the plan JSON.
		return "", errors.New("password must be a secret parameter (secret_params: [password])")
	}
	v, ok := SecretParam(ctx, "password")
	if !ok {
		return "", errors.New("secret parameter password was not delivered with the step")
	}
	return v, nil
}

func (adHoneyAccount) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	b, err := honeyBackend(env)
	if err != nil {
		return Plan{}, err
	}
	if _, err := (adHoneyAccount{}).password(ctx, p); err != nil {
		return Plan{}, err
	}
	ok, err := b.HoneyAccountExists(ctx, p.Str("name"))
	if err != nil {
		return Plan{}, err
	}
	if ok {
		return Plan{Done: true, Notes: []string{"account " + p.Str("name") + " exists; not touched"}}, nil
	}
	d := fmt.Sprintf("create AD account %s in %s (no rights)", p.Str("name"), p.Str("ou"))
	if p.Str("spn") != "" {
		d += ", SPN " + p.Str("spn")
	}
	if p.Bool("dont_require_preauth") {
		d += ", pre-authentication not required"
	}
	return Plan{Diff: d, Notes: []string{"not rolled back automatically: delete the account by hand"}}, nil
}

func (adHoneyAccount) Capture(context.Context, *Env, Params) (Rollback, error) {
	return Rollback{}, nil
}

func (a adHoneyAccount) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	b, err := honeyBackend(env)
	if err != nil {
		return nil, err
	}
	pw, err := a.password(ctx, p)
	if err != nil {
		return nil, err
	}
	err = b.CreateHoneyAccount(ctx, HoneyAccount{Name: p.Str("name"), OU: p.Str("ou"), Description: p.Str("description"),
		Password: pw, SPN: p.Str("spn"), DontRequirePreauth: p.Bool("dont_require_preauth"), Enabled: p.Bool("enabled")})
	if err != nil {
		// A backend error may echo its input; never pass the password through.
		return nil, errors.New("create honey account: " + strings.ReplaceAll(err.Error(), pw, "[redacted]"))
	}
	return Output{"account": p.Str("name")}, nil
}

func (adHoneyAccount) Verify(ctx context.Context, env *Env, p Params) error {
	b, err := honeyBackend(env)
	if err != nil {
		return err
	}
	ok, err := b.HoneyAccountExists(ctx, p.Str("name"))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("account %s does not exist after creation", p.Str("name"))
	}
	return nil
}
