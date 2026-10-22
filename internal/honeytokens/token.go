// Package honeytokens generates and tracks honeytokens (design: Deception,
// "Honeytokens"): fake credentials, keys and honey files unique per host, the
// plan (as action specs for the planner, never executed here) that plants them,
// and the registry that attributes a later sighting to the host that was
// looted. It also holds the honey-file read watcher interface (fanotify on
// Linux).
package honeytokens

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Kind is a honeytoken kind. The manifest's decoys.yml `honeytokens[].kind`
// takes these values.
type Kind string

const (
	KindSSHKey        Kind = "ssh_key"        // fake private key
	KindDBCred        Kind = "db_cred"        // .env / config / web.config
	KindShellHistory  Kind = "shell_history"  // inline password in .bash_history
	KindPasswordsFile Kind = "passwords_file" // passwords.txt-like bait
	KindBrowserCred   Kind = "browser_cred"   // browser password export lookalike
	KindAWSKey        Kind = "aws_key"        // canary AWS key-format strings
	KindHoneyFile     Kind = "honey_file"     // read-watched file with no credential
	KindADSPN         Kind = "ad_spn"         // kerberoast bait account
	KindADASREP       Kind = "ad_asrep"       // AS-REP roastable account
	KindADAdmin       Kind = "ad_admin"       // admin-lookalike account
)

var kinds = map[Kind]bool{KindSSHKey: true, KindDBCred: true, KindShellHistory: true, KindPasswordsFile: true,
	KindBrowserCred: true, KindAWSKey: true, KindHoneyFile: true, KindADSPN: true, KindADASREP: true, KindADAdmin: true}

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool { return kinds[k] }

// IsAD reports whether the token is a honey AD account.
func (k Kind) IsAD() bool { return k == KindADSPN || k == KindADASREP || k == KindADAdmin }

// Token is one planted honeytoken. Secret material is stored encrypted in the
// controller's vault; it is never logged.
type Token struct {
	ID          string `json:"id"`
	Host        string `json:"host"` // origin: the host it was planted on
	Kind        Kind   `json:"kind"`
	Path        string `json:"path,omitempty"`        // where it is planted (or OU for AD)
	User        string `json:"user,omitempty"`        // account / key id; "" = any user
	Secret      string `json:"secret,omitempty"`      // password / secret key
	Fingerprint string `json:"fingerprint,omitempty"` // SSH key SHA256 fingerprint
	SPN         string `json:"spn,omitempty"`         // service principal name (AD kerberoast bait)
}

// Registry is the controller's token registry. Every token is unique across
// hosts: Add refuses an ID, secret, account, fingerprint, SPN or path that is
// already registered.
type Registry struct {
	mu     sync.RWMutex
	byID   map[string]Token
	secret map[string][]string // secret -> ids
	user   map[string]string   // lower(user) -> id (accounts and key ids)
	fp     map[string]string
	spn    map[string]string
	path   map[string]string // lower(host\x00path) -> id
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byID: map[string]Token{}, secret: map[string][]string{}, user: map[string]string{},
		fp: map[string]string{}, spn: map[string]string{}, path: map[string]string{}}
}

// ErrDuplicate is returned by Add for a value that collides with another token.
var ErrDuplicate = errors.New("honeytokens: duplicate token value")

func pathKey(host, p string) string { return strings.ToLower(host + "\x00" + p) }

// Add registers a token.
func (r *Registry) Add(t Token) error {
	if t.ID == "" || t.Host == "" || !t.Kind.Valid() {
		return fmt.Errorf("honeytokens: token needs id, host and a valid kind (%q %q %q)", t.ID, t.Host, t.Kind)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.conflictLocked(t); err != nil {
		return err
	}
	r.byID[t.ID] = t
	if t.Secret != "" {
		r.secret[t.Secret] = append(r.secret[t.Secret], t.ID)
	}
	if t.User != "" {
		r.user[strings.ToLower(t.User)] = t.ID
	}
	if t.Fingerprint != "" {
		r.fp[t.Fingerprint] = t.ID
	}
	if t.SPN != "" {
		r.spn[strings.ToLower(t.SPN)] = t.ID
	}
	if t.Path != "" && !t.Kind.IsAD() {
		r.path[pathKey(t.Host, t.Path)] = t.ID
	}
	return nil
}

func (r *Registry) conflictLocked(t Token) error {
	if _, ok := r.byID[t.ID]; ok {
		return fmt.Errorf("%w: id %s", ErrDuplicate, t.ID)
	}
	if t.Secret != "" && len(r.secret[t.Secret]) > 0 {
		return fmt.Errorf("%w: secret of %s", ErrDuplicate, t.ID)
	}
	if t.User != "" {
		if _, ok := r.user[strings.ToLower(t.User)]; ok {
			return fmt.Errorf("%w: user %s", ErrDuplicate, t.User)
		}
	}
	if _, ok := r.fp[t.Fingerprint]; t.Fingerprint != "" && ok {
		return fmt.Errorf("%w: fingerprint of %s", ErrDuplicate, t.ID)
	}
	if _, ok := r.spn[strings.ToLower(t.SPN)]; t.SPN != "" && ok {
		return fmt.Errorf("%w: spn %s", ErrDuplicate, t.SPN)
	}
	if _, ok := r.path[pathKey(t.Host, t.Path)]; t.Path != "" && !t.Kind.IsAD() && ok {
		return fmt.Errorf("%w: path %s on %s", ErrDuplicate, t.Path, t.Host)
	}
	return nil
}

// Taken reports whether adding t would collide (used by the generator to retry).
func (r *Registry) Taken(t Token) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.conflictLocked(t) != nil
}

// Get returns a token by ID.
func (r *Registry) Get(id string) (Token, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.byID[id]
	return t, ok
}

// Tokens returns all tokens sorted by ID.
func (r *Registry) Tokens() []Token {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Token, 0, len(r.byID))
	for _, t := range r.byID {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// MatchCredential implements the decoy matcher. Secrets are unique per token,
// so a used secret is a sighting whatever account it is tried against (a
// password found in shell history or a .env is sprayed at other users and
// services).
func (r *Registry) MatchCredential(_, secret string) (Token, bool) {
	if secret == "" {
		return Token{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for s, ids := range r.secret {
		if len(s) != len(secret) || subtle.ConstantTimeCompare([]byte(s), []byte(secret)) != 1 {
			continue
		}
		if len(ids) > 0 {
			return r.byID[ids[0]], true
		}
	}
	return Token{}, false
}

// MatchFingerprint matches an SSH public key fingerprint (SHA256:...).
func (r *Registry) MatchFingerprint(fp string) (Token, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.fp[fp]
	if !ok {
		return Token{}, false
	}
	return r.byID[id], true
}

// MatchAccount matches an account name or key id (any attempt at a honey
// account is a sighting, whatever the password).
func (r *Registry) MatchAccount(name string) (Token, bool) {
	// strip DOMAIN\ and @realm
	if i := strings.LastIndex(name, `\`); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.Index(name, "@"); i > 0 {
		name = name[:i]
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.user[strings.ToLower(name)]
	if !ok {
		return Token{}, false
	}
	return r.byID[id], true
}

// Attribute resolves an event's fields (an alert, a decoy hit, a 4769/4663/auth
// event) to the honeytoken it involves and thereby the host that was looted.
func (r *Registry) Attribute(f map[string]any) (Token, bool) {
	str := func(k string) string { s, _ := f[k].(string); return s }
	if id := str("honeytoken"); id != "" {
		if t, ok := r.Get(id); ok {
			return t, true
		}
	}
	if fp := str("key_fingerprint"); fp != "" {
		if t, ok := r.MatchFingerprint(fp); ok {
			return t, true
		}
	}
	if s := str("service_name"); s != "" {
		r.mu.RLock()
		id, ok := r.spn[strings.ToLower(s)]
		r.mu.RUnlock()
		if ok {
			return r.byID[id], true
		}
	}
	for _, k := range []string{"aws_access_key_id", "account", "target_user_name", "user"} {
		if v := str(k); v != "" {
			if t, ok := r.MatchAccount(v); ok {
				return t, true
			}
		}
	}
	for _, k := range []string{"object_name", "path", "file"} {
		if p := str(k); p != "" {
			r.mu.RLock()
			var found Token
			ok := false
			for _, t := range r.byID {
				if !t.Kind.IsAD() && t.Path != "" && strings.EqualFold(t.Path, p) {
					found, ok = t, true
					break
				}
			}
			r.mu.RUnlock()
			if ok {
				return found, true
			}
		}
	}
	return Token{}, false
}

// Seeds returns the static detection profiles the rules in rules/deception.yml
// test against (feed them to the detect engine with Engine.Seed and no key).
func (r *Registry) Seeds() map[string][]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := map[string][]string{"honeytoken.accounts": nil, "honeytoken.spns": nil, "honeytoken.paths": nil, "honeytoken.aws_keys": nil}
	for _, t := range r.byID {
		switch {
		case t.Kind == KindAWSKey:
			out["honeytoken.aws_keys"] = append(out["honeytoken.aws_keys"], t.User)
		case t.User != "":
			out["honeytoken.accounts"] = append(out["honeytoken.accounts"], t.User)
		}
		if t.SPN != "" {
			out["honeytoken.spns"] = append(out["honeytoken.spns"], t.SPN)
		}
		if t.Path != "" && !t.Kind.IsAD() {
			out["honeytoken.paths"] = append(out["honeytoken.paths"], t.Path)
		}
	}
	for _, v := range out {
		sort.Strings(v)
	}
	return out
}
