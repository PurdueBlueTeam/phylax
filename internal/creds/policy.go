// Package creds generates, derives and orders credentials. It never stores
// them: values live in internal/vault, and a Record only names vault versions.
package creds

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

// Class selects a generation policy.
type Class int

const (
	// Scored accounts: 16-24 characters from [A-Za-z0-9._+=-]. Avoids `@ : /`
	// (MySQL DSN), shell metacharacters (custom checks pass the password
	// through a shell), and everything the PCR page treats specially (comma,
	// quotes, backslash, whitespace).
	Scored Class = iota
	// Unscored covers unscored service and app accounts and per-host local
	// accounts: longer, and a few extra symbols that are still safe in a
	// double-quoted shell word and a CSV.
	Unscored
	// Admin is for device and domain administrators: the longest class.
	Admin
)

func (c Class) String() string {
	switch c {
	case Scored:
		return "scored"
	case Unscored:
		return "unscored"
	case Admin:
		return "admin"
	}
	return "unknown"
}

const (
	upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower = "abcdefghijklmnopqrstuvwxyz"
	digit = "0123456789"
	// ConservativeSymbols are the non-alphanumerics allowed in Scored passwords.
	ConservativeSymbols = "._+=-"
	// ExtraSymbols are added for Unscored and Admin. `!` (history expansion),
	// `$`, backtick, `&|;<>()`, `{}[]`, `\`, quotes, `,`, `@:/` and space are
	// excluded on purpose; `*` and `~` are excluded for glob/tilde expansion.
	ExtraSymbols = "#%^"
)

// Charset returns the alphabet for a class.
func (c Class) Charset() string {
	if c == Scored {
		return upper + lower + digit + ConservativeSymbols
	}
	return upper + lower + digit + ConservativeSymbols + ExtraSymbols
}

// LengthRange returns the inclusive generated-length range.
func (c Class) LengthRange() (min, max int) {
	switch c {
	case Scored:
		return 16, 24
	case Unscored:
		return 24, 32
	default:
		return 32, 40
	}
}

// Sentinel errors.
var (
	ErrPolicy    = errors.New("creds: password violates policy")
	ErrDuplicate = errors.New("creds: duplicate password")
)

// Check reports whether pw satisfies the class policy and is safe for the PCR
// CSV (no comma, quotes, backslash, whitespace, `@ : /`, no control or
// non-ASCII bytes). Lengths outside the generated range are allowed down to the
// minimum so that break-glass derivations (fixed length) can be checked too.
func (c Class) Check(pw string) error {
	min, max := c.LengthRange()
	if len(pw) < min || len(pw) > max {
		return fmt.Errorf("%w: length %d outside %d-%d", ErrPolicy, len(pw), min, max)
	}
	return c.checkContent(pw)
}

func (c Class) checkContent(pw string) error {
	set := c.Charset()
	var u, l, d, s bool
	for i := 0; i < len(pw); i++ {
		ch := pw[i]
		if !strings.ContainsRune(set, rune(ch)) {
			return fmt.Errorf("%w: character %q not allowed", ErrPolicy, ch)
		}
		switch {
		case ch >= 'A' && ch <= 'Z':
			u = true
		case ch >= 'a' && ch <= 'z':
			l = true
		case ch >= '0' && ch <= '9':
			d = true
		default:
			s = true
		}
	}
	if !(u && l && d && s) {
		return fmt.Errorf("%w: needs upper, lower, digit and symbol", ErrPolicy)
	}
	if !alnum(pw[0]) || !alnum(pw[len(pw)-1]) {
		return fmt.Errorf("%w: must start and end with a letter or digit", ErrPolicy)
	}
	return nil
}

func alnum(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

// PCRSafe checks the Appendix F CSV constraints for any (username, password)
// pair, independent of class: both non-empty, no comma/newline/leading or
// trailing space, no surrounding-quote pair, no `\`, no control characters.
// The username must also be comma-free; usernames are case-exact and are
// never altered.
func PCRSafe(user, pw string) error {
	if user == "" || pw == "" {
		return errors.New("creds: empty user or password")
	}
	if strings.ContainsAny(user, ",\r\n") || strings.TrimSpace(user) != user {
		return errors.New("creds: username not CSV safe")
	}
	if strings.ContainsAny(pw, ",\r\n\\\"' \t") {
		return errors.New("creds: password contains comma, quote, backslash or whitespace")
	}
	for i := 0; i < len(pw); i++ {
		if pw[i] < 0x21 || pw[i] > 0x7e {
			return errors.New("creds: password has non-printable or non-ASCII byte")
		}
	}
	return nil
}

// Generator produces random passwords and guarantees uniqueness among
// everything it generated or was told about with Reserve. Uniqueness is
// case-insensitive (some targets fold case) and kept as SHA-256 digests so the
// generator does not hold plaintext.
type Generator struct {
	mu   sync.Mutex
	seen map[[32]byte]struct{}
}

func NewGenerator() *Generator { return &Generator{seen: map[[32]byte]struct{}{}} }

func digest(pw string) [32]byte { return sha256.Sum256([]byte(strings.ToLower(pw))) }

// Reserve registers an existing password (for example one read back from the
// vault) so that new ones differ. It returns ErrDuplicate if already present.
func (g *Generator) Reserve(pw string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	d := digest(pw)
	if _, ok := g.seen[d]; ok {
		return ErrDuplicate
	}
	g.seen[d] = struct{}{}
	return nil
}

// Release forgets a password (after it is permanently retired).
func (g *Generator) Release(pw string) {
	g.mu.Lock()
	delete(g.seen, digest(pw))
	g.mu.Unlock()
}

// Generate returns a new password for class. avoid lists substrings (usually
// the account name) that must not appear, case-insensitively, because Windows
// complexity rules reject a password containing the account name.
func (g *Generator) Generate(c Class, avoid ...string) (vault.Secret, error) {
	min, max := c.LengthRange()
	for try := 0; try < 100; try++ {
		n, err := randInt(max - min + 1)
		if err != nil {
			return vault.Secret{}, err
		}
		pw, err := randomString(c.Charset(), min+n)
		if err != nil {
			return vault.Secret{}, err
		}
		if c.checkContent(string(pw)) != nil || containsAny(string(pw), avoid) {
			vault.Wipe(pw)
			continue
		}
		if g.Reserve(string(pw)) != nil {
			vault.Wipe(pw)
			continue
		}
		s := vault.NewSecret(pw)
		vault.Wipe(pw)
		return s, nil
	}
	return vault.Secret{}, errors.New("creds: could not generate a compliant password")
}

func containsAny(pw string, avoid []string) bool {
	lp := strings.ToLower(pw)
	for _, a := range avoid {
		if len(a) >= 3 && strings.Contains(lp, strings.ToLower(a)) {
			return true
		}
	}
	return false
}

// randInt returns a uniform int in [0,n).
func randInt(n int) (int, error) {
	b := make([]byte, 1)
	limit := 256 - 256%n
	for {
		if _, err := rand.Read(b); err != nil {
			return 0, err
		}
		if int(b[0]) < limit {
			return int(b[0]) % n, nil
		}
	}
}

// randomString draws n characters uniformly from set by rejection sampling.
func randomString(set string, n int) ([]byte, error) {
	out := make([]byte, 0, n)
	limit := 256 - 256%len(set)
	buf := make([]byte, 64)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		for _, b := range buf {
			if int(b) < limit && len(out) < n {
				out = append(out, set[int(b)%len(set)])
			}
		}
	}
	return out, nil
}
