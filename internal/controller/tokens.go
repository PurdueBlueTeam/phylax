package controller

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/link"
)

var (
	ErrTokenInvalid  = errors.New("controller: enrollment token invalid")
	ErrTokenExpired  = errors.New("controller: enrollment token expired")
	ErrTokenUsed     = errors.New("controller: enrollment token already used")
	ErrTokenHost     = errors.New("controller: enrollment token is bound to a different host")
	ErrTooManyTokens = errors.New("controller: too many live enrollment tokens")
	ErrUnknownHost   = errors.New("controller: host is not in the manifest")
)

// DefaultTokenTTL is the enrollment token lifetime (design: 10 minutes).
const DefaultTokenTTL = 10 * time.Minute

type tokenRec struct {
	Hash    string    `json:"hash"` // hex sha256 of the token; the token itself is never stored
	Host    string    `json:"host"`
	Expires time.Time `json:"expires"`
	UsedBy  string    `json:"used_by,omitempty"` // pin of the key that consumed it
	UsedAt  time.Time `json:"used_at,omitempty"`
}

// Tokens mints and consumes one-time enrollment tokens, persisted (hashed) in
// a file so they survive a controller restart.
type Tokens struct {
	path string
	max  int
	now  func() time.Time

	mu   sync.Mutex
	recs map[string]*tokenRec // by hash
}

// OpenTokens loads (or starts) the token file at path.
func OpenTokens(path string, maxLive int) (*Tokens, error) {
	if maxLive <= 0 {
		maxLive = 1024
	}
	t := &Tokens{path: path, max: maxLive, now: time.Now, recs: map[string]*tokenRec{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return t, nil
	}
	if err != nil {
		return nil, err
	}
	var recs []*tokenRec
	if err := json.Unmarshal(b, &recs); err != nil {
		return nil, fmt.Errorf("controller: token file %s: %w", path, err)
	}
	for _, r := range recs {
		t.recs[r.Hash] = r
	}
	return t, nil
}

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func (t *Tokens) saveLocked() error {
	// Drop records that can no longer matter: expired and unused, or used long ago.
	now := t.now()
	out := make([]*tokenRec, 0, len(t.recs))
	for h, r := range t.recs {
		if (r.UsedBy == "" && now.After(r.Expires)) || (r.UsedBy != "" && now.Sub(r.UsedAt) > 24*time.Hour) {
			delete(t.recs, h)
			continue
		}
		out = append(out, r)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(t.path, b, 0o600)
}

func (t *Tokens) liveLocked() int {
	n := 0
	now := t.now()
	for _, r := range t.recs {
		if r.UsedBy == "" && now.Before(r.Expires) {
			n++
		}
	}
	return n
}

// Mint creates a token bound to host, valid for ttl (DefaultTokenTTL if <= 0).
// The plaintext is returned once and never stored.
func (t *Tokens) Mint(host string, ttl time.Duration) (string, error) {
	if host == "" || len(host) > 253 {
		return "", errors.New("controller: token needs a host name")
	}
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	var raw [20]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	tok := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:])
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.liveLocked() >= t.max {
		return "", ErrTooManyTokens
	}
	h := hashToken(tok)
	t.recs[h] = &tokenRec{Hash: h, Host: host, Expires: t.now().Add(ttl)}
	if err := t.saveLocked(); err != nil {
		delete(t.recs, h)
		return "", err
	}
	return tok, nil
}

// Consume spends tok for host presenting key pin. A wrong-host claim does not
// burn the token. Presenting the same (token, pin) again succeeds (idempotent
// retry after a dropped connection); a different pin is ErrTokenUsed.
func (t *Tokens) Consume(tok, host string, pin link.Pin) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.recs[hashToken(tok)]
	if !ok {
		return ErrTokenInvalid
	}
	if r.Host != host {
		return ErrTokenHost
	}
	if r.UsedBy != "" {
		if r.UsedBy == pin.String() {
			return nil
		}
		return ErrTokenUsed
	}
	if t.now().After(r.Expires) {
		return ErrTokenExpired
	}
	r.UsedBy, r.UsedAt = pin.String(), t.now()
	if err := t.saveLocked(); err != nil {
		r.UsedBy, r.UsedAt = "", time.Time{}
		return err
	}
	return nil
}
