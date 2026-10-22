package ui

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// ---------------------------------------------------------------- accounts

// ErrNoAccount is returned by AccountStore.Get for an unknown operator.
var ErrNoAccount = errors.New("ui: no such account")

// Account is one operator login. Hash is a PHC-format argon2id string.
type Account struct {
	Name    string
	Hash    string
	Created time.Time
}

// AccountStore persists operator accounts. The controller backs it with the
// store; MemAccounts is the in-memory implementation used by tests.
type AccountStore interface {
	Get(ctx context.Context, name string) (Account, error)
	Put(ctx context.Context, a Account) error
	Count(ctx context.Context) (int, error)
}

// MemAccounts is a goroutine-safe in-memory AccountStore.
type MemAccounts struct {
	mu sync.Mutex
	m  map[string]Account
}

func NewMemAccounts() *MemAccounts { return &MemAccounts{m: map[string]Account{}} }

func (s *MemAccounts) Get(_ context.Context, name string) (Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.m[name]
	if !ok {
		return Account{}, ErrNoAccount
	}
	return a, nil
}

func (s *MemAccounts) Put(_ context.Context, a Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[a.Name] = a
	return nil
}

func (s *MemAccounts) Count(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m), nil
}

// ---------------------------------------------------------------- argon2id

// Argon2Params are the argon2id cost parameters. Memory is in KiB.
type Argon2Params struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

// DefaultArgon2 follows the RFC 9106 "second recommended" profile.
var DefaultArgon2 = Argon2Params{Time: 3, Memory: 64 * 1024, Threads: 2}

const (
	argonSaltLen = 16
	argonKeyLen  = 32
	maxPassword  = 256 // bytes; bounds the work an attacker can force
	minPassword  = 12
)

// HashPassword returns a PHC-format argon2id hash of pw.
func HashPassword(pw string, p Argon2Params) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, p.Time, p.Memory, p.Threads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword checks pw against a PHC hash in constant time. Parameters
// are read from the hash but bounded so a corrupt record cannot exhaust memory.
func VerifyPassword(pw, phc string) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var ver int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &ver); err != nil || ver != argon2.Version {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	if m < 8 || m > 1<<20 || t < 1 || t > 20 || p < 1 || p > 16 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) < 16 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("ui: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---------------------------------------------------------------- sessions

type session struct {
	user     string // empty until authenticated
	csrf     string
	created  time.Time
	lastSeen time.Time
}

func (s *session) authed() bool { return s.user != "" }

type sessionStore struct {
	mu       sync.Mutex
	m        map[string]*session // key: sha256(cookie value)
	idle     time.Duration
	absolute time.Duration
	maxAnon  int
	maxAuth  int
	now      func() time.Time
}

func newSessionStore(idle, abs time.Duration, now func() time.Time) *sessionStore {
	return &sessionStore{m: map[string]*session{}, idle: idle, absolute: abs, maxAnon: 1000, maxAuth: 256, now: now}
}

func sessKey(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:])
}

func (st *sessionStore) expiredLocked(s *session, now time.Time) bool {
	return now.Sub(s.lastSeen) > st.idle || now.Sub(s.created) > st.absolute
}

// create makes a new session (anonymous when user is empty) and returns the
// cookie value. Expired entries are swept; if still over the cap the oldest
// session of that kind is evicted.
func (st *sessionStore) create(user string) (string, *session) {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := st.now()
	var anon, auth int
	for k, s := range st.m {
		if st.expiredLocked(s, now) {
			delete(st.m, k)
			continue
		}
		if s.authed() {
			auth++
		} else {
			anon++
		}
	}
	limit, count := st.maxAnon, anon
	if user != "" {
		limit, count = st.maxAuth, auth
	}
	if count >= limit {
		var ok string
		var oldest time.Time
		for k, s := range st.m {
			if s.authed() == (user != "") && (ok == "" || s.lastSeen.Before(oldest)) {
				ok, oldest = k, s.lastSeen
			}
		}
		delete(st.m, ok)
	}
	id := randToken(32)
	s := &session{user: user, csrf: randToken(32), created: now, lastSeen: now}
	st.m[sessKey(id)] = s
	return id, s
}

// get looks up and touches a session; expired sessions are deleted.
func (st *sessionStore) get(id string) (session, bool) {
	if id == "" {
		return session{}, false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	k := sessKey(id)
	s, ok := st.m[k]
	if !ok {
		return session{}, false
	}
	now := st.now()
	if st.expiredLocked(s, now) {
		delete(st.m, k)
		return session{}, false
	}
	s.lastSeen = now
	return *s, true
}

func (st *sessionStore) destroy(id string) {
	st.mu.Lock()
	delete(st.m, sessKey(id))
	st.mu.Unlock()
}

// destroyUser removes every session of user except the one with keepID.
func (st *sessionStore) destroyUser(user, keepID string) {
	keep := sessKey(keepID)
	st.mu.Lock()
	defer st.mu.Unlock()
	for k, s := range st.m {
		if s.user == user && k != keep {
			delete(st.m, k)
		}
	}
}

// ---------------------------------------------------------------- rate limit

type limitEntry struct {
	fails       int
	first       time.Time
	lockedUntil time.Time
}

// loginLimiter counts failures per key (client address and username) and
// locks a key out once it reaches max failures within window.
type loginLimiter struct {
	mu      sync.Mutex
	m       map[string]*limitEntry
	max     int
	window  time.Duration
	lockout time.Duration
	cap     int
	now     func() time.Time
}

func newLoginLimiter(max int, window, lockout time.Duration, now func() time.Time) *loginLimiter {
	return &loginLimiter{m: map[string]*limitEntry{}, max: max, window: window, lockout: lockout, cap: 10000, now: now}
}

// blocked reports whether any key is locked, and for how long.
func (l *loginLimiter) blocked(keys ...string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var worst time.Duration
	for _, k := range keys {
		if e := l.m[k]; e != nil && now.Before(e.lockedUntil) {
			if d := e.lockedUntil.Sub(now); d > worst {
				worst = d
			}
		}
	}
	return worst, worst > 0
}

func (l *loginLimiter) fail(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.m) >= l.cap {
		for k, e := range l.m {
			if now.After(e.lockedUntil) && now.Sub(e.first) > l.window {
				delete(l.m, k)
			}
		}
		for k := range l.m { // still full: evict arbitrary unlocked entries
			if len(l.m) < l.cap {
				break
			}
			if now.After(l.m[k].lockedUntil) {
				delete(l.m, k)
			}
		}
	}
	for _, k := range keys {
		e := l.m[k]
		if e == nil || now.Sub(e.first) > l.window {
			e = &limitEntry{first: now}
			l.m[k] = e
		}
		e.fails++
		if e.fails >= l.max {
			e.lockedUntil = now.Add(l.lockout)
			e.fails, e.first = 0, now
		}
	}
}

func (l *loginLimiter) success(keys ...string) {
	l.mu.Lock()
	for _, k := range keys {
		delete(l.m, k)
	}
	l.mu.Unlock()
}
