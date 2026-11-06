// Package enroll is the core first-contact path: one-time tokens, bundles,
// the enrollment decision, the bootstrap handler and the console one-liners.
// Modules never import it.
package enroll

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// Options are the controller-side dependencies of an Enroller.
type Options struct {
	DataDir       string // tokens.json, revoked.json, known_hosts.json live here
	MaxLiveTokens int    // 0 means 1024
	Store         *store.Store
	Identity      *link.Identity // the controller's transport identity (pin, certificate)
	PlanKey       ed25519.PublicKey
	ReleaseDir    string                                                        // phylax-linux-amd64 and phylax-windows-amd64.exe
	Advertise     string                                                        // controller host:port the host sees; empty means the request Host
	HostKnown     func(host string) bool                                        // nil allows any host
	Emit          func(ctx context.Context, e event.Event) (event.Event, error) // Controller.EmitController
	Alert         func(host, kind, detail string)                               // Controller.alert
	Connected     func(host string) bool                                        // true when the host's agent has a live session
	Now           func() time.Time                                              // nil means time.Now
}

// Enroller owns the token file and the enrollment decision.
type Enroller struct {
	opt Options

	mu       sync.Mutex // serialises enrollment decisions and revocation
	tokens   *Tokens
	revoked  *revokedKeys
	hostKeys *HostKeys

	nameMu     sync.Mutex // guards the lazy controller-wide install-name secret
	nameSecret []byte

	failMu sync.Mutex
	fails  map[string]failEntry
}

// failEntry counts one address's failed token lookups since the window began.
type failEntry struct {
	n     int
	since time.Time
}

// New opens the token and revocation files under o.DataDir.
func New(o Options) (*Enroller, error) {
	if o.MaxLiveTokens <= 0 {
		o.MaxLiveTokens = 1024
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	tokens, err := OpenTokens(filepath.Join(o.DataDir, "tokens.json"), o.MaxLiveTokens)
	if err != nil {
		return nil, err
	}
	tokens.now = o.Now
	revoked, err := openRevoked(filepath.Join(o.DataDir, "revoked.json"))
	if err != nil {
		return nil, err
	}
	hostKeys, err := OpenHostKeys(filepath.Join(o.DataDir, "known_hosts.json"))
	if err != nil {
		return nil, err
	}
	e := &Enroller{opt: o, tokens: tokens, revoked: revoked, hostKeys: hostKeys,
		fails: map[string]failEntry{}}
	return e, nil
}

// Tokens returns the token file for peeking and consuming.
func (e *Enroller) Tokens() *Tokens { return e.tokens }

// nameSecretFile holds the controller-wide secret the per-host install-name
// secrets derive from. It is created on first use (0600) and never leaves the
// controller's data dir.
const nameSecretFile = "name_secret"

// HostNameSecret derives the per-host secret the randomised service, binary
// and directory names come from. The controller secret is random, so the
// names are not computable from the host name alone.
func (e *Enroller) HostNameSecret(host string) ([]byte, error) {
	e.nameMu.Lock()
	defer e.nameMu.Unlock()
	if e.nameSecret == nil {
		sec, err := loadOrCreateNameSecret(e.opt.DataDir)
		if err != nil {
			return nil, err
		}
		e.nameSecret = sec
	}
	m := hmac.New(sha256.New, e.nameSecret)
	m.Write([]byte(host))
	return m.Sum(nil), nil
}

// loadOrCreateNameSecret reads the controller secret or creates a random one.
// The data-dir lock (LockDataDir) makes this process the only writer.
func loadOrCreateNameSecret(dir string) ([]byte, error) {
	path := filepath.Join(dir, nameSecretFile)
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("enroll: %s is %d bytes, want 32", path, len(b))
		}
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("enroll: %s: %w", path, err)
	}
	sec := make([]byte, 32)
	if _, err := rand.Read(sec); err != nil {
		return nil, err
	}
	if err := atomicfile.WriteFile(path, sec, 0o600); err != nil {
		return nil, fmt.Errorf("enroll: %s: %w", path, err)
	}
	return sec, nil
}

// MintToken creates a one-time enrollment token for a manifest host.
func (e *Enroller) MintToken(host string, ttl time.Duration) (string, error) {
	if e.opt.HostKnown != nil && !e.opt.HostKnown(host) {
		return "", ErrUnknownHost
	}
	return e.tokens.Mint(host, ttl)
}

// ErrRevoked reports a host key that an operator revoked.
var ErrRevoked = errors.New("enroll: key revoked")

// Result records what an Authorize call did.
type Result struct {
	Enrolled   bool // first enrollment of a host
	Reenrolled bool // a revoked host enrolled again
}

// Authorize decides whether pin may act as h.Host. Refusals call Options.Alert
// with the enrollment alert kind.
func (e *Enroller) Authorize(ctx context.Context, h *link.Hello, pin link.Pin) (Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	refuse := func(kind string, err error) (Result, error) {
		if e.opt.Alert != nil {
			e.opt.Alert(h.Host, kind, fmt.Sprintf("pin %s: %v", pin, err))
		}
		return Result{}, err
	}

	if e.revoked.has(h.Host) {
		ag, aerr := e.opt.Store.Agent(ctx, h.Host)
		switch {
		case aerr == nil && string(ag.PubKey) == string(pin[:]):
			return refuse("enroll.refused", ErrRevoked)
		case aerr != nil && !errors.Is(aerr, store.ErrUnknownAgent):
			return Result{}, aerr
		}
		if h.Token == "" {
			return refuse("enroll.refused", ErrRevoked)
		}
		if err := e.keyReuse(ctx, h.Host, pin); err != nil {
			return refuse("enroll.key_reuse", err)
		}
		if err := e.tokens.Consume(h.Token, h.Host, pin); err != nil {
			return refuse("enroll.refused", err)
		}
		res := Result{Reenrolled: true}
		if aerr == nil {
			if _, err := e.opt.Store.ArchiveAgent(ctx, h.Host, pin[:]); err != nil {
				return Result{}, err
			}
		} else {
			res = Result{Enrolled: true}
			if err := e.opt.Store.EnrollAgent(ctx, h.Host, pin[:]); err != nil {
				return Result{}, err
			}
		}
		if err := e.revoked.set(h.Host, false); err != nil {
			return Result{}, err
		}
		return res, nil
	}

	ag, err := e.opt.Store.Agent(ctx, h.Host)
	switch {
	case err == nil:
		if string(ag.PubKey) != string(pin[:]) {
			return refuse("enroll.key_mismatch", store.ErrKeyMismatch)
		}
		return Result{}, nil
	case !errors.Is(err, store.ErrUnknownAgent):
		return Result{}, err
	}
	if h.Token == "" {
		return refuse("enroll.refused", errors.New("unknown host without token"))
	}
	if err := e.keyReuse(ctx, h.Host, pin); err != nil {
		return refuse("enroll.key_reuse", err)
	}
	if err := e.tokens.Consume(h.Token, h.Host, pin); err != nil {
		return refuse("enroll.refused", err)
	}
	if err := e.opt.Store.EnrollAgent(ctx, h.Host, pin[:]); err != nil {
		return Result{}, err
	}
	res := Result{Enrolled: true}
	return res, nil
}

// keyReuse refuses a key already enrolled as another host.
func (e *Enroller) keyReuse(ctx context.Context, host string, pin link.Pin) error {
	all, err := e.opt.Store.Agents(ctx)
	if err != nil {
		return err
	}
	for _, o := range all {
		if o.ID != host && string(o.PubKey) == string(pin[:]) {
			return fmt.Errorf("key already enrolled as %q", o.ID)
		}
	}
	return nil
}

// Announce emits agent.enrolled or agent.reenrolled through Options.Emit.
func (e *Enroller) Announce(ctx context.Context, host string, pin link.Pin, r Result) error {
	var ev event.Event
	var err error
	switch {
	case r.Reenrolled:
		ev, err = event.New("agent.reenrolled", event.AgentReenrolled{Host: host, KeyHash: pin.String(), Manifest: host})
	case r.Enrolled:
		ev, err = event.New("agent.enrolled", event.AgentEnrolled{Host: host, KeyHash: pin.String(), Manifest: host})
	default:
		return nil
	}
	if err != nil {
		return err
	}
	if e.opt.Emit == nil {
		return errors.New("enroll: announce needs Options.Emit")
	}
	if _, err := e.opt.Emit(ctx, ev); err != nil {
		return err
	}
	return nil
}

// Revoke makes host's current key unusable until a new token replaces it.
// A live session is closed by the caller.
func (e *Enroller) Revoke(ctx context.Context, host string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.revoked.set(host, true)
}

// Revoked reports whether host's current key is revoked.
func (e *Enroller) Revoked(host string) bool { return e.revoked.has(host) }
