// Package enroll is the core first-contact path: one-time tokens, bundles,
// the enrollment decision, the bootstrap handler and the console one-liners.
// Modules never import it.
package enroll

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"sync"
	"time"

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
	HostKnown     func(host string) bool                                        // nil allows any host
	Emit          func(ctx context.Context, e event.Event) (event.Event, error) // Controller.EmitController
	Alert         func(host, kind, detail string)                               // Controller.alert
	Connected     func(host string) bool                                        // true when the host's agent has a live session
	Now           func() time.Time                                              // nil means time.Now
}

// Enroller owns the token file and the enrollment decision.
type Enroller struct {
	opt Options

	mu     sync.Mutex // serialises enrollment decisions
	tokens *Tokens
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
	return &Enroller{opt: o, tokens: tokens}, nil
}

// Tokens returns the token file for peeking and consuming.
func (e *Enroller) Tokens() *Tokens { return e.tokens }

// MintToken creates a one-time enrollment token for a manifest host.
func (e *Enroller) MintToken(host string, ttl time.Duration) (string, error) {
	if e.opt.HostKnown != nil && !e.opt.HostKnown(host) {
		return "", ErrUnknownHost
	}
	return e.tokens.Mint(host, ttl)
}
