// Package agent is the runtime of `phylax agent`: bootstrap and state layout,
// identity, the reconnecting link loop, the module host and supervisor, the
// health module, and the dead-man rollback entry point.
package agent

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/link"
)

// Bundle is the bootstrap file (design: "Enrollment, bootstrap and recovery").
// It carries only the controller's address(es) and pin, the host identity, the
// one-time token and the initial roles. Modules, rules and watches arrive
// later as signed config messages.
type Bundle struct {
	// Controllers are host:port addresses (controller or relays), tried in
	// rotation on each connection attempt.
	Controllers []string `json:"controllers"`
	// ControllerPin is the controller key pin (64 hex or sha256//base64).
	ControllerPin string `json:"controller_pin"`
	// Host is the manifest host name.
	Host string `json:"host"`
	// Token is the one-time enrollment token; removed after enrollment.
	Token string `json:"token,omitempty"`
	// Roles are the initial role switches from the manifest.
	Roles []string `json:"roles,omitempty"`
	// PlanKey is the controller's Ed25519 plan-signing public key (64 hex).
	// Steps are executed only if signed by it; with execution enabled the
	// agent refuses to start without one.
	PlanKey string `json:"plan_key,omitempty"`
}

// PlanPublicKey parses PlanKey; nil, nil if none is set.
func (b *Bundle) PlanPublicKey() (ed25519.PublicKey, error) {
	if b.PlanKey == "" {
		return nil, nil
	}
	raw, err := hex.DecodeString(strings.TrimSpace(b.PlanKey))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("bootstrap: plan_key must be 64 hex characters (Ed25519 public key)")
	}
	return ed25519.PublicKey(raw), nil
}

// Validate checks the bundle and returns the parsed pin.
func (b *Bundle) Validate() (link.Pin, error) {
	if len(b.Controllers) == 0 {
		return link.Pin{}, errors.New("bootstrap: no controller address")
	}
	for _, a := range b.Controllers {
		if _, _, err := net.SplitHostPort(a); err != nil {
			return link.Pin{}, fmt.Errorf("bootstrap: controller address %q: %w", a, err)
		}
	}
	if b.Host == "" || len(b.Host) > 253 {
		return link.Pin{}, errors.New("bootstrap: host name missing or too long")
	}
	if len(b.Token) > 256 {
		return link.Pin{}, errors.New("bootstrap: token too long")
	}
	if _, err := b.PlanPublicKey(); err != nil {
		return link.Pin{}, err
	}
	return link.ParsePin(b.ControllerPin)
}

// ParseBundle decodes and validates a bootstrap file's contents.
func ParseBundle(data []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	for i := range b.Controllers {
		b.Controllers[i] = strings.TrimSpace(b.Controllers[i])
	}
	if _, err := b.Validate(); err != nil {
		return nil, err
	}
	return &b, nil
}

// Layout is the agent state directory:
//
//	<root>/bootstrap.json   bundle (token removed once enrolled)
//	<root>/identity.pem     ECDSA P-256 key + certificate, mode 0600
//	<root>/state.json       enrollment flag
//	<root>/spool/           internal/spool
//	<root>/deadman/         internal/deadman journal
type Layout struct{ Root string }

func (l Layout) Bootstrap() string { return filepath.Join(l.Root, "bootstrap.json") }
func (l Layout) Identity() string  { return filepath.Join(l.Root, "identity.pem") }
func (l Layout) State() string     { return filepath.Join(l.Root, "state.json") }
func (l Layout) SpoolDir() string  { return filepath.Join(l.Root, "spool") }

// PlanSeq is the persisted (epoch, seq) high-water mark of accepted steps.
func (l Layout) PlanSeq() string { return filepath.Join(l.Root, "planseq.json") }

// SafeModeFile is the marker file whose presence means safe mode is on.
func (l Layout) SafeModeFile() string { return filepath.Join(l.Root, "safe_mode") }
func (l Layout) DeadmanDir() string {
	return filepath.Join(l.Root, "deadman")
}

// Ensure creates the root directory (mode 0700).
func (l Layout) Ensure() error { return os.MkdirAll(l.Root, 0o700) }

// LoadBundle reads the bootstrap file.
func (l Layout) LoadBundle() (*Bundle, error) {
	data, err := os.ReadFile(l.Bootstrap())
	if err != nil {
		return nil, err
	}
	return ParseBundle(data)
}

// SaveBundle writes the bootstrap file atomically with mode 0600.
func (l Layout) SaveBundle(b *Bundle) error {
	if _, err := b.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if err := l.Ensure(); err != nil {
		return err
	}
	return atomicfile.WriteFile(l.Bootstrap(), data, 0o600)
}

// State is the small persistent agent state.
type State struct {
	Enrolled bool `json:"enrolled"`
}

// LoadState reads state.json; a missing file is the zero state.
func (l Layout) LoadState() (State, error) {
	var s State
	data, err := os.ReadFile(l.State())
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(data, &s)
}

// SaveState writes state.json atomically.
func (l Layout) SaveState(s State) error {
	data, _ := json.Marshal(s)
	if err := l.Ensure(); err != nil {
		return err
	}
	return atomicfile.WriteFile(l.State(), data, 0o600)
}

// LoadIdentity returns the agent's transport identity, generating and saving
// it (atomically, 0600) on first start.
func (l Layout) LoadIdentity(host string) (*link.Identity, error) {
	if err := l.Ensure(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(l.Identity())
	if err == nil {
		return link.ParseIdentity(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	id, err := link.GenerateIdentity(host)
	if err != nil {
		return nil, err
	}
	pem, err := id.Marshal()
	if err != nil {
		return nil, err
	}
	if err := atomicfile.WriteFile(l.Identity(), pem, 0o600); err != nil {
		return nil, err
	}
	return id, nil
}
