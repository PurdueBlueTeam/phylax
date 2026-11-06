package enroll

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	phyagent "github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
)

// BundleOptions are the controller-side knobs of a bootstrap bundle.
type BundleOptions struct {
	Controllers []string      // host:port the agent dials, required
	TTL         time.Duration // token lifetime; <= 0 means DefaultTokenTTL
	Safe        bool
}

// WriteBundles mints one token per host and writes <dir>/<host>.json (dir mode
// 0700, files 0600). All hosts are validated before any token is minted, so a
// refused host costs no token.
func (e *Enroller) WriteBundles(dir string, hosts []string, o BundleOptions) error {
	bundles := make([]phyagent.Bundle, len(hosts))
	for i, h := range hosts {
		b, err := e.bundleFor(h, o, "")
		if err != nil {
			return err
		}
		bundles[i] = *b
	}

	// shortcut: MkdirAll does not tighten an existing looser dir mode; the
	// token-bearing files are 0600 either way, tighten if bundles ever land in
	// a shared directory.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("enroll: bundle dir: %w", err)
	}
	for i := range bundles {
		b := &bundles[i]
		tok, err := e.MintToken(b.Host, o.TTL)
		if err != nil {
			return fmt.Errorf("enroll: bundle for %s: %w", b.Host, err)
		}
		b.Token = tok
		data, err := json.MarshalIndent(b, "", "  ")
		if err != nil {
			return err
		}
		// Exact mode: a re-run must not keep a loosened mode on a file that
		// carries a live token.
		if err := atomicfile.WriteExactMode(filepath.Join(dir, b.Host+".json"), data, 0o600); err != nil {
			return fmt.Errorf("enroll: bundle for %s: %w", b.Host, err)
		}
	}
	return nil
}

// Bundle returns the in-memory bootstrap bundle for host with a fresh token.
func (e *Enroller) Bundle(host string, o BundleOptions) (*phyagent.Bundle, error) {
	tok, err := e.MintToken(host, o.TTL)
	if err != nil {
		return nil, err
	}
	return e.bundleFor(host, o, tok)
}

// bundleFor assembles (and validates) a bundle, with token when one is given.
func (e *Enroller) bundleFor(host string, o BundleOptions, token string) (*phyagent.Bundle, error) {
	if host == "" {
		return nil, errors.New("enroll: bundle needs a host name")
	}
	if e.opt.HostKnown != nil && !e.opt.HostKnown(host) {
		return nil, fmt.Errorf("%w: %s", ErrUnknownHost, host)
	}
	b := &phyagent.Bundle{
		Controllers:   o.Controllers,
		ControllerPin: e.opt.Identity.Pin.String(),
		Host:          host,
		Token:         token,
		PlanKey:       hex.EncodeToString(e.opt.PlanKey),
		Safe:          o.Safe,
	}
	// Validates the addresses, the pin and the plan key exactly as the agent
	// will on start.
	if _, err := b.Validate(); err != nil {
		return nil, fmt.Errorf("enroll: bundle for %s: %w", host, err)
	}
	return b, nil
}
