package controller

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
func (c *Controller) WriteBundles(dir string, hosts []string, o BundleOptions) error {
	key := hex.EncodeToString(c.PlanPublicKey())
	pin := c.Pin().String()

	bundles := make([]phyagent.Bundle, len(hosts))
	for i, h := range hosts {
		if h == "" {
			return errors.New("controller: bundle needs a host name")
		}
		if c.opt.HostKnown != nil && !c.opt.HostKnown(h) {
			return fmt.Errorf("%w: %s", ErrUnknownHost, h)
		}
		bundles[i] = phyagent.Bundle{
			Controllers:   o.Controllers,
			ControllerPin: pin,
			Host:          h,
			PlanKey:       key,
			Safe:          o.Safe,
		}
		// Validates the addresses, the pin and the plan key exactly as the
		// agent will on start.
		if _, err := bundles[i].Validate(); err != nil {
			return fmt.Errorf("controller: bundle for %s: %w", h, err)
		}
	}

	// shortcut: MkdirAll does not tighten an existing looser dir mode; the
	// token-bearing files are 0600 either way, tighten if bundles ever land in
	// a shared directory.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("controller: bundle dir: %w", err)
	}
	for i := range bundles {
		b := &bundles[i]
		tok, err := c.MintToken(b.Host, o.TTL)
		if err != nil {
			return fmt.Errorf("controller: bundle for %s: %w", b.Host, err)
		}
		b.Token = tok
		data, err := json.MarshalIndent(b, "", "  ")
		if err != nil {
			return err
		}
		// Exact mode: a re-run must not keep a loosened mode on a file that
		// carries a live token.
		if err := atomicfile.WriteExactMode(filepath.Join(dir, b.Host+".json"), data, 0o600); err != nil {
			return fmt.Errorf("controller: bundle for %s: %w", b.Host, err)
		}
	}
	return nil
}
