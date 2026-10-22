package controller

import (
	"net/netip"
	"sort"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

// scorerSourceProfile is the static profile controller-scope scan rules
// exclude by (reference.scorer_sources in rules/profiles.yml).
const scorerSourceProfile = "reference.scorer_sources"

// maxLearnedSources bounds the addresses scorer discovery can add at run time.
const maxLearnedSources = 256

// ManifestScorerSources lists the addresses whose traffic is expected to look
// like scanning and must never count as scan fan-in: the vantage hosts
// (scanner and canary roles: the Kali; a bare check_runner does not scan), the address their segment is
// source-translated to, their public address, and the controller host (the
// team console). Hosts with a DHCP address contribute nothing here; the
// scorer itself is identified by behaviour, so its addresses arrive through
// NoteScorerSource when discovery has confirmed them.
//
// This is a profile seed, not an access rule: nothing is ever filtered or
// blocked by it, it only keeps our own tooling out of P88 (D13e).
func ManifestScorerSources(m *manifest.Manifest) []string {
	if m == nil {
		return nil
	}
	set := map[string]bool{}
	add := func(s string) {
		if a, err := netip.ParseAddr(s); err == nil {
			set[a.Unmap().String()] = true
		}
	}
	for name, h := range m.Hosts {
		if !(h.HasRole(manifest.RoleScanner) || h.HasRole(manifest.RoleCanary)) && name != m.ControllerHost() {
			continue
		}
		if a, ok := m.HostAddr(name); ok {
			add(a.String())
		}
		if h.Public != "" {
			add(h.Public)
		}
		if a, ok := m.TranslatedSource(h.Segment); ok {
			add(a.String())
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// NoteScorerSource records an address that scorer discovery or the operator
// has confirmed as scorer, vantage or team-console traffic. It joins the
// reference.scorer_sources profile at once and survives rule reloads (not a
// controller restart: re-derive it from discovery). Returns false when the
// address is invalid or the bounded set is full.
func (c *Controller) NoteScorerSource(addr string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	return c.capture().noteSource(a.Unmap().String())
}
