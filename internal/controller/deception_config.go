package controller

import (
	"sort"

	"github.com/PurdueBlueTeam/phylax/internal/honeytokens"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// honeySeeds turns the registry's detection profiles (Registry.Seeds) into the
// signed config's seeds: the static profiles rules/deception.yml tests with
// in_profile. Every host with rules gets them (a honey logon shows up on the
// DC, a canary key id on whichever host sees the egress).
func honeySeeds(tokens []honeytokens.Token) []plan.ProfileSeed {
	if len(tokens) == 0 {
		return nil
	}
	reg := honeytokens.NewRegistry()
	for _, t := range tokens {
		t.Secret = "" // secrets play no part in the seeds; skips secret uniqueness checks
		_ = reg.Add(t)
	}
	seeds := reg.Seeds()
	names := make([]string, 0, len(seeds))
	for n := range seeds {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []plan.ProfileSeed
	for _, n := range names {
		if vals := uniq(seeds[n]); len(vals) > 0 {
			out = append(out, plan.ProfileSeed{Profile: n, Values: vals})
		}
	}
	return out
}

// deceptionSettings builds a host's decoy section from decoys.yml and the
// registry: nil unless the host has the decoys role and a decoys entry.
func deceptionSettings(in ConfigInputs, host string, h manifest.Host) *plan.DeceptionSettings {
	m := in.Manifest
	d, ok := m.Decoys[host]
	if !h.HasRole(manifest.RoleDecoys) || !ok {
		return nil
	}
	ds := &plan.DeceptionSettings{Common: module.Common{Enabled: true}}
	for _, l := range d.Listeners {
		ds.Listeners = append(ds.Listeners, plan.DecoyListenerSettings{Kind: l.Kind, Port: l.Port})
	}
	ports := map[uint16]bool{}
	for _, id := range m.ServicesOn(host) {
		s := m.Services[id]
		if !s.Scored {
			continue
		}
		for _, l := range s.Listen {
			ps := l.PortSet()
			for _, p := range ps.Ports {
				ports[p] = true
			}
			for _, r := range ps.Ranges {
				if int(r.Hi)-int(r.Lo) < maxExpandedRange {
					for p := int(r.Lo); p <= int(r.Hi); p++ {
						ports[uint16(p)] = true
					}
				}
			}
		}
	}
	for p := range ports {
		ds.ScoredPorts = append(ds.ScoredPorts, p)
	}
	sort.Slice(ds.ScoredPorts, func(i, j int) bool { return ds.ScoredPorts[i] < ds.ScoredPorts[j] })
	var watch []string
	for _, t := range in.Tokens {
		ds.Tokens = append(ds.Tokens, plan.HoneyToken{ID: t.ID, Host: t.Host, Kind: string(t.Kind), Path: t.Path,
			User: t.User, Secret: t.Secret, Fingerprint: t.Fingerprint, SPN: t.SPN})
		// Shell history files are opened by the shell itself at every login and
		// exit: watching them would alert on the legitimate owner. They remain
		// tokens (the decoys still recognise the password).
		if t.Host == host && t.Path != "" && !t.Kind.IsAD() && t.Kind != honeytokens.KindShellHistory {
			watch = append(watch, t.Path)
		}
	}
	ds.WatchPaths = uniq(watch)
	return ds
}
