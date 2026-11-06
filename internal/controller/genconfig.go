package controller

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/honeytokens"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// ConfigInputs is everything besides the manifest that goes into the agents'
// configs: the detection rules and the reference ledger the integrity module
// judges against.
type ConfigInputs struct {
	Manifest *manifest.Manifest
	Rules    []plan.RuleFile
	Ledger   plan.LedgerRef
	// Tokens is a snapshot of the honeytoken registry (secrets included), set
	// by the controller when it builds a config; see deception_config.go.
	Tokens []honeytokens.Token
}

// Per-module event budgets (events per second sustained / burst) applied at
// the supervisor. Audit and winevt also limit internally.
var moduleBudgets = map[string][2]int{
	"net": {500, 1000}, "winevt": {2000, 4000}, "integrity": {100, 200}, "detect": {100, 200},
}

const maxExpandedRange = 64

// BuildAgentConfig derives a host's AgentConfig from the manifest. Epoch,
// Version and IssuedAt are the caller's. Warnings name inputs that could not
// be used (the config is still produced).
func BuildAgentConfig(in ConfigInputs, host string) (cfg *plan.AgentConfig, warnings []string, err error) {
	m := in.Manifest
	if m == nil {
		return nil, nil, fmt.Errorf("no manifest")
	}
	h, ok := m.Hosts[host]
	if !ok {
		return nil, nil, fmt.Errorf("host %q is not in the manifest", host)
	}
	cfg = &plan.AgentConfig{Host: host, Roles: expandRoles(h.Roles)}
	enabled := module.Common{Enabled: true} // every block the controller renders runs
	lim := func(mod string) plan.ModuleLimits {
		b := moduleBudgets[mod]
		return plan.ModuleLimits{Common: enabled, RatePerSec: float64(b[0]), Burst: b[1]}
	}
	cfg.Modules.Health = &plan.HealthSettings{ModuleLimits: plan.ModuleLimits{Common: enabled}, IntervalSec: 60}

	svcs := m.ServicesOn(host)
	var webRoots, bins []string
	var pins []plan.PinSettings
	comms := map[string]bool{}
	netSvc := map[string]string{}
	for _, id := range svcs {
		s := m.Services[id]
		if s.Content != nil {
			webRoots = append(webRoots, s.Content.Roots...)
			webRoots = append(webRoots, s.Content.UploadDirs...)
		}
		if s.Process != nil {
			unit := s.Process.Unit
			if unit == "" && len(s.Process.Units) > 0 {
				unit = s.Process.Units[0]
			}
			for _, b := range s.Process.Binaries {
				bins = append(bins, b)
				if s.Process.Pin {
					pins = append(pins, plan.PinSettings{Service: id, Path: b, Unit: unit})
				}
				if s.Scored {
					comms[comm(b)] = true
				}
			}
		}
		for _, l := range s.Listen {
			ps := l.PortSet()
			for _, p := range ps.Ports {
				netSvc[fmt.Sprintf("%s/%d", l.Proto, p)] = id
			}
			for _, r := range ps.Ranges {
				if int(r.Hi)-int(r.Lo) >= maxExpandedRange {
					warnings = append(warnings, fmt.Sprintf("service %s: port range %s too wide to name; left unnamed", id, r))
					continue
				}
				for p := int(r.Lo); p <= int(r.Hi); p++ {
					netSvc[fmt.Sprintf("%s/%d", l.Proto, p)] = id
				}
			}
		}
	}
	for _, d := range m.Decoys[host].Listeners {
		netSvc[fmt.Sprintf("tcp/%d", d.Port)] = "decoy-" + d.Kind
	}

	if h.IsWindows() {
		cfg.Modules.Winevt = &plan.WinevtSettings{ModuleLimits: lim("winevt")}
	} else {
		cfg.Modules.Audit = &plan.AuditSettings{ModuleLimits: plan.ModuleLimits{Common: enabled}, WebRoots: uniq(webRoots), ServiceBinaries: uniq(bins)}
		cfg.Modules.Net = &plan.NetSettings{ModuleLimits: lim("net"), Services: nilIfEmpty(netSvc), HashExe: true, IntervalMS: 2000}
		hp, perr := render.BuildHostPolicy(m, host)
		if perr != nil {
			warnings = append(warnings, "firewall policy not derived, no NFLOG groups or canaries: "+perr.Error())
		} else {
			groups := map[uint16]bool{}
			if hp.DenyLogGroup != 0 && !hp.Workstation {
				groups[hp.DenyLogGroup] = true
			}
			for _, r := range hp.Rules {
				if r.Log && r.LogGroup != 0 {
					groups[r.LogGroup] = true
				}
				if r.Group == render.GroupCanary && r.Dir == render.Out && !r.Approx {
					for _, p := range r.Peers {
						for _, port := range r.RemotePorts {
							cfg.Modules.Net.Canaries = append(cfg.Modules.Net.Canaries,
								plan.CanarySettings{Addr: p.Addr().String(), Port: port, Tag: "canary"})
						}
					}
				}
			}
			for g := range groups {
				cfg.Modules.Net.NFLogGroups = append(cfg.Modules.Net.NFLogGroups, g)
			}
			sort.Slice(cfg.Modules.Net.NFLogGroups, func(i, j int) bool { return cfg.Modules.Net.NFLogGroups[i] < cfg.Modules.Net.NFLogGroups[j] })
		}
		cfg.Modules.Integrity = &plan.IntegritySettings{ModuleLimits: lim("integrity"), Pins: pins, Ledger: in.Ledger}
	}
	if len(in.Rules) > 0 {
		d := &plan.DetectSettings{ModuleLimits: lim("detect"), Rules: in.Rules, Seeds: detectSeeds(m, host, h, svcs, comms)}
		d.Seeds = append(d.Seeds, honeySeeds(in.Tokens)...)
		cfg.Modules.Detect = d
	}
	cfg.Modules.Deception = deceptionSettings(in, host, h)
	return cfg, warnings, nil
}

// detectSeeds fills the manifest-derived static profiles: the behavioural
// scorer exemption (scored accounts and service processes, never addresses).
func detectSeeds(m *manifest.Manifest, host string, h manifest.Host, svcs []string, comms map[string]bool) []plan.ProfileSeed {
	var scored, pending, deps []string
	for key, a := range m.Accounts {
		if !accountOn(a, host) {
			continue
		}
		name := a.Username
		if name == "" {
			name, _, _ = strings.Cut(key, "@")
		}
		if a.Protected() {
			scored = append(scored, name)
		}
		if h.DefaultCredential != "" && (a.Rotation == "pcr_transaction" || a.Rotation == "free") {
			pending = append(pending, name)
		}
	}
	for _, id := range svcs {
		for _, d := range m.Services[id].DependsOn {
			if a, ok := m.HostAddr(d.To); ok {
				deps = append(deps, a.String())
			}
		}
	}
	var out []plan.ProfileSeed
	add := func(profile string, vals []string) {
		if vals = uniq(vals); len(vals) > 0 {
			out = append(out, plan.ProfileSeed{Profile: profile, Values: vals})
		}
	}
	add("accounts.scored", scored)
	add("rotation.pending", pending)
	add("service.dependencies", deps)
	cs := make([]string, 0, len(comms))
	for c := range comms {
		cs = append(cs, c)
	}
	add("scored.service_comms", cs)
	return out
}

func accountOn(a manifest.Account, host string) bool {
	if len(a.Hosts) == 0 || a.Scope == "domain" || a.Scope == "service" {
		return true
	}
	for _, x := range a.Hosts {
		if x == host {
			return true
		}
	}
	return false
}

// comm is the kernel's process name for a binary path (15 characters).
func comm(binary string) string {
	b := path.Base(strings.ReplaceAll(binary, `\`, "/"))
	if len(b) > 15 {
		b = b[:15]
	}
	return b
}

func expandRoles(in []string) []string {
	set := map[string]bool{}
	for _, r := range in {
		if r == manifest.RoleVantage {
			set[manifest.RoleCheckRunner], set[manifest.RoleScanner], set[manifest.RoleCanary] = true, true, true
		}
		set[r] = true
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

func uniq(in []string) []string {
	set := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !set[s] {
			set[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func nilIfEmpty(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	return m
}
