package vyos

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/devices"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
)

// TranslateOpts carries what the intent does not know.
type TranslateOpts struct {
	// OutboundInterface is the NAT egress interface (for example eth0). Empty
	// leaves it out and adds a warning.
	OutboundInterface string
}

// Translation is the typed intent as device changes.
type Translation struct {
	Policy     devices.ChangeSet // source NAT and forward firewall rules
	PolicyRisk devices.Risk
	Mgmt       devices.ChangeSet // SSH/HTTPS lockdown: lockout class, needs the dead-man
	MgmtRisk   devices.Risk
	Warnings   []string
}

// clean keeps descriptions to plain words so they can never break out of the
// single quotes of a vbash command.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == ' ', r == '.', r == ':', r == '-', r == '_', r == '/', r == ',':
			return r
		}
		return ' '
	}, s)
}

func normAddr(v string) string {
	if _, err := netip.ParsePrefix(v); err == nil {
		return v
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return a.String()
	}
	return v
}

func portSpec(s render.ServiceSpec) string {
	var parts []string
	for _, p := range s.Ports {
		parts = append(parts, strconv.Itoa(int(p)))
	}
	for _, r := range s.Ranges {
		if r.Lo == r.Hi {
			parts = append(parts, strconv.Itoa(int(r.Lo)))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", r.Lo, r.Hi))
		}
	}
	return strings.Join(parts, ",")
}

func q(v string) string { return "'" + v + "'" }

// one address per endpoint list: VyOS rules take a single address.
func oneAddr(eps []render.Endpoint, what string, rule int) (addr string, skip bool, warn string, err error) {
	switch len(eps) {
	case 0:
		return "", false, "", nil
	case 1:
		if eps[0].Value == "" {
			return "", true, fmt.Sprintf("firewall rule %d skipped: %s %q has no address yet", rule, what, eps[0].Host), nil
		}
		return normAddr(eps[0].Value), false, "", nil
	}
	return "", false, "", fmt.Errorf("vyos: rule %d has %d %s endpoints; a VyOS rule takes one", rule, len(eps), what)
}

// Translate turns the typed VyOS intent into ChangeSets. Each rule is
// replaced as a whole (delete then set), guarded so only phylax-managed rules
// are replaced.
func (a *Adapter) Translate(in *render.VyOSIntent, opt TranslateOpts) (*Translation, error) {
	t := &Translation{PolicyRisk: devices.RiskNone, MgmtRisk: devices.RiskLockout}
	raise := func(r string) {
		switch r {
		case render.RiskLockout:
			t.PolicyRisk = devices.RiskLockout
		case render.RiskService:
			if t.PolicyRisk == devices.RiskNone {
				t.PolicyRisk = devices.RiskService
			}
		}
	}
	desc := func(d string) string {
		d = clean(d)
		if !strings.HasPrefix(d, ManagedTag) {
			d = ManagedTag + ": " + d
		}
		return d
	}

	for _, n := range in.SourceNAT {
		base := fmt.Sprintf("nat source rule %d", n.Rule)
		cmds := []string{"delete " + base,
			fmt.Sprintf("set %s description %s", base, q(desc(n.Description))),
			fmt.Sprintf("set %s source address %s", base, q(normAddr(n.Source))),
			fmt.Sprintf("set %s translation address %s", base, q(normAddr(n.Translation)))}
		if opt.OutboundInterface != "" {
			cmds = append(cmds, fmt.Sprintf("set %s outbound-interface name %s", base, q(opt.OutboundInterface)))
		} else {
			t.Warnings = append(t.Warnings, fmt.Sprintf("nat source rule %d has no outbound interface (not in the intent): set TranslateOpts.OutboundInterface", n.Rule))
		}
		t.Policy.Ops = append(t.Policy.Ops, MakeOp("nat.upsert", base, base, cmds...))
		raise(n.Risk)
	}

	for _, r := range in.Firewall {
		src, skip, w, err := oneAddr(r.Source, "source", r.Rule)
		if err != nil {
			return nil, err
		}
		if skip {
			t.Warnings = append(t.Warnings, w)
			continue
		}
		dst, skip, w, err := oneAddr(r.Destination, "destination", r.Rule)
		if err != nil {
			return nil, err
		}
		if skip {
			t.Warnings = append(t.Warnings, w)
			continue
		}
		services := r.Services
		if len(services) == 0 {
			services = []render.ServiceSpec{{}} // any protocol
		}
		if len(services) > 9 {
			return nil, fmt.Errorf("vyos: rule %d has %d services; at most 9 fit in the rule number gap", r.Rule, len(services))
		}
		for i, s := range services {
			num := r.Rule + i
			base := fmt.Sprintf("firewall ipv4 forward filter rule %d", num)
			cmds := []string{"delete " + base,
				fmt.Sprintf("set %s description %s", base, q(desc(r.Description))),
				fmt.Sprintf("set %s action %s", base, q(r.Action))}
			if src != "" {
				cmds = append(cmds, fmt.Sprintf("set %s source address %s", base, q(src)))
			}
			if dst != "" {
				cmds = append(cmds, fmt.Sprintf("set %s destination address %s", base, q(dst)))
			}
			switch s.Proto {
			case "", "any":
			case "tcp", "udp", "icmp":
				cmds = append(cmds, fmt.Sprintf("set %s protocol %s", base, q(s.Proto)))
				if ps := portSpec(s); ps != "" && s.Proto != "icmp" {
					cmds = append(cmds, fmt.Sprintf("set %s destination port %s", base, q(ps)))
				}
			default:
				return nil, fmt.Errorf("vyos: rule %d: unsupported protocol %q", r.Rule, s.Proto)
			}
			t.Policy.Ops = append(t.Policy.Ops, MakeOp("rule.upsert", base, base, cmds...))
		}
		raise(r.Risk)
	}

	if in.Mgmt != nil {
		var allowed []string
		for _, e := range in.Mgmt.PermittedFrom {
			if e.Value == "" {
				t.Warnings = append(t.Warnings, "mgmt access: permitted-from address for "+e.Host+" is unresolved; lockdown not generated")
				allowed = nil
				break
			}
			allowed = append(allowed, normAddr(e.Value))
		}
		if len(allowed) > 0 && len(in.Mgmt.Ports) > 0 {
			var ports []string
			for _, p := range in.Mgmt.Ports {
				ports = append(ports, strconv.Itoa(int(p)))
			}
			sort.Strings(ports)
			plist := strings.Join(ports, ",")
			// Allow rules first, one drop for everyone else last. Added in one commit
			// under the dead-man; a fresh connection proves the controller still gets in.
			for i, ad := range allowed {
				base := fmt.Sprintf("firewall ipv4 input filter rule %d", 5+i)
				t.Mgmt.Ops = append(t.Mgmt.Ops, MakeOp("mgmt.permit", base, base,
					"delete "+base,
					fmt.Sprintf("set %s description %s", base, q(ManagedTag+": management from the controller")),
					fmt.Sprintf("set %s action 'accept'", base),
					fmt.Sprintf("set %s protocol 'tcp'", base),
					fmt.Sprintf("set %s destination port %s", base, q(plist)),
					fmt.Sprintf("set %s source address %s", base, q(ad))))
				if strings.Contains(plist, "443") {
					t.Mgmt.Ops = append(t.Mgmt.Ops, MakeOp("mgmt.permit", "https-allow-"+ad, "", fmt.Sprintf("set service https allow-client address %s", q(ad))))
				}
			}
			drop := "firewall ipv4 input filter rule 900"
			t.Mgmt.Ops = append(t.Mgmt.Ops, MakeOp("mgmt.permit", drop, drop,
				"delete "+drop,
				fmt.Sprintf("set %s description %s", drop, q(ManagedTag+": management denied to everyone else")),
				fmt.Sprintf("set %s action 'drop'", drop),
				fmt.Sprintf("set %s protocol 'tcp'", drop),
				fmt.Sprintf("set %s destination port %s", drop, q(plist))))
		}
	}
	return t, nil
}
