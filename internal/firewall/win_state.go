package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
)

// This file is the platform-independent half of the Windows Firewall support:
// the state model, the translation from render.WinPolicy, normalization of the
// strings Windows hands back, and diffing. It has no COM and no build tag, so
// it is unit tested on Linux.

// WinMgmtGroup is the Windows rule group holding the management rules.
const WinMgmtGroup = "Phylax Mgmt"

// winOwnedGroups are the rule groups this package owns. render defines the
// names; any rule outside them is foreign and never modified.
var winOwnedGroups = map[string]bool{
	"Phylax Base": true, WinMgmtGroup: true, "Phylax Service": true,
	"Phylax Dependency": true, "Phylax Decoy": true, "Phylax Egress": true, "Phylax Canary": true,
}

// WinOwnedGroup reports whether a rule group is one of ours.
func WinOwnedGroup(g string) bool { return winOwnedGroups[g] }

// WinProfileNames are the three firewall profiles.
var WinProfileNames = []string{"Domain", "Private", "Public"}

// WinProfileState is the state of one profile.
type WinProfileState struct {
	Name            string `json:"name"` // Domain | Private | Public
	Enabled         bool   `json:"enabled"`
	DefaultInbound  string `json:"default_inbound"`  // Block | Allow
	DefaultOutbound string `json:"default_outbound"` // Block | Allow
}

// WinRuleState is one rule in canonical form (what Windows reports and what we
// compare). Ports and addresses are normalized by NormPorts / NormAddrs.
type WinRuleState struct {
	Name            string `json:"name"`
	Description     string `json:"description,omitempty"`
	Group           string `json:"group"`
	Direction       string `json:"direction"` // Inbound | Outbound
	Action          string `json:"action"`    // Allow | Block
	Protocol        string `json:"protocol"`  // TCP | UDP | ICMPv4 | ICMPv6 | Any
	LocalPorts      string `json:"local_ports,omitempty"`
	RemotePorts     string `json:"remote_ports,omitempty"`
	RemoteAddresses string `json:"remote_addresses,omitempty"`
	ICMPTypes       string `json:"icmp_types,omitempty"`
	Profiles        string `json:"profiles"` // Any (all profiles)
	Enabled         bool   `json:"enabled"`
}

// WinState is a complete Windows Firewall intent or observation: the profiles
// and the rules of our groups.
type WinState struct {
	Profiles []WinProfileState `json:"profiles"`
	Rules    []WinRuleState    `json:"rules"`
}

// WinTranslateOptions tunes TranslateWindows.
type WinTranslateOptions struct {
	Mode              Mode
	AllowNoManagement bool
}

// TranslateWindows converts the rendered WinPolicy to the desired state: every
// profile enabled with the policy's default actions, and the policy's rules.
func TranslateWindows(wp *render.WinPolicy, opt WinTranslateOptions) (*WinState, error) {
	if opt.Mode == ModeShadow {
		return nil, ErrShadowUnsupported
	}
	for _, d := range []string{wp.DefaultInbound, wp.DefaultOutbound} {
		if d != "Block" && d != "Allow" {
			return nil, fmt.Errorf("firewall: bad default action %q", d)
		}
	}
	st := &WinState{}
	for _, p := range WinProfileNames {
		st.Profiles = append(st.Profiles, WinProfileState{Name: p, Enabled: true, DefaultInbound: wp.DefaultInbound, DefaultOutbound: wp.DefaultOutbound})
	}
	seen := map[string]bool{}
	mgmt := false
	for _, r := range wp.Rules {
		if r.Name == "" || len(r.Name) > 255 {
			return nil, fmt.Errorf("firewall: rule name %q empty or too long", r.Name)
		}
		if seen[r.Name] {
			return nil, fmt.Errorf("firewall: duplicate rule name %q", r.Name)
		}
		seen[r.Name] = true
		if !WinOwnedGroup(r.Group) {
			return nil, fmt.Errorf("firewall: rule %q is in group %q, which is not a Phylax group", r.Name, r.Group)
		}
		if r.Group == WinMgmtGroup && r.Action == "Allow" && r.Enabled {
			mgmt = true
		}
		rs := WinRuleState{
			Name: r.Name, Description: r.Description, Group: r.Group,
			Direction: r.Direction, Action: r.Action, Protocol: r.Protocol,
			LocalPorts: NormPorts(joinPorts(r.LocalPorts)), RemotePorts: NormPorts(joinPorts(r.RemotePorts)),
			ICMPTypes: r.ICMPTypes, Profiles: "Any", Enabled: r.Enabled,
		}
		if r.Profiles != "" && r.Profiles != "Any" {
			return nil, fmt.Errorf("firewall: rule %q: profiles %q not supported (only Any)", r.Name, r.Profiles)
		}
		if rs.Direction != "Inbound" && rs.Direction != "Outbound" {
			return nil, fmt.Errorf("firewall: rule %q: bad direction %q", r.Name, rs.Direction)
		}
		if rs.Action != "Allow" && rs.Action != "Block" {
			return nil, fmt.Errorf("firewall: rule %q: bad action %q", r.Name, rs.Action)
		}
		switch rs.Protocol {
		case "TCP", "UDP":
		case "ICMPv4", "ICMPv6", "Any":
			if rs.LocalPorts != "" || rs.RemotePorts != "" {
				return nil, fmt.Errorf("firewall: rule %q: ports on protocol %s", r.Name, rs.Protocol)
			}
		default:
			return nil, fmt.Errorf("firewall: rule %q: bad protocol %q", r.Name, rs.Protocol)
		}
		if rs.ICMPTypes != "" && rs.Protocol != "ICMPv4" && rs.Protocol != "ICMPv6" {
			return nil, fmt.Errorf("firewall: rule %q: ICMP types on protocol %s", r.Name, rs.Protocol)
		}
		addrs, err := NormAddrs(strings.Join(r.RemoteAddress, ","))
		if err != nil {
			return nil, fmt.Errorf("firewall: rule %q: %w", r.Name, err)
		}
		rs.RemoteAddresses = addrs
		st.Rules = append(st.Rules, rs)
	}
	if (wp.DefaultInbound == "Block" || wp.DefaultOutbound == "Block") && !mgmt && !opt.AllowNoManagement {
		return nil, ErrNoManagement
	}
	st.normalize()
	return st, nil
}

func joinPorts(p []uint16) string {
	s := make([]string, len(p))
	for i, v := range p {
		s[i] = strconv.Itoa(int(v))
	}
	return strings.Join(s, ",")
}

// NormPorts canonicalizes a Windows port list: "" and "*" mean any; otherwise
// numbers and ranges, sorted and de-duplicated.
func NormPorts(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return ""
	}
	type pr struct{ lo, hi int }
	var ps []pr
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		lo, hi, isRange := strings.Cut(tok, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return strings.ToLower(s) // keywords (RPC, IPHTTPS, ...): keep as is
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil {
				return strings.ToLower(s)
			}
		}
		ps = append(ps, pr{a, b})
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].lo < ps[j].lo || ps[i].lo == ps[j].lo && ps[i].hi < ps[j].hi })
	var out []string
	prev := pr{-1, -1}
	for _, p := range ps {
		if p == prev {
			continue
		}
		prev = p
		if p.lo == p.hi {
			out = append(out, strconv.Itoa(p.lo))
		} else {
			out = append(out, fmt.Sprintf("%d-%d", p.lo, p.hi))
		}
	}
	return strings.Join(out, ",")
}

// NormAddrs canonicalizes a Windows address list. Windows reports subnets as
// "10.0.0.0/255.255.255.0" and hosts without a prefix; we write prefixes. Both
// become "10.0.0.0/24" / "10.0.0.5/32". "" and "*" mean any. Ranges
// ("a-b") and keywords (LocalSubnet, DNS, ...) are kept, lower-cased.
func NormAddrs(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" || strings.EqualFold(s, "any") {
		return "", nil
	}
	var out []string
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if a, b, ok := strings.Cut(tok, "-"); ok && !strings.Contains(tok, "/") {
			x, e1 := netip.ParseAddr(strings.TrimSpace(a))
			y, e2 := netip.ParseAddr(strings.TrimSpace(b))
			if e1 != nil || e2 != nil {
				return "", fmt.Errorf("bad address range %q", tok)
			}
			out = append(out, x.String()+"-"+y.String())
			continue
		}
		addr, mask, hasMask := strings.Cut(tok, "/")
		ip, err := netip.ParseAddr(addr)
		if err != nil {
			if hasMask {
				return "", fmt.Errorf("bad address %q", tok)
			}
			out = append(out, strings.ToLower(tok)) // keyword
			continue
		}
		bits := ip.BitLen()
		if hasMask {
			if n, err := strconv.Atoi(mask); err == nil {
				bits = n
			} else if m, err := netip.ParseAddr(mask); err == nil && m.Is4() {
				bits = 0
				for _, by := range m.AsSlice() {
					for by&0x80 != 0 {
						bits++
						by <<= 1
					}
				}
			} else {
				return "", fmt.Errorf("bad mask in %q", tok)
			}
		}
		p, err := ip.Prefix(bits)
		if err != nil {
			return "", fmt.Errorf("bad prefix %q", tok)
		}
		out = append(out, p.String())
	}
	sort.Strings(out)
	return strings.Join(out, ","), nil
}

// ComAddr renders a normalized address list the way Windows is happiest to
// receive it: bare IPs for hosts, prefix notation otherwise.
func ComAddr(norm string) string {
	if norm == "" {
		return "*"
	}
	toks := strings.Split(norm, ",")
	for i, t := range toks {
		if p, err := netip.ParsePrefix(t); err == nil && p.Bits() == p.Addr().BitLen() {
			toks[i] = p.Addr().String()
		}
	}
	return strings.Join(toks, ",")
}

func (st *WinState) normalize() {
	sort.Slice(st.Profiles, func(i, j int) bool { return st.Profiles[i].Name < st.Profiles[j].Name })
	sort.Slice(st.Rules, func(i, j int) bool { return st.Rules[i].Name < st.Rules[j].Name })
}

// Hash is a stable digest of the state (the "ruleset hash" D10 audits).
func (st *WinState) Hash() string {
	c := *st
	c.Profiles = append([]WinProfileState(nil), st.Profiles...)
	c.Rules = append([]WinRuleState(nil), st.Rules...)
	c.normalize()
	b, _ := json.Marshal(&c)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// DiffWinStates lists the differences between want and got. Description is
// informational and not compared.
func DiffWinStates(want, got *WinState) []string {
	var d []string
	gp := map[string]WinProfileState{}
	for _, p := range got.Profiles {
		gp[p.Name] = p
	}
	for _, p := range want.Profiles {
		o, ok := gp[p.Name]
		switch {
		case !ok:
			d = append(d, "profile "+p.Name+": missing")
		case o != p:
			d = append(d, fmt.Sprintf("profile %s: found %+v, declared %+v", p.Name, o, p))
		}
	}
	gr := map[string]WinRuleState{}
	for _, r := range got.Rules {
		gr[r.Name] = r
	}
	wr := map[string]bool{}
	for _, r := range want.Rules {
		wr[r.Name] = true
		o, ok := gr[r.Name]
		if !ok {
			d = append(d, "rule "+strconvQ(r.Name)+": missing")
			continue
		}
		a, b := r, o
		a.Description, b.Description = "", ""
		if a != b {
			d = append(d, fmt.Sprintf("rule %s: found %+v, declared %+v", strconvQ(r.Name), o, r))
		}
	}
	for _, r := range got.Rules {
		if !wr[r.Name] {
			d = append(d, "rule "+strconvQ(r.Name)+": present in a Phylax group but not declared")
		}
	}
	sort.Strings(d)
	return d
}

func strconvQ(s string) string { return strconv.Quote(s) }

func jsonIndent(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", " ")
	return append(b, '\n'), err
}
