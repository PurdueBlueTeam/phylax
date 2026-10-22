package manifest

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// PortRange is an inclusive TCP/UDP port range. In YAML it is written as the
// string "lo-hi" (or a single port "n"); in rendered JSON it is the same string.
type PortRange struct{ Lo, Hi uint16 }

// ParsePortRange parses "lo-hi" or "n".
func ParsePortRange(s string) (PortRange, error) {
	s = strings.TrimSpace(s)
	lo, hi, isRange := strings.Cut(s, "-")
	l, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	if err != nil || l == 0 {
		return PortRange{}, fmt.Errorf("port range %q: want \"lo-hi\" with ports 1-65535", s)
	}
	h := l
	if isRange {
		h, err = strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
		if err != nil || h == 0 {
			return PortRange{}, fmt.Errorf("port range %q: want \"lo-hi\" with ports 1-65535", s)
		}
	}
	if h < l {
		return PortRange{}, fmt.Errorf("port range %q: low port is above high port", s)
	}
	return PortRange{uint16(l), uint16(h)}, nil
}

// MustPortRanges parses already validated input; invalid entries are skipped.
func MustPortRanges(ss []string) []PortRange {
	var out []PortRange
	for _, s := range ss {
		if r, err := ParsePortRange(s); err == nil {
			out = append(out, r)
		}
	}
	return out
}

func (r PortRange) String() string {
	if r.Lo == r.Hi {
		return strconv.Itoa(int(r.Lo))
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}

// MarshalText renders "lo-hi" (used for JSON).
func (r PortRange) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

// UnmarshalText parses "lo-hi".
func (r *PortRange) UnmarshalText(b []byte) error {
	v, err := ParsePortRange(string(b))
	if err != nil {
		return err
	}
	*r = v
	return nil
}

// Contains reports whether the port is in the range.
func (r PortRange) Contains(p uint16) bool { return p >= r.Lo && p <= r.Hi }

// ContainsRange reports whether o lies entirely inside r.
func (r PortRange) ContainsRange(o PortRange) bool { return o.Lo >= r.Lo && o.Hi <= r.Hi }

// Overlaps reports whether the ranges share a port.
func (r PortRange) Overlaps(o PortRange) bool { return r.Lo <= o.Hi && o.Lo <= r.Hi }

// SortRanges returns the ranges sorted and de-duplicated.
func SortRanges(rs []PortRange) []PortRange {
	out := append([]PortRange(nil), rs...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Lo != out[j].Lo {
			return out[i].Lo < out[j].Lo
		}
		return out[i].Hi < out[j].Hi
	})
	w := 0
	for i, r := range out {
		if i > 0 && r == out[w-1] {
			continue
		}
		out[w] = r
		w++
	}
	return out[:w]
}

// Ports is a set of single ports and ranges.
type Ports struct {
	Ports  []uint16
	Ranges []PortRange
}

// Has reports whether the port is in the set.
func (p Ports) Has(x uint16) bool {
	for _, v := range p.Ports {
		if v == x {
			return true
		}
	}
	for _, r := range p.Ranges {
		if r.Contains(x) {
			return true
		}
	}
	return false
}

// Covers reports whether every wanted port and range lies in the set.
func (p Ports) Covers(want Ports) bool {
	for _, x := range want.Ports {
		if !p.Has(x) {
			return false
		}
	}
	for _, w := range want.Ranges {
		ok := false
		for _, r := range p.Ranges {
			if r.ContainsRange(w) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// Overlaps reports whether the sets share a port.
func (p Ports) Overlaps(o Ports) bool {
	for _, x := range o.Ports {
		if p.Has(x) {
			return true
		}
	}
	for _, w := range o.Ranges {
		for _, x := range p.Ports {
			if w.Contains(x) {
				return true
			}
		}
		for _, r := range p.Ranges {
			if r.Overlaps(w) {
				return true
			}
		}
	}
	return false
}

// DefaultRPCRange is the Windows dynamic RPC port range (Vista and later).
var DefaultRPCRange = PortRange{49152, 65535}

// DomainAllowance is one protocol's worth of domain-member to DC traffic.
type DomainAllowance struct {
	Proto   string
	Ports   []uint16
	Ranges  []PortRange
	Comment string
}

// DomainAllowances is the complete set of member-to-DC allowances: DNS 53,
// Kerberos 88 and kpasswd 464, LDAP 389 (CLDAP over udp) and LDAPS 636, global
// catalog 3268/3269, SMB 445 (SYSVOL/NETLOGON, GPO), the RPC endpoint mapper
// 135 plus the DC's dynamic RPC range (pinned when the DC declares rpc_range),
// and NTP 123/udp.
func (m *Manifest) DomainAllowances(dc string) []DomainAllowance {
	rpc := DefaultRPCRange
	if s := m.Hosts[dc].RPCRange; s != "" {
		if r, err := ParsePortRange(s); err == nil {
			rpc = r
		}
	}
	return []DomainAllowance{
		{Proto: "tcp", Ports: []uint16{53, 88, 135, 389, 445, 464, 636, 3268, 3269}, Ranges: []PortRange{rpc},
			Comment: "AD tcp: DNS, Kerberos, LDAP(S), GC, SMB, RPC 135 + dynamic range"},
		{Proto: "udp", Ports: []uint16{53, 88, 123, 389, 464},
			Comment: "AD udp: DNS, Kerberos, NTP, CLDAP"},
	}
}

// DomainMembers returns the hosts that declare dc as their domain controller, sorted.
func (m *Manifest) DomainMembers(dc string) []string {
	var out []string
	for n, h := range m.Hosts {
		if h.DomainMember == dc {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func (p Ports) String() string {
	var parts []string
	for _, x := range p.Ports {
		parts = append(parts, strconv.Itoa(int(x)))
	}
	for _, r := range p.Ranges {
		parts = append(parts, r.String())
	}
	return "[" + strings.Join(parts, " ") + "]"
}
