package firewall

import (
	"fmt"
	"sort"
	"strings"
)

// RenderNFT renders a HostPolicy as an nftables script. The output is the
// reviewable golden artifact and the human-readable form of what fw.apply
// installs as netlink batches.
func (p *HostPolicy) RenderNFT() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# phylax firewall policy for %s (mode: %s)\n", p.Host, p.Mode)
	b.WriteString("# Generated from the manifest; do not hand-edit.\n")
	fmt.Fprintf(&b, "table inet %s {\n", p.Table)
	for _, ch := range p.Chains {
		fmt.Fprintf(&b, "    chain %s {\n", ch.Name)
		fmt.Fprintf(&b, "        type filter hook %s priority %d; policy drop;\n", ch.Hook, ch.Priority)
		for _, r := range ch.Rules {
			b.WriteString("        ")
			b.WriteString(r.render())
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "    }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func (r Rule) render() string {
	var parts []string
	if r.Iif != "" {
		parts = append(parts, fmt.Sprintf("iif %q", r.Iif))
	}
	if r.Oif != "" {
		parts = append(parts, fmt.Sprintf("oif %q", r.Oif))
	}
	if len(r.CT) > 0 {
		parts = append(parts, "ct state "+strings.Join(r.CT, ","))
	}
	if len(r.Src) > 0 {
		parts = append(parts, "ip saddr "+renderSet(r.Src))
	}
	if len(r.Dst) > 0 {
		parts = append(parts, "ip daddr "+renderSet(r.Dst))
	}
	if r.Proto != "" {
		parts = append(parts, "meta l4proto "+r.Proto)
	}
	if len(r.DPorts) > 0 {
		proto := r.Proto
		if proto == "" {
			proto = "tcp"
		}
		parts = append(parts, proto+" dport "+renderInts(r.DPorts))
	}
	switch r.Verdict {
	case Accept:
		parts = append(parts, "accept")
	case Drop:
		parts = append(parts, "drop")
	case Log:
		parts = append(parts, fmt.Sprintf("log prefix %q counter accept", r.LogPrefix))
	case NFLogDrop:
		parts = append(parts, fmt.Sprintf("log group %d prefix %q", r.LogGroup, r.LogPrefix), "drop")
	case NFLogRedirect:
		parts = append(parts, fmt.Sprintf("log group %d prefix %q", r.LogGroup, r.LogPrefix), "redirect to "+r.Redirect)
	case Redirect:
		parts = append(parts, "redirect to "+r.Redirect)
	}
	if r.Comment != "" {
		parts = append(parts, fmt.Sprintf("comment %q", r.Comment))
	}
	return strings.Join(parts, " ")
}

func renderSet(items []string) string {
	if len(items) == 1 {
		return items[0]
	}
	sorted := append([]string(nil), items...)
	sort.Strings(sorted)
	return "{" + strings.Join(sorted, ", ") + "}"
}

func renderInts(ports []int) string {
	if len(ports) == 1 {
		return fmt.Sprint(ports[0])
	}
	sorted := append([]int(nil), ports...)
	sort.Ints(sorted)
	parts := make([]string, len(sorted))
	for i, p := range sorted {
		parts[i] = fmt.Sprint(p)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
