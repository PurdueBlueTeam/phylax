// Package firewall models the declared host firewall policy that the
// manifest renders into, and which fw.apply installs on each host.
//
// Rule hygiene (design doc § Rule hygiene and bring-up): management rules
// (agent, relay and device-proxy links) live in their own group, separate
// from service rules, decoy rules and inject changes. On Linux the groups
// are chains of one nftables table; drift detection and restore treat each
// group separately.
package firewall

// Mode is the enforcement state of the rendered policy.
type Mode string

const (
	// Enforce drops everything not explicitly accepted.
	Enforce Mode = "enforce"
	// Shadow logs would-be drops instead of dropping them (Linux only;
	// Windows shadow mode evaluates locally and installs nothing).
	Shadow Mode = "shadow"
)

// Verdict is what a rule does to matching packets.
type Verdict string

const (
	Accept        Verdict = "accept"
	Drop          Verdict = "drop"
	Log           Verdict = "log"            // shadow: log prefix, no drop
	NFLogDrop     Verdict = "nflog"          // nflog group + drop (denied egress)
	NFLogRedirect Verdict = "nflog-redirect" // nflog group + redirect (sinkhole)
	Redirect      Verdict = "redirect"       // to Rule.Redirect
)

// Rule is one nftables rule. All fields optional; empty = wildcard.
type Rule struct {
	Comment   string // phylax tag, e.g. "phylax:svc:ecom-http"
	Proto     string // tcp, udp, "" = any
	Src       []string
	Dst       []string
	DPorts    []int
	CT        []string // established, related
	Iif       string
	Oif       string
	Verdict   Verdict
	Redirect  string // addr:port for Redirect verdicts
	LogGroup  int    // nflog group for NFLog* verdicts
	LogPrefix string // prefix for Log/NFLog* verdicts
}

// Chain is a named nftables chain (one policy group).
type Chain struct {
	Name     string
	Hook     string // input, output
	Priority int
	Rules    []Rule
}

// HostPolicy is the full declared policy for one host.
type HostPolicy struct {
	Host   string
	Mode   Mode
	Table  string // nftables table name
	Chains []Chain
}

// SinkholeCatcher is the loopback address:port of the agent's sinkhole
// catcher, for redirect rules.
type SinkholeCatcher struct {
	Addr string
	Port int
}
