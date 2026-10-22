package chains

import (
	"fmt"
	"strings"
)

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// describe fills the one-line text of a hop.
func describe(h *Hop) {
	acct := ""
	if h.Account != "" {
		acct = " as " + h.Account
	}
	svc := orStr(h.Service, "network")
	switch h.Kind {
	case Access:
		h.What = fmt.Sprintf("%s reaches %s via %s%s", orStr(h.SrcAddr, "unknown source"), h.DstHost, svc, acct)
	case Move:
		src := orStr(h.SrcHost, h.SrcAddr)
		h.What = fmt.Sprintf("lateral movement %s -> %s via %s%s", src, orStr(h.DstHost, h.DstAddr), svc, acct)
	case Exec:
		what := ""
		if h.Proc != nil {
			what = orStr(h.Proc.Cmdline, h.Proc.Exe)
		}
		h.What = fmt.Sprintf("%s runs %s%s", h.DstHost, trunc(what, 120), acct)
	case Change:
		h.What = fmt.Sprintf("%s: %s", h.DstHost, orStr(h.Path, "change"))
		if h.Persistence {
			h.What += " (persistence)"
		}
	case Egress:
		h.What = fmt.Sprintf("%s connects out to %s:%d", h.SrcHost, h.DstAddr, h.DstPort)
	}
	h.What = strings.TrimSpace(h.What)
}
