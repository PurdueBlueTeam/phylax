package chains

import (
	"fmt"
	"sort"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/traceback"
)

// Campaign is a set of chains that share a source address, an account, a
// binary hash or a C2 destination: one IR per campaign.
type Campaign struct {
	ID     int64
	Name   string
	Chains []*Chain
	Keys   Keys
	First  time.Time
	Last   time.Time
}

// ChainKeys returns the grouping keys of a chain. Sources are the outside
// addresses of access hops (internal pivot addresses are not keys, or two
// unrelated attackers pivoting through one host would merge); accounts exclude
// the ignored set; C2 is the destination of egress hops.
func ChainKeys(c *Chain, cfg Config) Keys {
	cfg = cfg.withDefaults()
	set := [4]map[string]bool{{}, {}, {}, {}}
	for _, h := range c.Hops {
		if h.Kind == Access && h.SrcAddr != "" && !traceback.IsLoopback(h.SrcAddr) && !cfg.ours(h.SrcAddr) {
			set[0][h.SrcAddr] = true
		}
		if !cfg.ignored(h.Account) {
			set[1][h.Account] = true
		}
		if h.Proc != nil && h.Proc.SHA256 != "" {
			set[2][h.Proc.SHA256] = true
		}
		if h.Kind == Egress && h.DstAddr != "" {
			set[3][h.DstAddr] = true
		}
	}
	list := func(m map[string]bool) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	return Keys{Sources: list(set[0]), Accounts: list(set[1]), Hashes: list(set[2]), C2: list(set[3])}
}

func (c *Chain) span() (time.Time, time.Time) {
	var a, b time.Time
	for _, h := range c.Hops {
		if a.IsZero() || h.Start.Before(a) {
			a = h.Start
		}
		if h.End.After(b) {
			b = h.End
		}
	}
	return a, b
}

// Group merges chains that share a key into campaigns, ordered by first
// activity.
func Group(chains []*Chain, cfg Config) []*Campaign {
	parent := make([]int, len(chains))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	keys := make([]Keys, len(chains))
	owner := map[string]int{}
	for i, c := range chains {
		keys[i] = ChainKeys(c, cfg)
		for typ, vals := range [][]string{keys[i].Sources, keys[i].Accounts, keys[i].Hashes, keys[i].C2} {
			for _, v := range vals {
				k := fmt.Sprintf("%d|%s", typ, v)
				if j, ok := owner[k]; ok {
					parent[find(i)] = find(j)
				} else {
					owner[k] = i
				}
			}
		}
	}
	byRoot := map[int]*Campaign{}
	var order []int
	for i, c := range chains {
		r := find(i)
		cp := byRoot[r]
		if cp == nil {
			cp = &Campaign{}
			byRoot[r] = cp
			order = append(order, r)
		}
		cp.Chains = append(cp.Chains, c)
		a, b := c.span()
		if cp.First.IsZero() || (!a.IsZero() && a.Before(cp.First)) {
			cp.First = a
		}
		if b.After(cp.Last) {
			cp.Last = b
		}
		cp.Keys = mergeKeys(cp.Keys, keys[i])
		if cp.ID == 0 || (c.CampaignID != 0 && c.CampaignID < cp.ID) {
			cp.ID = c.CampaignID
		}
	}
	var out []*Campaign
	for _, r := range order {
		cp := byRoot[r]
		cp.Name = campaignName(cp)
		out = append(out, cp)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].First.Before(out[j].First) })
	return out
}

func mergeKeys(a, b Keys) Keys {
	u := func(x, y []string) []string {
		m := map[string]bool{}
		for _, s := range append(append([]string(nil), x...), y...) {
			m[s] = true
		}
		var out []string
		for s := range m {
			out = append(out, s)
		}
		sort.Strings(out)
		return out
	}
	return Keys{u(a.Sources, b.Sources), u(a.Accounts, b.Accounts), u(a.Hashes, b.Hashes), u(a.C2, b.C2)}
}

func campaignName(c *Campaign) string {
	var parts []string
	if len(c.Keys.Sources) > 0 {
		parts = append(parts, c.Keys.Sources[0])
	}
	if len(c.Keys.Accounts) > 0 {
		parts = append(parts, c.Keys.Accounts[len(c.Keys.Accounts)-1])
	}
	if len(parts) == 0 && len(c.Keys.Hashes) > 0 {
		h := c.Keys.Hashes[0]
		if len(h) > 12 {
			h = h[:12]
		}
		parts = append(parts, "sha256:"+h)
	}
	if len(parts) == 0 && len(c.Keys.C2) > 0 {
		parts = append(parts, c.Keys.C2[0])
	}
	name := "campaign"
	for _, p := range parts {
		name += " " + p
	}
	if len(c.Chains) > 1 {
		name += fmt.Sprintf(" (%d chains)", len(c.Chains))
	}
	return name
}
