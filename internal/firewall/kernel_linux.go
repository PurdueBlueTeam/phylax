//go:build linux

package firewall

import (
	"fmt"
	"slices"
	"sort"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// ForeignTable describes a table we do not own: another firewall (ufw,
// firewalld, docker, Kubernetes) or a red-team rule set. It is only ever read.
type ForeignTable struct {
	Name   string         `json:"name"`
	Family uint8          `json:"family"`
	Chains []ForeignChain `json:"chains"`
	// Hooked: at least one chain is attached to a netfilter hook.
	Hooked bool `json:"hooked"`
	// MayBlock: a hooked chain has a drop policy or a drop/reject rule, so it
	// can affect traffic our policy accepts.
	MayBlock bool `json:"may_block"`
	// ShadowsOurName: the table has one of our names in another family.
	ShadowsOurName bool `json:"shadows_our_name,omitempty"`
}

// ForeignChain summarizes one chain of a foreign table.
type ForeignChain struct {
	Name     string `json:"name"`
	Hooked   bool   `json:"hooked"`
	Hook     uint32 `json:"hook,omitempty"`
	Priority int32  `json:"priority,omitempty"`
	Policy   string `json:"policy,omitempty"`
	Rules    int    `json:"rules"`
	Blocks   bool   `json:"blocks,omitempty"`
}

func policyName(p *nftables.ChainPolicy) string {
	if p == nil {
		return ""
	}
	if *p == nftables.ChainPolicyDrop {
		return "drop"
	}
	return "accept"
}

// readKernel reads the owned tables (as a Ruleset) and summarizes every other
// table. It does not modify anything.
func readKernel(c *nftables.Conn) (*Ruleset, []ForeignTable, error) {
	tables, err := c.ListTables()
	if err != nil {
		return nil, nil, fmt.Errorf("firewall: list tables: %w", err)
	}
	chains, err := c.ListChains()
	if err != nil {
		return nil, nil, fmt.Errorf("firewall: list chains: %w", err)
	}
	owned := &Ruleset{}
	var foreign []ForeignTable
	for _, t := range tables {
		if isOwned(t.Name) && uint8(t.Family) == famINet {
			ts, err := readOwnedTable(c, t, chains)
			if err != nil {
				return nil, nil, err
			}
			owned.Tables = append(owned.Tables, ts)
			continue
		}
		ft := ForeignTable{Name: t.Name, Family: uint8(t.Family), ShadowsOurName: isOwned(t.Name)}
		for _, ch := range chains {
			if ch.Table == nil || ch.Table.Name != t.Name || ch.Table.Family != t.Family {
				continue
			}
			fc := ForeignChain{Name: ch.Name, Policy: policyName(ch.Policy)}
			if ch.Hooknum != nil && ch.Priority != nil {
				fc.Hooked, fc.Hook, fc.Priority = true, uint32(*ch.Hooknum), int32(*ch.Priority)
			}
			rules, err := c.GetRules(t, ch)
			if err != nil {
				return nil, nil, fmt.Errorf("firewall: read foreign table %s: %w", t.Name, err)
			}
			fc.Rules = len(rules)
			if fc.Hooked && ch.Policy != nil && *ch.Policy == nftables.ChainPolicyDrop {
				fc.Blocks = true
			}
			for _, r := range rules {
				for _, e := range r.Exprs {
					if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictDrop {
						fc.Blocks = fc.Blocks || fc.Hooked
					}
					if _, ok := e.(*expr.Reject); ok {
						fc.Blocks = fc.Blocks || fc.Hooked
					}
				}
			}
			ft.Hooked = ft.Hooked || fc.Hooked
			ft.MayBlock = ft.MayBlock || fc.Blocks
			ft.Chains = append(ft.Chains, fc)
		}
		sort.Slice(ft.Chains, func(i, j int) bool { return ft.Chains[i].Name < ft.Chains[j].Name })
		foreign = append(foreign, ft)
	}
	sort.Slice(foreign, func(i, j int) bool {
		if foreign[i].Name != foreign[j].Name {
			return foreign[i].Name < foreign[j].Name
		}
		return foreign[i].Family < foreign[j].Family
	})
	return owned.normalized(), foreign, nil
}

func readOwnedTable(c *nftables.Conn, t *nftables.Table, chains []*nftables.Chain) (*TableSpec, error) {
	ts := &TableSpec{Name: t.Name, Family: uint8(t.Family)}
	for _, ch := range chains {
		if ch.Table == nil || ch.Table.Name != t.Name || ch.Table.Family != t.Family {
			continue
		}
		cs := &ChainSpec{Name: ch.Name, Type: string(ch.Type)}
		if ch.Hooknum != nil {
			h := uint32(*ch.Hooknum)
			cs.Hook = &h
		}
		if ch.Priority != nil {
			p := int32(*ch.Priority)
			cs.Priority = &p
		}
		if ch.Policy != nil {
			p := uint32(*ch.Policy)
			cs.Policy = &p
		}
		rules, err := c.GetRules(t, ch)
		if err != nil {
			return nil, fmt.Errorf("firewall: read rules of %s/%s: %w", t.Name, ch.Name, err)
		}
		for _, r := range rules {
			rs := &RuleSpec{UserData: r.UserData}
			for _, e := range r.Exprs {
				if _, ok := exprTypes[exprName(e)]; !ok {
					rs.Lossy = "unsupported expression " + exprName(e)
					rs.Exprs = nil
					break
				}
				rs.Exprs = append(rs.Exprs, Expr{e})
			}
			repairCtStores(rs.Exprs)
			cs.Rules = append(cs.Rules, rs)
		}
		ts.Chains = append(ts.Chains, cs)
	}
	sets, err := c.GetSets(t)
	if err != nil {
		return nil, fmt.Errorf("firewall: read sets of %s: %w", t.Name, err)
	}
	for _, s := range sets {
		if s.Anonymous {
			continue
		}
		ss := &SetSpec{Name: s.Name, KeyName: s.KeyType.Name, KeyBytes: s.KeyType.Bytes, KeyMagic: s.KeyType.GetNFTMagic(), Interval: s.Interval}
		els, err := c.GetSetElements(s)
		if err != nil {
			return nil, fmt.Errorf("firewall: read set %s/%s: %w", t.Name, s.Name, err)
		}
		for _, el := range els {
			ss.Elems = append(ss.Elems, SetElem{Key: slices.Clone(el.Key), End: el.IntervalEnd})
		}
		ts.Sets = append(ts.Sets, ss)
	}
	return ts, nil
}

// replaceOwned queues, on c, an atomic replacement of our tables: every
// desired table is declared, deleted and redefined (so the kernel swaps it in
// one transaction and an absent table is not an error), and owned tables that
// are not desired are removed. Nothing else is touched. The caller flushes.
func replaceOwned(c *nftables.Conn, desired *Ruleset) (skipped []string, err error) {
	want := map[string]bool{}
	for _, t := range desired.Tables {
		if !isOwned(t.Name) {
			return nil, fmt.Errorf("firewall: refusing to write table %q: not one of ours", t.Name)
		}
		want[t.Name] = true
	}
	for _, name := range ownedTables {
		if want[name] {
			continue
		}
		t := &nftables.Table{Name: name, Family: nftables.TableFamilyINet}
		c.AddTable(t) // make the delete succeed when absent
		c.DelTable(t)
	}
	for _, ts := range desired.Tables {
		t := &nftables.Table{Name: ts.Name, Family: nftables.TableFamily(ts.Family)}
		c.AddTable(t)
		c.DelTable(t)
		c.AddTable(t)
		sets := map[string]*nftables.Set{}
		for _, ss := range ts.Sets {
			s := &nftables.Set{Table: t, Name: ss.Name, Interval: ss.Interval, KeyType: nftables.SetDatatype{Name: ss.KeyName, Bytes: ss.KeyBytes}}
			s.KeyType.SetNFTMagic(ss.KeyMagic)
			var els []nftables.SetElement
			for _, e := range ss.Elems {
				els = append(els, nftables.SetElement{Key: slices.Clone(e.Key), IntervalEnd: e.End})
			}
			if err := c.AddSet(s, els); err != nil {
				return nil, fmt.Errorf("firewall: set %s: %w", ss.Name, err)
			}
			sets[ss.Name] = s
		}
		for _, cs := range ts.Chains {
			ch := &nftables.Chain{Name: cs.Name, Table: t, Type: nftables.ChainType(cs.Type)}
			if cs.Hook != nil {
				h := nftables.ChainHook(*cs.Hook)
				ch.Hooknum = &h
			}
			if cs.Priority != nil {
				p := nftables.ChainPriority(*cs.Priority)
				ch.Priority = &p
			}
			if cs.Policy != nil {
				p := nftables.ChainPolicy(*cs.Policy)
				ch.Policy = &p
			}
			c.AddChain(ch)
			for i, rs := range cs.Rules {
				if !rs.supported() {
					skipped = append(skipped, fmt.Sprintf("%s/%s rule %d: %s", ts.Name, cs.Name, i, rs.Lossy))
					continue
				}
				r := &nftables.Rule{Table: t, Chain: ch, UserData: slices.Clone(rs.UserData)}
				for _, e := range rs.Exprs {
					if lk, ok := e.Any.(*expr.Lookup); ok {
						s := sets[lk.SetName]
						if s == nil {
							return nil, fmt.Errorf("firewall: rule %d of %s/%s uses undefined set %q", i, ts.Name, cs.Name, lk.SetName)
						}
						cp := *lk
						cp.SetID = s.ID
						r.Exprs = append(r.Exprs, &cp)
						continue
					}
					r.Exprs = append(r.Exprs, e.Any)
				}
				c.AddRule(r)
			}
		}
	}
	return skipped, nil
}

// repairCtStores works around github.com/google/nftables dropping the source
// register of `ct <key> set` when decoding a rule (its Ct decoder only reads
// NFTA_CT_DREG), which would turn the management-mark store into a load on
// restore. A load always has a destination register; a decoded Ct with none is
// a store, and its value is what the previous expression left in its
// destination register (nft and this package always emit load/modify/store).
func repairCtStores(es []Expr) {
	for i, e := range es {
		ct, ok := e.Any.(*expr.Ct)
		if !ok || ct.SourceRegister || ct.Register != 0 {
			continue
		}
		reg := uint32(1)
		if i > 0 {
			switch p := es[i-1].Any.(type) {
			case *expr.Bitwise:
				reg = p.DestRegister
			case *expr.Payload:
				reg = p.DestRegister
			case *expr.Immediate:
				reg = p.Register
			case *expr.Meta:
				if !p.SourceRegister {
					reg = p.Register
				}
			case *expr.Ct:
				if !p.SourceRegister {
					reg = p.Register
				}
			}
		}
		ct.SourceRegister, ct.Register = true, reg
	}
}
