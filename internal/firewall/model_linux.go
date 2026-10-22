//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/google/nftables/expr"
)

// The model is a plain-data mirror of the nftables objects we own. It is what
// the translator produces, what a kernel read-back produces, what snapshots
// serialize, and what diffs compare.

// Ruleset is a set of tables.
type Ruleset struct {
	Tables []*TableSpec `json:"tables"`
}

// TableSpec is one nftables table with its chains and named sets.
type TableSpec struct {
	Name   string       `json:"name"`
	Family uint8        `json:"family"`
	Chains []*ChainSpec `json:"chains"`
	Sets   []*SetSpec   `json:"sets,omitempty"`
}

// ChainSpec is one chain. Hook, Priority, Policy and Type are set for base chains.
type ChainSpec struct {
	Name     string      `json:"name"`
	Type     string      `json:"type,omitempty"`
	Hook     *uint32     `json:"hook,omitempty"`
	Priority *int32      `json:"priority,omitempty"`
	Policy   *uint32     `json:"policy,omitempty"`
	Rules    []*RuleSpec `json:"rules"`
}

// RuleSpec is one rule: an expression list plus its userdata (the comment).
type RuleSpec struct {
	Exprs    []Expr `json:"exprs"`
	UserData []byte `json:"userdata,omitempty"`
	// Lossy is set on read-back when an expression could not be captured
	// (match/target extensions); such a rule cannot be restored.
	Lossy string `json:"lossy,omitempty"`
}

// SetSpec is a named set (ports or address prefixes).
type SetSpec struct {
	Name     string    `json:"name"`
	KeyName  string    `json:"key_name"`
	KeyBytes uint32    `json:"key_bytes"`
	KeyMagic uint32    `json:"key_magic"`
	Interval bool      `json:"interval,omitempty"`
	Elems    []SetElem `json:"elems"`
}

// SetElem is one set element; for interval sets End marks a range end.
type SetElem struct {
	Key []byte `json:"key"`
	End bool   `json:"end,omitempty"`
}

// Expr wraps an nftables expression so it can be serialized.
type Expr struct{ expr.Any }

// exprTypes lists every expression type that round-trips through JSON.
var exprTypes = func() map[string]reflect.Type {
	m := map[string]reflect.Type{}
	for _, e := range []expr.Any{
		&expr.Bitwise{}, &expr.Byteorder{}, &expr.Cmp{}, &expr.Counter{}, &expr.Ct{},
		&expr.Dup{}, &expr.Exthdr{}, &expr.Fib{}, &expr.Immediate{}, &expr.Limit{},
		&expr.Log{}, &expr.Lookup{}, &expr.Masq{}, &expr.Meta{}, &expr.NAT{},
		&expr.Notrack{}, &expr.Payload{}, &expr.Queue{}, &expr.Quota{}, &expr.Range{},
		&expr.Redir{}, &expr.Reject{}, &expr.Rt{}, &expr.Socket{}, &expr.Verdict{},
	} {
		m[exprName(e)] = reflect.TypeOf(e)
	}
	return m
}()

func exprName(e expr.Any) string {
	return strings.TrimPrefix(reflect.TypeOf(e).String(), "*expr.")
}

type exprJSON struct {
	T string          `json:"t"`
	D json.RawMessage `json:"d,omitempty"`
}

// MarshalJSON encodes the expression with its type name.
func (e Expr) MarshalJSON() ([]byte, error) {
	if e.Any == nil {
		return []byte("null"), nil
	}
	n := exprName(e.Any)
	if _, ok := exprTypes[n]; !ok {
		return json.Marshal(exprJSON{T: "unsupported:" + n})
	}
	d, err := json.Marshal(e.Any)
	if err != nil {
		return nil, err
	}
	return json.Marshal(exprJSON{T: n, D: d})
}

// UnmarshalJSON decodes an expression written by MarshalJSON.
func (e *Expr) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		e.Any = nil
		return nil
	}
	var j exprJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	t, ok := exprTypes[j.T]
	if !ok {
		return fmt.Errorf("firewall: unsupported expression %q in snapshot", j.T)
	}
	v := reflect.New(t.Elem())
	if err := json.Unmarshal(j.D, v.Interface()); err != nil {
		return err
	}
	e.Any = v.Interface().(expr.Any)
	return nil
}

// Supported reports whether every expression of the rule is restorable.
func (r *RuleSpec) supported() bool {
	if r.Lossy != "" {
		return false
	}
	for _, e := range r.Exprs {
		if e.Any == nil {
			return false
		}
		if _, ok := exprTypes[exprName(e.Any)]; !ok {
			return false
		}
	}
	return true
}

// Table returns the named table or nil.
func (rs *Ruleset) Table(name string) *TableSpec {
	for _, t := range rs.Tables {
		if t.Name == name {
			return t
		}
	}
	return nil
}

// normalized returns a deep, canonical copy: tables, chains and sets sorted,
// set elements sorted, kernel-assigned identifiers removed. Rule order is kept
// (it is semantic).
func (rs *Ruleset) normalized() *Ruleset {
	out := &Ruleset{}
	for _, t := range rs.Tables {
		nt := &TableSpec{Name: t.Name, Family: t.Family}
		for _, c := range t.Chains {
			nc := &ChainSpec{Name: c.Name, Type: c.Type, Hook: c.Hook, Priority: c.Priority, Policy: c.Policy}
			for _, r := range c.Rules {
				nr := &RuleSpec{UserData: r.UserData, Lossy: r.Lossy}
				for _, e := range r.Exprs {
					nr.Exprs = append(nr.Exprs, normExpr(e))
				}
				nc.Rules = append(nc.Rules, nr)
			}
			nt.Chains = append(nt.Chains, nc)
		}
		sort.Slice(nt.Chains, func(i, j int) bool { return nt.Chains[i].Name < nt.Chains[j].Name })
		for _, s := range t.Sets {
			ns := *s
			ns.Elems = append([]SetElem(nil), s.Elems...)
			sort.Slice(ns.Elems, func(i, j int) bool {
				if c := bytes.Compare(ns.Elems[i].Key, ns.Elems[j].Key); c != 0 {
					return c < 0
				}
				return !ns.Elems[i].End && ns.Elems[j].End
			})
			nt.Sets = append(nt.Sets, &ns)
		}
		sort.Slice(nt.Sets, func(i, j int) bool { return nt.Sets[i].Name < nt.Sets[j].Name })
		out.Tables = append(out.Tables, nt)
	}
	sort.Slice(out.Tables, func(i, j int) bool { return out.Tables[i].Name < out.Tables[j].Name })
	return out
}

func normExpr(e Expr) Expr {
	if v, ok := e.Any.(*expr.Lookup); ok {
		c := *v
		c.SetID = 0 // assigned per transaction
		return Expr{&c}
	}
	return e
}

// comparable is normalized plus the removal of kernel-filled details that do
// not change behaviour: a Log's attribute bitmask, snaplen and queue threshold
// (the kernel reports defaults for the NFLOG type). It is what hashes and
// diffs use; apply and restore use the exact objects.
func (rs *Ruleset) comparable() *Ruleset {
	out := rs.normalized()
	for _, t := range out.Tables {
		for _, c := range t.Chains {
			for _, r := range c.Rules {
				for i, e := range r.Exprs {
					if v, ok := e.Any.(*expr.Log); ok {
						cp := *v
						cp.Key, cp.Snaplen, cp.QThreshold = 0, 0, 0
						cp.Data = append([]byte(nil), v.Data...)
						r.Exprs[i] = Expr{&cp}
					}
				}
			}
		}
	}
	return out
}

// canonical is the stable serialization used for hashing and diffing.
func (rs *Ruleset) canonical() []byte {
	b, err := json.Marshal(rs.comparable())
	if err != nil {
		panic(err) // the model only contains marshalable types
	}
	return b
}

// Hash is a stable digest of the ruleset (the "ruleset hash" D10 audits).
func (rs *Ruleset) Hash() string {
	h := sha256.Sum256(rs.canonical())
	return hex.EncodeToString(h[:])
}

func describeRule(r *RuleSpec) string {
	b, _ := json.Marshal(r)
	return string(b)
}

// DiffRulesets lists human-readable differences between want and got. An empty
// result means identical (after normalization).
func DiffRulesets(want, got *Ruleset) []string {
	w, g := want.comparable(), got.comparable()
	var d []string
	wt, gt := map[string]*TableSpec{}, map[string]*TableSpec{}
	for _, t := range w.Tables {
		wt[t.Name] = t
	}
	for _, t := range g.Tables {
		gt[t.Name] = t
	}
	for _, t := range w.Tables {
		o := gt[t.Name]
		if o == nil {
			d = append(d, fmt.Sprintf("table %s: missing", t.Name))
			continue
		}
		d = append(d, diffTable(t, o)...)
	}
	for _, t := range g.Tables {
		if wt[t.Name] == nil {
			d = append(d, fmt.Sprintf("table %s: present but not declared", t.Name))
		}
	}
	return d
}

func diffTable(w, g *TableSpec) []string {
	var d []string
	pfx := "table " + w.Name
	if w.Family != g.Family {
		d = append(d, fmt.Sprintf("%s: family %d, declared %d", pfx, g.Family, w.Family))
	}
	gc := map[string]*ChainSpec{}
	for _, c := range g.Chains {
		gc[c.Name] = c
	}
	wc := map[string]bool{}
	for _, c := range w.Chains {
		wc[c.Name] = true
		o := gc[c.Name]
		cp := pfx + " chain " + c.Name
		if o == nil {
			d = append(d, cp+": missing")
			continue
		}
		if c.Type != o.Type || !eqPtr(c.Hook, o.Hook) || !eqPtr(c.Priority, o.Priority) || !eqPtr(c.Policy, o.Policy) {
			d = append(d, fmt.Sprintf("%s: attributes differ (declared %s, found %s)", cp, chainAttrs(c), chainAttrs(o)))
		}
		n := max(len(c.Rules), len(o.Rules))
		for i := 0; i < n; i++ {
			switch {
			case i >= len(o.Rules):
				d = append(d, fmt.Sprintf("%s rule %d: missing: %s", cp, i, describeRule(c.Rules[i])))
			case i >= len(c.Rules):
				d = append(d, fmt.Sprintf("%s rule %d: not declared: %s", cp, i, describeRule(o.Rules[i])))
			case !bytes.Equal(ruleJSON(c.Rules[i]), ruleJSON(o.Rules[i])):
				d = append(d, fmt.Sprintf("%s rule %d: differs: declared %s, found %s", cp, i, describeRule(c.Rules[i]), describeRule(o.Rules[i])))
			}
		}
	}
	for _, c := range g.Chains {
		if !wc[c.Name] {
			d = append(d, fmt.Sprintf("%s chain %s: present but not declared", pfx, c.Name))
		}
	}
	gs := map[string]*SetSpec{}
	for _, s := range g.Sets {
		gs[s.Name] = s
	}
	ws := map[string]bool{}
	for _, s := range w.Sets {
		ws[s.Name] = true
		o := gs[s.Name]
		if o == nil {
			d = append(d, fmt.Sprintf("%s set %s: missing", pfx, s.Name))
			continue
		}
		sj, _ := json.Marshal(s)
		oj, _ := json.Marshal(o)
		if !bytes.Equal(sj, oj) {
			d = append(d, fmt.Sprintf("%s set %s: contents differ", pfx, s.Name))
		}
	}
	for _, s := range g.Sets {
		if !ws[s.Name] {
			d = append(d, fmt.Sprintf("%s set %s: present but not declared", pfx, s.Name))
		}
	}
	return d
}

func ruleJSON(r *RuleSpec) []byte { b, _ := json.Marshal(r); return b }

func eqPtr[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func chainAttrs(c *ChainSpec) string {
	s := "type=" + c.Type
	if c.Hook != nil {
		s += fmt.Sprintf(" hook=%d", *c.Hook)
	}
	if c.Priority != nil {
		s += fmt.Sprintf(" prio=%d", *c.Priority)
	}
	if c.Policy != nil {
		s += fmt.Sprintf(" policy=%d", *c.Policy)
	}
	return s
}
