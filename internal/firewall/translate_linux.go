//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"golang.org/x/sys/unix"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
)

// Table names we own (the renderer's names). Anything else is foreign.
var ownedTables = []string{render.TableMgmt, render.TableMain, render.TableNAT}

// OwnedTables returns the names of the tables this package owns.
func OwnedTables() []string { return slices.Clone(ownedTables) }

func isOwned(name string) bool { return slices.Contains(ownedTables, name) }

const (
	famINet = uint8(nftables.TableFamilyINet)
	// mgmtMark is render.MgmtMark as a number.
	mgmtMark uint32 = 0x7068

	maxCommentBytes = 100
)

// TranslateOptions tunes Translate.
type TranslateOptions struct {
	Mode Mode
	// AllowNoManagement lets a default-drop policy without management rules
	// through (labs, tests).
	AllowNoManagement bool
}

// Translate builds the nftables ruleset for a Linux host policy. It mirrors
// render.NFTables rule for rule (the nft text is the reviewed reference and
// `nft -c` validates it in CI), but builds typed netlink objects directly: no
// text parser, no shelling out, and the result can be diffed against a kernel
// read-back, which text cannot.
func Translate(hp *render.HostPolicy, opt TranslateOptions) (*Ruleset, error) {
	if hp.Family == "windows" {
		return nil, fmt.Errorf("firewall: host %s is Windows", hp.Host)
	}
	if opt.Mode == "" {
		opt.Mode = ModeEnforce
	}
	if opt.Mode != ModeEnforce && opt.Mode != ModeShadow {
		return nil, fmt.Errorf("firewall: unknown mode %q", opt.Mode)
	}
	if (hp.DefaultIn == render.Drop || hp.DefaultOut == render.Drop) && !opt.AllowNoManagement {
		has := false
		for _, r := range hp.Rules {
			if r.Group == render.GroupMgmt {
				has = true
			}
		}
		if !has {
			return nil, ErrNoManagement
		}
	}
	shadow := opt.Mode == ModeShadow
	rs := &Ruleset{}

	mgmt := newTable(render.TableMgmt)
	for _, d := range []render.Direction{render.In, render.Out} {
		c := baseChain(mgmt, hookName(d), "filter", hookNum(d), -10, nftables.ChainPolicyAccept)
		for _, r := range hp.Rules {
			if r.Group == render.GroupMgmt && r.Dir == d {
				mgmt.addRules(c, r, ruleOpts{mark: true, shadow: shadow})
			}
		}
	}
	rs.Tables = append(rs.Tables, mgmt.spec)

	main := newTable(render.TableMain)
	for _, d := range []render.Direction{render.In, render.Out} {
		def := hp.DefaultIn
		if d == render.Out {
			def = hp.DefaultOut
		}
		pol := nftables.ChainPolicyAccept
		if def == render.Drop && !shadow {
			pol = nftables.ChainPolicyDrop
		}
		c := baseChain(main, hookName(d), "filter", hookNum(d), 0, pol)
		ifKey := expr.MetaKeyIIF
		if d == render.Out {
			ifKey = expr.MetaKeyOIF
		}
		main.add(c, []expr.Any{
			&expr.Meta{Key: ifKey, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(1)}, // lo
			&expr.Verdict{Kind: expr.VerdictAccept},
		}, "loopback")
		if !shadow { // shadow never drops, not even invalid packets
			main.add(c, append(ctState(expr.CmpOpNeq, 0, expr.CtStateBitINVALID), &expr.Verdict{Kind: expr.VerdictDrop}), "")
		}
		main.add(c, append(ctState(expr.CmpOpNeq, 0, expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED), &expr.Verdict{Kind: expr.VerdictAccept}), "established and related")
		main.add(c, []expr.Any{
			&expr.Ct{Register: 1, Key: expr.CtKeyMARK},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(mgmtMark), Xor: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(mgmtMark)},
			&expr.Verdict{Kind: expr.VerdictAccept},
		}, "management flows (table "+render.TableMgmt+")")
		for _, r := range hp.Rules {
			if r.Dir != d || r.Group == render.GroupMgmt || r.Kind == render.KindLoopback || r.Kind == render.KindEstablished {
				continue
			}
			main.addRules(c, r, ruleOpts{shadow: shadow})
		}
		if d == render.Out && hp.DenyLogGroup != 0 && hp.DefaultOut == render.Drop {
			main.add(c, []expr.Any{
				limit(100, 200),
				logExpr(hp.DenyLogGroup, "phylax-egress-deny: "),
			}, "denied egress; the policy then drops")
		}
		if shadow && def == render.Drop {
			// The would-be drop: logged, then the accept policy lets it through.
			main.add(c, []expr.Any{
				limit(100, 200),
				logExpr(shadowGroup(hp), "phylax-shadow-"+hookName(d)+": "),
			}, "shadow: would drop")
		}
	}
	rs.Tables = append(rs.Tables, main.spec)

	if hp.SinkholePort != 0 && hp.DefaultOut == render.Drop && !shadow {
		nat := newTable(render.TableNAT)
		c := baseChain(nat, "sinkhole", "nat", *nftables.ChainHookOutput, -100, nftables.ChainPolicyAccept)
		nat.add(c, []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIF, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(1)},
			&expr.Verdict{Kind: expr.VerdictReturn},
		}, "")
		nat.add(c, append(ctState(expr.CmpOpEq, 0, expr.CtStateBitNEW), &expr.Verdict{Kind: expr.VerdictReturn}), "")
		for _, r := range hp.Rules {
			if r.Dir != render.Out || r.Proto != "tcp" {
				continue
			}
			switch r.Group {
			case render.GroupMgmt, render.GroupDependency, render.GroupEgress, render.GroupCanary, render.GroupDomain:
				rr := r
				rr.Action, rr.Log = render.Accept, false
				nat.addRules(c, rr, ruleOpts{verdict: expr.VerdictReturn})
			}
		}
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], hp.SinkholePort)
		nat.add(c, []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Immediate{Register: 1, Data: port[:]},
			&expr.Redir{RegisterProtoMin: 1, RegisterProtoMax: 1, Flags: 2 /* NF_NAT_RANGE_PROTO_SPECIFIED, as nft sets it */},
		}, "sinkhole: record what the implant would have said")
		rs.Tables = append(rs.Tables, nat.spec)
	}
	for _, t := range rs.Tables {
		sort.Slice(t.Sets, func(i, j int) bool { return t.Sets[i].Name < t.Sets[j].Name })
	}
	return rs.normalized(), nil
}

// shadowGroup is the NFLOG group for shadow would-drop records.
func shadowGroup(hp *render.HostPolicy) uint16 {
	if hp.DenyLogGroup != 0 {
		return hp.DenyLogGroup
	}
	return 1
}

func hookName(d render.Direction) string {
	return map[render.Direction]string{render.In: "input", render.Out: "output"}[d]
}
func hookNum(d render.Direction) nftables.ChainHook {
	if d == render.In {
		return *nftables.ChainHookInput
	}
	return *nftables.ChainHookOutput
}

type tableBuilder struct {
	spec *TableSpec
	sets map[string]*SetSpec
}

func newTable(name string) *tableBuilder {
	return &tableBuilder{spec: &TableSpec{Name: name, Family: famINet}, sets: map[string]*SetSpec{}}
}

func baseChain(t *tableBuilder, name, typ string, hook nftables.ChainHook, prio int32, pol nftables.ChainPolicy) *ChainSpec {
	h, p := uint32(hook), uint32(pol)
	c := &ChainSpec{Name: name, Type: typ, Hook: &h, Priority: &prio, Policy: &p}
	t.spec.Chains = append(t.spec.Chains, c)
	return c
}

func (t *tableBuilder) add(c *ChainSpec, exprs []expr.Any, comment string) {
	r := &RuleSpec{}
	for _, e := range exprs {
		r.Exprs = append(r.Exprs, Expr{e})
	}
	if comment != "" {
		r.UserData = userdata.Append(nil, userdata.TypeComment, []byte(cleanComment(comment)))
	}
	c.Rules = append(c.Rules, r)
}

// cleanComment mirrors the nft renderer's sanitising and bounds the length
// (the kernel accepts only short userdata).
func cleanComment(s string) string {
	s = strings.Map(func(ch rune) rune {
		if ch == '"' || ch == '\\' || ch == '\n' {
			return '\''
		}
		return ch
	}, s)
	if len(s) > maxCommentBytes {
		s = s[:maxCommentBytes]
		for len(s) > 0 && s[len(s)-1]&0xC0 == 0x80 { // do not split a UTF-8 sequence
			s = s[:len(s)-1]
		}
	}
	return s
}

type ruleOpts struct {
	mark    bool
	shadow  bool
	verdict expr.VerdictKind // overrides the rule's action when set (return)
}

// addRules mirrors render.ruleLines: v4 and v6 peers become separate rules.
func (t *tableBuilder) addRules(c *ChainSpec, r render.Rule, o ruleOpts) {
	verdictKind := expr.VerdictAccept
	if r.Action == render.Drop {
		verdictKind = expr.VerdictDrop
	}
	if o.verdict != 0 {
		verdictKind = o.verdict
	}
	var tail []expr.Any
	if o.mark {
		tail = append(tail, &expr.Ct{Register: 1, Key: expr.CtKeyMARK},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: binaryutil.NativeEndian.PutUint32(^mgmtMark), Xor: binaryutil.NativeEndian.PutUint32(mgmtMark)},
			&expr.Ct{Register: 1, SourceRegister: true, Key: expr.CtKeyMARK})
	}
	if r.Log {
		tail = append(tail, limit(20, 40), logExpr(r.LogGroup, "phylax-canary: "))
	}
	if !(o.shadow && verdictKind == expr.VerdictDrop) { // shadow: log, never drop
		tail = append(tail, &expr.Verdict{Kind: verdictKind})
	} else if !r.Log {
		tail = append(tail, limit(20, 40), logExpr(1, "phylax-shadow: "))
	}

	var l4 []expr.Any
	switch r.Proto {
	case "icmp":
		t.add(c, append(l4proto(unix.IPPROTO_ICMP), tail...), r.Comment)
		return
	case "icmpv6":
		t.add(c, append(l4proto(unix.IPPROTO_ICMPV6), tail...), r.Comment)
		return
	case "tcp", "udp":
		pn := byte(unix.IPPROTO_TCP)
		if r.Proto == "udp" {
			pn = unix.IPPROTO_UDP
		}
		l4 = append(l4, l4proto(pn)...)
		dst, dstR, src, srcR := r.LocalPorts, r.LocalRanges, r.RemotePorts, r.RemoteRanges
		if r.Dir == render.Out {
			dst, dstR, src, srcR = r.RemotePorts, r.RemoteRanges, r.LocalPorts, r.LocalRanges
		}
		if len(src)+len(srcR) > 0 {
			l4 = append(l4, t.portMatch(0, src, srcR)...)
		}
		if len(dst)+len(dstR) > 0 {
			l4 = append(l4, t.portMatch(2, dst, dstR)...)
		}
	}
	if o.mark {
		l4 = append(l4, ctState(expr.CmpOpNeq, 0, expr.CtStateBitNEW)...)
	}
	if len(r.Peers) == 0 {
		t.add(c, append(l4, tail...), r.Comment)
		return
	}
	var v4, v6 []netip.Prefix
	for _, p := range r.Peers {
		if p.Addr().Is4() {
			v4 = append(v4, p.Masked())
		} else {
			v6 = append(v6, p.Masked())
		}
	}
	for _, grp := range [][]netip.Prefix{v4, v6} {
		if len(grp) == 0 {
			continue
		}
		m := t.addrMatch(r.Dir, grp)
		var e []expr.Any
		e = append(e, m...)
		e = append(e, l4...)
		e = append(e, tail...)
		t.add(c, e, r.Comment)
	}
}

func l4proto(p byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{p}},
	}
}

// ctState emits: ct state & bits <op> val. (op Neq 0 = "any of bits".)
func ctState(op expr.CmpOp, val uint32, bits uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(bits), Xor: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: op, Register: 1, Data: binaryutil.NativeEndian.PutUint32(val)},
	}
}

func limit(rate uint64, burst uint32) *expr.Limit {
	return &expr.Limit{Type: expr.LimitTypePkts, Rate: rate, Unit: expr.LimitTimeSecond, Burst: burst}
}

func logExpr(group uint16, prefix string) *expr.Log {
	return &expr.Log{
		Key:   1<<unix.NFTA_LOG_GROUP | 1<<unix.NFTA_LOG_PREFIX,
		Group: group, Data: []byte(prefix),
	}
}

// portMatch matches the transport header port at offset (0 sport, 2 dport)
// against single ports and inclusive ranges. Overlapping and adjacent items
// are merged; more than one item, or any range, becomes an interval set.
func (t *tableBuilder) portMatch(offset uint32, ports []uint16, ranges []manifest.PortRange) []expr.Any {
	var iv []manifest.PortRange
	for _, p := range ports {
		iv = append(iv, manifest.PortRange{Lo: p, Hi: p})
	}
	iv = append(iv, ranges...)
	sort.Slice(iv, func(i, j int) bool { return iv[i].Lo < iv[j].Lo })
	var m []manifest.PortRange
	for _, r := range iv {
		if n := len(m); n > 0 && int(r.Lo) <= int(m[n-1].Hi)+1 {
			if r.Hi > m[n-1].Hi {
				m[n-1].Hi = r.Hi
			}
			continue
		}
		m = append(m, r)
	}
	load := &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: 2}
	be := func(v uint16) []byte { var b [2]byte; binary.BigEndian.PutUint16(b[:], v); return b[:] }
	if len(m) == 1 && m[0].Lo == m[0].Hi {
		return []expr.Any{load, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: be(m[0].Lo)}}
	}
	s := &SetSpec{KeyName: nftables.TypeInetService.Name, KeyBytes: nftables.TypeInetService.Bytes, KeyMagic: nftables.TypeInetService.GetNFTMagic()}
	if len(ranges) == 0 {
		for _, r := range m {
			s.Elems = append(s.Elems, SetElem{Key: be(r.Lo)})
		}
	} else {
		s.Interval = true
		for _, r := range m {
			s.Elems = append(s.Elems, SetElem{Key: be(r.Lo)})
			if r.Hi != 65535 { // the range then runs to the top of the key space
				s.Elems = append(s.Elems, SetElem{Key: be(r.Hi + 1), End: true})
			}
		}
	}
	return []expr.Any{load, &expr.Lookup{SourceRegister: 1, SetName: t.addSet("port", s)}}
}

// addrMatch matches the source (In) or destination (Out) address against
// prefixes of one family. Contained prefixes are folded into their cover
// (interval sets reject overlaps; the meaning is unchanged).
func (t *tableBuilder) addrMatch(dir render.Direction, ps []netip.Prefix) []expr.Any {
	is4 := ps[0].Addr().Is4()
	ps = foldPrefixes(ps)
	var nf byte = unix.NFPROTO_IPV6
	var off, alen uint32 = 8, 16 // ip6 saddr
	if is4 {
		nf, off, alen = unix.NFPROTO_IPV4, 12, 4
	}
	if dir == render.Out {
		off = map[bool]uint32{true: 16, false: 24}[is4]
	}
	out := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nf}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: alen},
	}
	if len(ps) == 1 {
		p := ps[0]
		if p.Bits() == 0 {
			return out[:2] // any address of the family
		}
		a := p.Addr().AsSlice()
		if p.Bits() != int(alen)*8 {
			mask := prefixMask(p.Bits(), int(alen))
			out = append(out, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: alen, Mask: mask, Xor: make([]byte, alen)})
		}
		return append(out, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: a})
	}
	typ := nftables.TypeIPAddr
	if !is4 {
		typ = nftables.TypeIP6Addr
	}
	s := &SetSpec{KeyName: typ.Name, KeyBytes: typ.Bytes, KeyMagic: typ.GetNFTMagic(), Interval: true}
	// Adjacent prefixes are merged into one range: an end key equal to the next
	// start key is a duplicate element for the kernel.
	type rng struct {
		lo, hi []byte // hi nil: the range runs to the top of the address space
	}
	var rs []rng
	for _, p := range ps {
		end, ok := prefixEnd(p)
		cur := rng{lo: p.Addr().AsSlice()}
		if ok {
			cur.hi = end
		}
		if n := len(rs); n > 0 && rs[n-1].hi != nil && bytes.Equal(rs[n-1].hi, cur.lo) {
			rs[n-1].hi = cur.hi
			continue
		}
		rs = append(rs, cur)
	}
	for _, r := range rs {
		s.Elems = append(s.Elems, SetElem{Key: r.lo})
		if r.hi != nil {
			s.Elems = append(s.Elems, SetElem{Key: r.hi, End: true})
		}
	}
	return append(out, &expr.Lookup{SourceRegister: 1, SetName: t.addSet("addr"+map[bool]string{true: "4", false: "6"}[is4], s)})
}

func prefixMask(bits, n int) []byte {
	m := make([]byte, n)
	for i := 0; i < bits; i++ {
		m[i/8] |= 0x80 >> (i % 8)
	}
	return m
}

// prefixEnd returns the first address after the prefix; ok is false if the
// prefix ends at the top of the address space (the interval then runs to the
// end and no end element is needed).
func prefixEnd(p netip.Prefix) ([]byte, bool) {
	out := p.Masked().Addr().AsSlice() // host bits are zero
	for bit := p.Bits() - 1; bit >= 0; bit-- {
		by, mk := bit/8, byte(0x80>>(bit%8))
		if out[by]&mk == 0 {
			out[by] |= mk
			return out, true
		}
		out[by] &^= mk // carry
	}
	return nil, false
}

// foldPrefixes sorts, de-duplicates and drops prefixes contained in another.
func foldPrefixes(ps []netip.Prefix) []netip.Prefix {
	ps = slices.Clone(ps)
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
	var out []netip.Prefix
	for _, p := range ps {
		if n := len(out); n > 0 && out[n-1].Contains(p.Addr()) && out[n-1].Bits() <= p.Bits() {
			continue
		}
		out = append(out, p)
	}
	return out
}

// addSet registers a named set, de-duplicated by content, and returns its name.
func (t *tableBuilder) addSet(kind string, s *SetSpec) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%d|%v", s.KeyName, s.KeyBytes, s.Interval)
	for _, e := range s.Elems {
		fmt.Fprintf(h, "|%x:%v", e.Key, e.End)
	}
	s.Name = kind + "_" + hex.EncodeToString(h.Sum(nil))[:10]
	if _, ok := t.sets[s.Name]; !ok {
		t.sets[s.Name] = s
		t.spec.Sets = append(t.spec.Sets, s)
	}
	return s.Name
}
