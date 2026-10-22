package capture

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/net/bpf"
)

// Snap lengths returned by the filter program (the kernel truncates the copy
// to the returned length; 0 drops the packet).
const (
	SnapFull  = 262144
	SnapOther = 128
)

// Filter describes the kernel packet filter: full packets on scored ports and
// ICMP, short captures elsewhere (or nothing elsewhere when OnlyScored), and
// the agent's own traffic dropped so capture cannot feed back on itself.
type Filter struct {
	Ports      []uint16         // scored and decoy ports, TCP and UDP
	SnapScored uint32           // default SnapFull
	SnapOther  uint32           // default SnapOther
	OnlyScored bool             // drop packets that match no scored port
	Exclude    []netip.AddrPort // controller endpoints: dropped in both directions
}

const maxFilterPorts = 48

type insn struct {
	op   bpf.Instruction
	jt   string // label for a true branch ("" = fall through)
	jf   string
	jump string // unconditional jump label
	lbl  string // label defined at this instruction
}

type asm struct {
	prog []insn
	n    int
}

func (a *asm) add(op bpf.Instruction) { a.prog = append(a.prog, insn{op: op}) }
func (a *asm) label(l string)         { a.prog = append(a.prog, insn{lbl: l}) }
func (a *asm) jeq(v uint32, t, f string) {
	a.prog = append(a.prog, insn{op: bpf.JumpIf{Cond: bpf.JumpEqual, Val: v}, jt: t, jf: f})
}
func (a *asm) jset(v uint32, t, f string) {
	a.prog = append(a.prog, insn{op: bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: v}, jt: t, jf: f})
}
func (a *asm) jmp(l string)    { a.prog = append(a.prog, insn{jump: l}) }
func (a *asm) ldh(off uint32)  { a.add(bpf.LoadAbsolute{Off: off, Size: 2}) }
func (a *asm) ldb(off uint32)  { a.add(bpf.LoadAbsolute{Off: off, Size: 1}) }
func (a *asm) ld32(off uint32) { a.add(bpf.LoadAbsolute{Off: off, Size: 4}) }

// resolve turns labels into relative skips. Label pseudo-instructions are
// removed; a label's position is the next real instruction.
func (a *asm) resolve() ([]bpf.Instruction, error) {
	pos := map[string]int{}
	n := 0
	for _, in := range a.prog {
		if in.lbl != "" {
			pos[in.lbl] = n
			continue
		}
		n++
	}
	var out []bpf.Instruction
	i := 0
	for _, in := range a.prog {
		if in.lbl != "" {
			continue
		}
		skip := func(l string) (uint8, error) {
			if l == "" {
				return 0, nil
			}
			p, ok := pos[l]
			if !ok {
				return 0, fmt.Errorf("bpf: undefined label %q", l)
			}
			d := p - (i + 1)
			if d < 0 || d > 255 {
				return 0, fmt.Errorf("bpf: jump to %q out of range (%d)", l, d)
			}
			return uint8(d), nil
		}
		switch {
		case in.jump != "":
			p, ok := pos[in.jump]
			if !ok || p <= i {
				return nil, fmt.Errorf("bpf: bad jump to %q", in.jump)
			}
			out = append(out, bpf.Jump{Skip: uint32(p - (i + 1))})
		default:
			if j, ok := in.op.(bpf.JumpIf); ok {
				t, err := skip(in.jt)
				if err != nil {
					return nil, err
				}
				f, err := skip(in.jf)
				if err != nil {
					return nil, err
				}
				j.SkipTrue, j.SkipFalse = t, f
				out = append(out, j)
			} else {
				out = append(out, in.op)
			}
		}
		i++
	}
	return out, nil
}

// Instructions assembles the classic BPF program.
func (f Filter) Instructions() ([]bpf.Instruction, error) {
	if len(f.Ports) > maxFilterPorts {
		return nil, fmt.Errorf("capture: %d ports exceeds the %d the filter can encode", len(f.Ports), maxFilterPorts)
	}
	if len(f.Exclude) > 8 {
		return nil, errors.New("capture: too many excluded endpoints")
	}
	if f.SnapScored == 0 {
		f.SnapScored = SnapFull
	}
	if f.SnapOther == 0 {
		f.SnapOther = SnapOther
	}
	a := &asm{}
	// Ethernet: untagged or one 802.1Q tag. (AF_PACKET normally strips the tag
	// into packet metadata; the tagged path serves pcap input and raw sockets.)
	// Dispatch jumps are one-byte, so each target is reached through a local
	// trampoline of unconditional (32-bit) jumps.
	a.ldh(12)
	a.jeq(0x0800, "t_v4_14", "")
	a.jeq(0x86dd, "t_v6_14", "")
	a.jeq(0x8100, "", "t_other")
	a.ldh(16)
	a.jeq(0x0800, "t_v4_18", "")
	a.jeq(0x86dd, "t_v6_18", "")
	a.label("t_other")
	a.jmp("other_0")
	for _, t := range []string{"v4_14", "v6_14", "v4_18", "v6_18"} {
		a.label("t_" + t)
		a.jmp(t)
	}
	a.label("other_0")
	f.ret(a, "other_0", f.otherSnap())
	for _, base := range []uint32{14, 18} {
		f.v4(a, base)
		f.v6(a, base)
	}
	return a.resolve()
}

func (f Filter) otherSnap() uint32 {
	if f.OnlyScored {
		return 0
	}
	return f.SnapOther
}

func (f Filter) ret(a *asm, label string, v uint32) {
	a.label(label)
	a.add(bpf.RetConstant{Val: v})
}

// rets places the three terminal instructions local to a block so every
// conditional jump stays within the one-byte range.
func (f Filter) rets(a *asm, base uint32, tag string) {
	f.ret(a, lbl("other"+tag, base), f.otherSnap())
	f.ret(a, lbl("drop"+tag, base), 0)
	f.ret(a, lbl("scored"+tag, base), f.SnapScored)
}

func lbl(s string, base uint32) string { return fmt.Sprintf("%s_%d", s, base) }

func (f Filter) portTests(a *asm, scored string) {
	for _, p := range f.Ports {
		a.jeq(uint32(p), scored, "")
	}
}

func (f Filter) v4(a *asm, base uint32) {
	t := "4"
	a.label(lbl("v4", base))
	for _, e := range f.Exclude {
		if !e.Addr().Is4() {
			continue
		}
		ip := e.Addr().As4()
		v := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
		for k, ipOff := range []uint32{12, 16} { // src then dst
			a.n++
			next, ports := fmt.Sprintf("n%d", a.n), fmt.Sprintf("p%d", a.n)
			a.ld32(base + ipOff)
			a.jeq(v, "", next)
			a.ldb(base + 9)
			a.jeq(6, ports, "")
			a.jeq(17, "", next)
			a.label(ports)
			a.add(bpf.LoadMemShift{Off: base})
			a.add(bpf.LoadIndirect{Off: base + 2*uint32(k), Size: 2})
			a.jeq(uint32(e.Port()), lbl("drop"+t, base), "")
			a.label(next)
		}
	}
	a.ldb(base + 9)
	a.jeq(1, lbl("scored"+t, base), "")
	l4 := lbl("l4"+t, base)
	a.jeq(6, l4, "")
	a.jeq(17, l4, lbl("other"+t, base))
	a.label(l4)
	a.ldh(base + 6)
	a.jset(0x1fff, lbl("other"+t, base), "") // non-first fragment: no ports
	a.add(bpf.LoadMemShift{Off: base})
	a.add(bpf.LoadIndirect{Off: base, Size: 2})
	f.portTests(a, lbl("scored"+t, base))
	a.add(bpf.LoadIndirect{Off: base + 2, Size: 2})
	f.portTests(a, lbl("scored"+t, base))
	a.jmp(lbl("other"+t, base))
	f.rets(a, base, t)
}

func (f Filter) v6(a *asm, base uint32) {
	t := "6"
	a.label(lbl("v6", base))
	for _, e := range f.Exclude {
		if !e.Addr().Is6() || e.Addr().Is4In6() {
			continue
		}
		ip := e.Addr().As16()
		for k, ipOff := range []uint32{8, 24} {
			a.n++
			next, ports := fmt.Sprintf("n%d", a.n), fmt.Sprintf("p%d", a.n)
			for w := 0; w < 4; w++ {
				v := uint32(ip[4*w])<<24 | uint32(ip[4*w+1])<<16 | uint32(ip[4*w+2])<<8 | uint32(ip[4*w+3])
				a.ld32(base + ipOff + uint32(4*w))
				a.jeq(v, "", next)
			}
			a.ldb(base + 6)
			a.jeq(6, ports, "")
			a.jeq(17, "", next)
			a.label(ports)
			a.ldh(base + 40 + 2*uint32(k))
			a.jeq(uint32(e.Port()), lbl("drop"+t, base), "")
			a.label(next)
		}
	}
	a.ldb(base + 6)
	a.jeq(58, lbl("scored"+t, base), "")
	l4 := lbl("l4"+t, base)
	a.jeq(6, l4, "")
	a.jeq(17, l4, lbl("other"+t, base))
	a.label(l4)
	a.ldh(base + 40)
	f.portTests(a, lbl("scored"+t, base))
	a.ldh(base + 42)
	f.portTests(a, lbl("scored"+t, base))
	a.jmp(lbl("other"+t, base))
	f.rets(a, base, t)
}

// Raw returns the program in kernel form for SO_ATTACH_FILTER.
func (f Filter) Raw() ([]bpf.RawInstruction, error) {
	ins, err := f.Instructions()
	if err != nil {
		return nil, err
	}
	return bpf.Assemble(ins)
}
