//go:build linux

package capture

import (
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// ProgramForFullPorts compiles the kernel filter: pass TCP and UDP
// (the protocols this platform parses), drop the rest. The Go side
// decides full vs truncated from the manifest's full ports.
func ProgramForFullPorts(full []int) []unix.SockFilter {
	prog := []bpf.Instruction{
		bpf.LoadAbsolute{Off: 9, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 1}, // TCP: accept
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17},             // UDP: accept
		bpf.RetConstant{Val: 0},                               // drop
		bpf.RetConstant{Val: 65535},                           // accept
	}
	return assemble(prog)
}

// assemble compiles instructions to the kernel sock_filter format; a
// compile error yields a minimal accept-all so capture still works.
func assemble(prog []bpf.Instruction) []unix.SockFilter {
	raw, err := bpf.Assemble(prog)
	if err != nil {
		raw, _ = bpf.Assemble([]bpf.Instruction{bpf.RetConstant{Val: 65535}})
	}
	out := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		out[i] = unix.SockFilter{
			Code:  uint16(r.Op),
			Jt:    r.Jt,
			Jf:    r.Jf,
			K:     r.K,
		}
	}
	return out
}
