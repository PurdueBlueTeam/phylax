//go:build linux

package gotools

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	netmod "github.com/PurdueBlueTeam/phylax/internal/collect/net"
)

// Proc is one process as read from /proc.
type Proc struct {
	PID, PPID  int
	UID        uint32
	State      string
	Comm       string
	Exe        string
	ExeDeleted bool
	Cmdline    string
	StartTicks uint64
}

// procRoot is overridable by tests.
var procRoot = "/proc"

func pids() []int {
	ents, _ := os.ReadDir(procRoot)
	var out []int
	for _, e := range ents {
		if n, err := strconv.Atoi(e.Name()); err == nil && n > 0 {
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
}

func readProc(pid int) (Proc, bool) {
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return Proc{}, false
	}
	l, r := bytes.IndexByte(stat, '('), bytes.LastIndexByte(stat, ')')
	if l < 0 || r < l {
		return Proc{}, false
	}
	p := Proc{PID: pid, Comm: string(stat[l+1 : r])}
	f := strings.Fields(string(stat[r+1:]))
	if len(f) < 20 {
		return Proc{}, false
	}
	p.State = f[0]
	p.PPID, _ = strconv.Atoi(f[1])
	p.StartTicks, _ = strconv.ParseUint(f[19], 10, 64)
	if st, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
		for _, line := range strings.Split(string(st), "\n") {
			if v, ok := strings.CutPrefix(line, "Uid:"); ok {
				if fs := strings.Fields(v); len(fs) > 0 {
					u, _ := strconv.ParseUint(fs[0], 10, 32)
					p.UID = uint32(u)
				}
			}
		}
	}
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		if c, ok := strings.CutSuffix(exe, " (deleted)"); ok {
			exe, p.ExeDeleted = c, true
		}
		p.Exe = exe
	}
	if cl, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		p.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(bytes.TrimRight(cl, "\x00")), "\x00", " "))
	}
	return p, true
}

// PS lists all processes visible in /proc. Kernel threads have an empty Exe.
func PS() []Proc {
	var out []Proc
	for _, pid := range pids() {
		if p, ok := readProc(pid); ok {
			out = append(out, p)
		}
	}
	return out
}

// FormatPS renders a ps -ef style table. A deleted executable is flagged,
// since a running binary whose file was unlinked is a classic implant sign.
func FormatPS(w io.Writer, ps []Proc) {
	fmt.Fprintf(w, "%7s %7s %6s %s  %-16s %s\n", "PID", "PPID", "UID", "S", "COMM", "EXE / CMDLINE")
	for _, p := range ps {
		exe := p.Exe
		if p.ExeDeleted {
			exe += " (DELETED)"
		}
		cmd := p.Cmdline
		if cmd == "" {
			cmd = "[" + p.Comm + "]"
		}
		fmt.Fprintf(w, "%7d %7d %6d %s  %-16s %s | %s\n", p.PID, p.PPID, p.UID, p.State, p.Comm, exe, cmd)
	}
}

// Open is one open file descriptor of a process.
type Open struct {
	PID     int
	Comm    string
	FD      int
	Target  string // readlink of the fd: path, "socket:[inode]", "pipe:[inode]"
	Deleted bool
}

// Lsof lists the open descriptors of the given pids (all when empty).
// Unreadable processes (no privilege) are skipped.
func Lsof(only []int) []Open {
	want := map[int]bool{}
	for _, p := range only {
		want[p] = true
	}
	var out []Open
	for _, pid := range pids() {
		if len(want) > 0 && !want[pid] {
			continue
		}
		dir := filepath.Join(procRoot, strconv.Itoa(pid))
		ents, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			continue
		}
		comm := ""
		if b, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
			comm = strings.TrimSpace(string(b))
		}
		for _, e := range ents {
			fd, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			t, err := os.Readlink(filepath.Join(dir, "fd", e.Name()))
			if err != nil {
				continue
			}
			o := Open{PID: pid, Comm: comm, FD: fd, Target: t}
			if c, ok := strings.CutSuffix(t, " (deleted)"); ok {
				o.Target, o.Deleted = c, true
			}
			out = append(out, o)
		}
	}
	return out
}

// FormatLsof renders descriptors.
func FormatLsof(w io.Writer, os []Open) {
	fmt.Fprintf(w, "%-16s %7s %5s  %s\n", "COMM", "PID", "FD", "TARGET")
	for _, o := range os {
		t := o.Target
		if o.Deleted {
			t += " (DELETED)"
		}
		fmt.Fprintf(w, "%-16s %7d %5d  %s\n", o.Comm, o.PID, o.FD, t)
	}
}

// SockRow is a socket joined to its owning process.
type SockRow struct {
	netmod.Sock
	PID  int
	Comm string
}

// SS dumps TCP and UDP sockets over netlink sock_diag and joins them to
// processes through /proc/<pid>/fd (the join needs privilege for other users'
// processes; unowned sockets show PID 0).
func SS() ([]SockRow, error) {
	socks, err := netmod.SockDiag{}.Sockets()
	if err != nil {
		return nil, err
	}
	owner := map[uint64]Open{}
	for _, o := range Lsof(nil) {
		if s, ok := strings.CutPrefix(o.Target, "socket:["); ok {
			if n, err := strconv.ParseUint(strings.TrimSuffix(s, "]"), 10, 64); err == nil {
				if _, dup := owner[n]; !dup {
					owner[n] = o
				}
			}
		}
	}
	out := make([]SockRow, 0, len(socks))
	for _, s := range socks {
		r := SockRow{Sock: s}
		if o, ok := owner[s.Inode]; ok {
			r.PID, r.Comm = o.PID, o.Comm
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].Local.Port() < out[j].Local.Port()
	})
	return out, nil
}

var stateNames = map[uint8]string{
	netmod.StateEstablished: "ESTAB", netmod.StateSynSent: "SYN-SENT", netmod.StateSynRecv: "SYN-RECV",
	netmod.StateTimeWait: "TIME-WAIT", netmod.StateClose: "UNCONN", netmod.StateListen: "LISTEN",
}

// FormatSS renders sockets.
func FormatSS(w io.Writer, rows []SockRow) {
	fmt.Fprintf(w, "%-4s %-10s %-28s %-28s %s\n", "PROTO", "STATE", "LOCAL", "REMOTE", "PID/COMM")
	for _, r := range rows {
		st := stateNames[r.State]
		if st == "" {
			st = strconv.Itoa(int(r.State))
		}
		who := "-"
		if r.PID != 0 {
			who = fmt.Sprintf("%d/%s", r.PID, r.Comm)
		}
		fmt.Fprintf(w, "%-5s %-10s %-28s %-28s %s\n", r.Proto, st, r.Local, r.Remote, who)
	}
}
