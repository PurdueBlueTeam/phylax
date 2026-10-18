// Package netmod is the agent's `net` module (docs: Modules): listeners
// and connections with owning process, sampled every 2 s. It reads
// /proc/net/{tcp,tcp6,udp,udp6} and resolves the owning pid through the
// socket inodes in /proc/<pid>/fd, so it needs no privileges for the
// tables (resolving other users' sockets needs read access to their fd
// dirs, which a root agent has) and no kernel module.
package netmod

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ConnEvent is one network event.
type ConnEvent struct {
	Kind    string `json:"kind"` // listener_new | connection_new | connection_gone
	Proto   string `json:"proto"`
	LAddr   string `json:"laddr,omitempty"`
	LPort   int    `json:"lport,omitempty"`
	RAddr   string `json:"raddr,omitempty"`
	RPort   int    `json:"rport,omitempty"`
	State   string `json:"state,omitempty"`
	PID     int    `json:"pid,omitempty"`
	Comm    string `json:"comm,omitempty"`
	Inode   uint64 `json:"inode,omitempty"`
}

// Sink receives network events.
type Sink interface {
	NetEvent(ConnEvent)
}

// Module samples the socket tables.
type Module struct {
	sink     Sink
	interval time.Duration
	procRoot string // /proc in production

	mu     sync.Mutex
	known  map[string]bool // key -> seen (key: proto|kind|addr:port[:raddr:rport])
	byInod map[uint64]string
}

// New builds the module. procRoot empty means /proc.
func New(sink Sink, procRoot string) *Module {
	if procRoot == "" {
		procRoot = "/proc"
	}
	return &Module{
		sink: sink, interval: 2 * time.Second,
		procRoot: procRoot,
		known: map[string]bool{}, byInod: map[uint64]string{},
	}
}

// Run samples until ctx is done.
func (m *Module) Run(ctx context.Context) error {
	m.sample(true)
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			m.sample(false)
		}
	}
}

type sock struct {
	proto string
	laddr string
	lport int
	raddr string
	rport int
	state string
	inode uint64
}

// sample reads the tables once.
func (m *Module) sample(baseline bool) {
	var socks []sock
	for _, tbl := range []struct {
		file  string
		proto string
	}{
		{"tcp", "tcp"}, {"tcp6", "tcp6"}, {"udp", "udp"}, {"udp6", "udp6"},
	} {
		socks = append(socks, parseTable(m.procRoot+"/net/"+tbl.file, tbl.proto)...)
	}
	pidOf := m.inodeToPID()

	m.mu.Lock()
	var evs []ConnEvent
	for _, s := range socks {
		kind := "connection_new"
		if s.state == "LISTEN" {
			kind = "listener_new"
		}
		key := fmt.Sprintf("%s|%s|%s:%d", s.proto, kind, s.laddr, s.lport)
		if s.proto == "tcp" && s.state != "" && s.state != "LISTEN" {
			// include the remote side so the same local port to many
			// peers is not one key
			key = fmt.Sprintf("%s|%s|%s:%d|%s:%d", s.proto, kind, s.laddr, s.lport, s.raddr, s.rport)
		}
		isNew := !m.known[key]
		m.known[key] = true
		if isNew && !baseline {
			evs = append(evs, ConnEvent{
				Kind: kind, Proto: s.proto, LAddr: s.laddr, LPort: s.lport,
				RAddr: s.raddr, RPort: s.rport, State: s.state,
				Inode: s.inode,
			})
		}
		if s.inode > 0 {
			m.byInod[s.inode] = key
		}
	}
	gone := make([]uint64, 0, 4)
	for ino, key := range m.byInod {
		still := false
		for _, s := range socks {
			if s.inode == ino {
				still = true
				break
			}
		}
		if !still {
			delete(m.byInod, ino)
			delete(m.known, key)
			if !baseline {
				gone = append(gone, ino)
			}
		}
	}
	m.mu.Unlock()

	for _, e := range evs {
		if pid, ok := pidOf[e.Inode]; ok {
			e.PID = pid
			e.Comm = m.comm(pid)
		}
		m.sink.NetEvent(e)
	}
	for _, ino := range gone {
		m.sink.NetEvent(ConnEvent{Kind: "connection_gone", Inode: ino})
	}
}

// inodeToPID maps socket inodes to pids via /proc/<pid>/fd.
func (m *Module) inodeToPID() map[uint64]int {
	out := map[uint64]int{}
	ents, err := os.ReadDir(m.procRoot)
	if err != nil {
		return out
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdents, err := os.ReadDir(filepath.Join(m.procRoot, e.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fdents {
			t, err := os.Readlink(filepath.Join(m.procRoot, e.Name(), "fd", fd.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(t, "socket:[") {
				ino, err := strconv.ParseUint(t[8:len(t)-1], 10, 64)
				if err == nil {
					out[ino] = pid
				}
			}
		}
	}
	return out
}

// comm reads the process name from the module's proc root.
func (m *Module) comm(pid int) string {
	b, err := os.ReadFile(filepath.Join(m.procRoot, fmt.Sprint(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// parseTable reads one /proc/net/{tcp,tcp6,udp,udp6} table.
func parseTable(path, proto string) []sock {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []sock
	lines := strings.Split(string(b), "\n")
	for _, line := range lines[1:] { // skip header
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		var s sock
		s.proto = proto
		s.laddr, s.lport = parseAddr(f[1], proto)
		s.raddr, s.rport = parseAddr(f[2], proto)
		s.state = stateName(f[3], proto)
		// f[9] is the inode
		s.inode, _ = strconv.ParseUint(f[9], 10, 64)
		out = append(out, s)
	}
	return out
}

// parseAddr decodes "AABBCCDD:1F90" (v4) or the 32-hex v6 form.
func parseAddr(hexaddr, proto string) (string, int) {
	i := strings.LastIndexByte(hexaddr, ':')
	if i < 0 {
		return "", 0
	}
	hexp, portHex := hexaddr[:i], hexaddr[i+1:]
	port, _ := strconv.ParseInt(portHex, 16, 32)
	h := strings.ToLower(hexp)
	if strings.ContainsRune(proto, '6') {
		var ip [16]byte
		for i := 0; i < len(h) && i/2 < 16; i += 2 {
			v, _ := strconv.ParseUint(h[i:i+2], 16, 8)
			ip[i/2] = byte(v)
		}
		// each 32-bit word is printed little-endian
		for w := 0; w < 4; w++ {
			a, b, c, d := ip[4*w], ip[4*w+1], ip[4*w+2], ip[4*w+3]
			ip[4*w], ip[4*w+1], ip[4*w+2], ip[4*w+3] = d, c, b, a
		}
		return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
			ip[0:2], ip[2:4], ip[4:6], ip[6:8], ip[8:10], ip[10:12], ip[12:14], ip[14:16]), int(port)
	}
	// v4: the kernel prints each 32-bit word little-endian in hex
	var ip [4]byte
	for i := 0; i < len(h) && i < 8; i += 2 {
		v, _ := strconv.ParseUint(h[i:i+2], 16, 8)
		ip[i/2] = byte(v)
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip[3], ip[2], ip[1], ip[0]), int(port)
}

// udp has no state and gets "".
func stateName(hex, proto string) string {
	if strings.HasPrefix(proto, "udp") {
		return ""
	}
	switch hex {
	case "01":
		return "ESTABLISHED"
	case "02":
		return "SYN_SENT"
	case "06":
		return "TIME_WAIT"
	case "0A":
		return "LISTEN"
	default:
		return hex
	}
}
