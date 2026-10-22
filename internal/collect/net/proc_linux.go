//go:build linux

package netmod

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ProcFS resolves socket inodes to owning processes by walking
// <Root>/<pid>/fd (osquery's algorithm). Known inodes are served from a cache;
// a walk happens only when a wanted inode is unmapped, and inodes that stay
// unmapped (other users' sockets when unprivileged, kernel sockets) are not
// retried until NegativeTTL passes. Not safe for concurrent use.
type ProcFS struct {
	Root        string        // default /proc
	HashExe     bool          // sha256 the executable
	MaxHashSize int64         // skip hashing larger files (default 256 MiB)
	NegativeTTL time.Duration // default 10s
	Now         func() time.Time

	cache  map[uint64]Proc
	neg    map[uint64]time.Time
	hashes map[fileID]string
	walks  int
}

type fileID struct {
	dev, ino uint64
	csec     int64
	cnsec    int64
	size     int64
}

const maxHashCache = 4096

// Walks returns how many full /proc walks have run (for tests and health).
func (p *ProcFS) Walks() int { return p.walks }

func (p *ProcFS) root() string {
	if p.Root == "" {
		return "/proc"
	}
	return p.Root
}

func (p *ProcFS) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Resolve maps each wanted inode to its owner. Inodes with no readable owner
// are absent from the result. Cache entries for inodes not wanted are pruned,
// which bounds memory to the live socket table.
func (p *ProcFS) Resolve(inodes []uint64) map[uint64]Proc {
	if p.cache == nil {
		p.cache, p.neg, p.hashes = map[uint64]Proc{}, map[uint64]time.Time{}, map[fileID]string{}
	}
	want := make(map[uint64]struct{}, len(inodes))
	for _, in := range inodes {
		if in != 0 {
			want[in] = struct{}{}
		}
	}
	for in := range p.cache {
		if _, ok := want[in]; !ok {
			delete(p.cache, in)
		}
	}
	for in := range p.neg {
		if _, ok := want[in]; !ok {
			delete(p.neg, in)
		}
	}
	now := p.now()
	ttl := p.NegativeTTL
	if ttl == 0 {
		ttl = 10 * time.Second
	}
	missing := map[uint64]struct{}{}
	for in := range want {
		if _, ok := p.cache[in]; ok {
			continue
		}
		if t, ok := p.neg[in]; ok && now.Sub(t) < ttl {
			continue
		}
		missing[in] = struct{}{}
	}
	if len(missing) > 0 {
		p.walk(missing)
		for in := range missing {
			if _, ok := p.cache[in]; !ok {
				p.neg[in] = now
			} else {
				delete(p.neg, in)
			}
		}
	}
	out := make(map[uint64]Proc, len(p.cache))
	for in, pr := range p.cache {
		out[in] = pr
	}
	return out
}

func (p *ProcFS) walk(missing map[uint64]struct{}) {
	p.walks++
	root := p.root()
	d, err := os.Open(root)
	if err != nil {
		return
	}
	names, _ := d.Readdirnames(-1)
	d.Close()
	owners := map[int][]uint64{}
	for _, name := range names {
		pid, err := strconv.Atoi(name)
		if err != nil || pid <= 0 {
			continue
		}
		fdd, err := os.Open(filepath.Join(root, name, "fd"))
		if err != nil {
			continue
		}
		fds, _ := fdd.Readdirnames(-1)
		fdd.Close()
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(root, name, "fd", fd))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			in, err := strconv.ParseUint(strings.TrimSuffix(link[len("socket:["):], "]"), 10, 64)
			if err != nil {
				continue
			}
			if _, ok := missing[in]; !ok {
				continue
			}
			owners[pid] = append(owners[pid], in)
			delete(missing, in)
		}
		if len(missing) == 0 {
			break
		}
	}
	for pid, ins := range owners {
		pr, ok := p.ReadProc(pid)
		if !ok {
			continue
		}
		for _, in := range ins {
			p.cache[in] = pr
		}
	}
}

// ReadProc reads the identity of one process: pid, start time (clock ticks
// since boot, from stat field 22), comm, exe path, uid and binary hash.
func (p *ProcFS) ReadProc(pid int) (Proc, bool) {
	if p.hashes == nil {
		p.hashes = map[fileID]string{}
	}
	dir := filepath.Join(p.root(), strconv.Itoa(pid))
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return Proc{}, false
	}
	comm, start, ok := parseStat(stat)
	if !ok {
		return Proc{}, false
	}
	pr := Proc{PID: pid, StartTicks: start, Comm: comm}
	if st, err := os.Stat(dir); err == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			pr.UID = sys.Uid
		}
	}
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		if cut, found := strings.CutSuffix(exe, " (deleted)"); found {
			exe, pr.ExeDeleted = cut, true
		}
		pr.Exe = exe
		if p.HashExe {
			pr.ExeSHA256 = p.hashExe(filepath.Join(dir, "exe"))
		}
	}
	return pr, true
}

// parseStat extracts comm and starttime from /proc/<pid>/stat. comm may hold
// spaces and parentheses, so it is delimited by the first '(' and last ')'.
func parseStat(b []byte) (comm string, start uint64, ok bool) {
	l, r := bytes.IndexByte(b, '('), bytes.LastIndexByte(b, ')')
	if l < 0 || r < l {
		return "", 0, false
	}
	comm = string(b[l+1 : r])
	f := strings.Fields(string(b[r+1:]))
	// after ")" the fields start at field 3 (state); starttime is field 22.
	if len(f) < 20 {
		return "", 0, false
	}
	v, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return comm, v, true
}

func (p *ProcFS) hashExe(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	max := p.MaxHashSize
	if max == 0 {
		max = 256 << 20
	}
	if st.Size() > max {
		return ""
	}
	id := fileID{uint64(sys.Dev), sys.Ino, int64(sys.Ctim.Sec), int64(sys.Ctim.Nsec), st.Size()}
	if h, ok := p.hashes[id]; ok {
		return h
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, max+1)); err != nil {
		return ""
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if len(p.hashes) >= maxHashCache {
		clear(p.hashes)
	}
	p.hashes[id] = sum
	return sum
}
