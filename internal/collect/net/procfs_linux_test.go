//go:build linux

package netmod

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeProc builds a /proc-shaped tree: pid dirs with stat, exe -> real file,
// and fd symlinks "socket:[inode]".
func fakeProc(t *testing.T) (root, exe string) {
	t.Helper()
	root = t.TempDir()
	exe = filepath.Join(t.TempDir(), "sshd")
	if err := os.WriteFile(exe, []byte("#!fake binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	mk := func(pid int, comm string, start uint64, socks ...uint64) {
		d := filepath.Join(root, fmt.Sprint(pid))
		os.MkdirAll(filepath.Join(d, "fd"), 0o755)
		stat := fmt.Sprintf("%d (%s) S 1 %d 0 0 -1 4194560 100 0 0 0 1 1 0 0 20 0 1 0 %d 1000 100 18446744073709551615", pid, comm, pid, start)
		os.WriteFile(filepath.Join(d, "stat"), []byte(stat), 0o644)
		os.Symlink(exe, filepath.Join(d, "exe"))
		os.Symlink("/dev/null", filepath.Join(d, "fd", "0"))
		for i, in := range socks {
			os.Symlink(fmt.Sprintf("socket:[%d]", in), filepath.Join(d, "fd", fmt.Sprint(i+3)))
		}
	}
	mk(100, "sshd", 5000, 111, 112)
	mk(200, "we ird) (name", 7777, 222)
	os.MkdirAll(filepath.Join(root, "self"), 0o755) // non-numeric entries ignored
	return root, exe
}

func TestProcFSFakeTree(t *testing.T) {
	root, exe := fakeProc(t)
	now := time.Unix(1000, 0)
	pf := &ProcFS{Root: root, HashExe: true, Now: func() time.Time { return now }}
	got := pf.Resolve([]uint64{111, 222, 999})
	if got[111].PID != 100 || got[112].PID != 0 /* not wanted, not resolved */ {
		t.Fatalf("111 -> %+v", got[111])
	}
	if p := got[222]; p.PID != 200 || p.Comm != "we ird) (name" || p.StartTicks != 7777 {
		t.Fatalf("222 -> %+v", p)
	}
	if _, ok := got[999]; ok {
		t.Error("unowned inode resolved")
	}
	sum := sha256.Sum256([]byte("#!fake binary"))
	if got[111].ExeSHA256 != hex.EncodeToString(sum[:]) || got[111].Exe != exe {
		t.Errorf("exe: %+v", got[111])
	}
	if got[111].StartTicks != 5000 {
		t.Errorf("starttime %d", got[111].StartTicks)
	}

	// Cache: no walk for known inodes; unmapped inode is retried only after TTL.
	w := pf.Walks()
	pf.Resolve([]uint64{111, 999})
	if pf.Walks() != w {
		t.Error("walked again inside negative TTL")
	}
	now = now.Add(11 * time.Second)
	pf.Resolve([]uint64{111, 999})
	if pf.Walks() != w+1 {
		t.Error("expected a retry walk after negative TTL")
	}
	// A new inode appears (process opens another socket): one walk finds it.
	os.Symlink("socket:[333]", filepath.Join(root, "100", "fd", "9"))
	pf.Resolve([]uint64{111, 333})
	if got := pf.Resolve([]uint64{333}); got[333].PID != 100 {
		t.Errorf("333 -> %+v", got[333])
	}
	// Pruning bounds the cache to wanted inodes.
	pf.Resolve([]uint64{333})
	if len(pf.cache) != 1 {
		t.Errorf("cache not pruned: %d", len(pf.cache))
	}
}

func TestExeHashCacheKeyedByFileIdentity(t *testing.T) {
	root, exe := fakeProc(t)
	pf := &ProcFS{Root: root, HashExe: true, NegativeTTL: time.Nanosecond}
	h1 := pf.Resolve([]uint64{111})[111].ExeSHA256
	if len(pf.hashes) != 1 {
		t.Fatalf("hash cache size %d", len(pf.hashes))
	}
	// Same size, new content, ctime changes on write: must rehash.
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(exe, []byte("#!FAKE binary"), 0o755)
	pf.cache = nil
	pf.cache = map[uint64]Proc{}
	h2 := pf.Resolve([]uint64{111})[111].ExeSHA256
	if h1 == h2 || h2 == "" {
		t.Errorf("stale hash after rewrite: %s == %s", h1, h2)
	}
}

func TestParseStat(t *testing.T) {
	c, s, ok := parseStat([]byte("42 (a (b) c) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 99 100"))
	if !ok || c != "a (b) c" || s != 99 {
		t.Fatalf("%q %d %v", c, s, ok)
	}
	if _, _, ok := parseStat([]byte("garbage")); ok {
		t.Error("garbage parsed")
	}
}
