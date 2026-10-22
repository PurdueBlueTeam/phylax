//go:build linux

package gotools

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPSFindsSelf(t *testing.T) {
	self, _ := os.Executable()
	var me *Proc
	for _, p := range PS() {
		if p.PID == os.Getpid() {
			p := p
			me = &p
		}
	}
	if me == nil {
		t.Fatal("own pid not listed")
	}
	if me.PPID != os.Getppid() || me.UID != uint32(os.Getuid()) || me.Exe != self {
		t.Fatalf("%+v want ppid %d uid %d exe %s", me, os.Getppid(), os.Getuid(), self)
	}
	var b bytes.Buffer
	FormatPS(&b, PS())
	if !strings.Contains(b.String(), self) {
		t.Fatal("table lacks own exe")
	}
}

func TestLsofFindsOpenAndDeletedFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "held")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	find := func() (Open, bool) {
		for _, o := range Lsof([]int{os.Getpid()}) {
			if o.FD == int(f.Fd()) {
				return o, true
			}
		}
		return Open{}, false
	}
	o, ok := find()
	if !ok || o.Target != p || o.Deleted || o.PID != os.Getpid() {
		t.Fatalf("%+v %v", o, ok)
	}
	os.Remove(p)
	o, ok = find()
	if !ok || !o.Deleted || o.Target != p {
		t.Fatalf("deleted file not flagged: %+v", o)
	}
	var b bytes.Buffer
	FormatLsof(&b, []Open{o})
	if !strings.Contains(b.String(), "(DELETED)") {
		t.Fatal(b.String())
	}
}

func TestSSFindsOwnListener(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	defer l.Close()
	rows, err := SS()
	if err != nil {
		t.Skip("sock_diag unavailable:", err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	for _, r := range rows {
		if r.Proto == "tcp" && r.Local.Port() == port && r.IsListener() {
			if r.PID != os.Getpid() {
				t.Fatalf("listener attributed to pid %d, want %d", r.PID, os.Getpid())
			}
			var b bytes.Buffer
			FormatSS(&b, rows)
			if !strings.Contains(b.String(), "LISTEN") {
				t.Fatal(b.String())
			}
			return
		}
	}
	t.Fatalf("own listener on %d not found among %d sockets", port, len(rows))
}
