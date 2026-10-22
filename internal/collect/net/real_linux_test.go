//go:build linux

package netmod

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func findSock(socks []Sock, f func(Sock) bool) (Sock, bool) {
	for _, s := range socks {
		if f(s) {
			return s, true
		}
	}
	return Sock{}, false
}

// Real sock_diag against sockets this test opens; needs no privileges.
func TestRealSockDiagAndProcJoin(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	lport := uint16(ln.Addr().(*net.TCPAddr).Port)
	cl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	sv, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer sv.Close()
	if _, err := cl.Write([]byte("hello world")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // let the ack land

	socks, err := SockDiag{WantBytes: true}.Sockets()
	if err != nil {
		t.Fatalf("sock_diag: %v", err)
	}
	lst, ok := findSock(socks, func(s Sock) bool { return s.Proto == "tcp" && s.State == StateListen && s.Local.Port() == lport })
	if !ok || !lst.IsListener() || lst.Inode == 0 {
		t.Fatalf("listener not found: %+v", lst)
	}
	cs, ok := findSock(socks, func(s Sock) bool {
		return s.Proto == "tcp" && s.Remote.Port() == lport && s.State == StateEstablished
	})
	if !ok || !cs.IsConnection() {
		t.Fatal("client connection not found")
	}
	if !cs.HasBytes || cs.BytesOut != 11 {
		t.Errorf("client bytes_out = %d (has=%v), want 11", cs.BytesOut, cs.HasBytes)
	}
	ss, ok := findSock(socks, func(s Sock) bool {
		return s.Proto == "tcp" && s.Local.Port() == lport && s.State == StateEstablished
	})
	if !ok || ss.BytesIn != 11 {
		t.Errorf("server bytes_in = %d, want 11", ss.BytesIn)
	}

	exe, _ := os.Executable()
	data, _ := os.ReadFile(exe)
	sum := sha256.Sum256(data)
	wantHash := hex.EncodeToString(sum[:])

	pf := &ProcFS{HashExe: true}
	got := pf.Resolve([]uint64{lst.Inode, cs.Inode})
	p, ok := got[lst.Inode]
	if !ok || p.PID != os.Getpid() {
		t.Fatalf("listener owner = %+v, want pid %d", p, os.Getpid())
	}
	if p.ExeSHA256 != wantHash {
		t.Errorf("exe hash %s want %s", p.ExeSHA256, wantHash)
	}
	if p.StartTicks == 0 || p.Comm == "" {
		t.Errorf("missing identity: %+v", p)
	}
	if got[cs.Inode].PID != os.Getpid() {
		t.Error("client socket not joined")
	}
	// Second resolve must be served from cache.
	w := pf.Walks()
	pf.Resolve([]uint64{lst.Inode, cs.Inode})
	if pf.Walks() != w {
		t.Error("cached inodes triggered another walk")
	}
	// An unmappable inode walks once, then is held off by the negative cache.
	pf.Resolve([]uint64{lst.Inode, 4000000000})
	w = pf.Walks()
	pf.Resolve([]uint64{lst.Inode, 4000000000})
	if pf.Walks() != w {
		t.Error("negative cache ignored")
	}
}

func TestRealUDPAndV6(t *testing.T) {
	uc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uport := uint16(uc.LocalAddr().(*net.UDPAddr).Port)
	l6, err6 := net.Listen("tcp6", "[::1]:0")
	var p6 uint16
	if err6 == nil {
		defer l6.Close()
		p6 = uint16(l6.Addr().(*net.TCPAddr).Port)
	}
	socks, err := SockDiag{}.Sockets()
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := findSock(socks, func(s Sock) bool { return s.Proto == "udp" && s.Local.Port() == uport }); !ok || !s.IsListener() {
		t.Errorf("udp listener not found: %+v", s)
	}
	if err6 != nil {
		t.Log("ipv6 loopback unavailable; skipping v6 check:", err6)
		return
	}
	if s, ok := findSock(socks, func(s Sock) bool { return s.Proto == "tcp" && s.Local.Port() == p6 }); !ok || s.Local.Addr().String() != "::1" {
		t.Errorf("v6 listener not found: %+v", s)
	}
}

// End to end: real sockets through the real tracker.
func TestRealTrackerLifecycle(t *testing.T) {
	tr := NewTracker(TrackerConfig{Services: map[string]string{}}, SockDiag{}, &ProcFS{HashExe: true})
	if _, err := tr.Poll(time.Now()); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	tr.cfg.Services[itoa(port)] = "testsvc"
	cl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sv, _ := ln.Accept()
	evs, err := tr.Poll(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var added *event.Event
	dirs := map[string]event.Event{}
	for i, e := range evs {
		if e.Kind == KindListenerAdded && e.Fields["port"] == port {
			added = &evs[i]
		}
		if e.Kind == KindConnectionOpened && (e.Fields["lport"] == port || e.Fields["rport"] == port) {
			dirs[e.Fields["dir"].(string)] = e
		}
	}
	if added == nil || added.Fields["pid"] != os.Getpid() || added.Fields["service"] != "testsvc" || added.Fields["exe_sha256"] == "" {
		t.Fatalf("listener_added wrong: %+v", added)
	}
	in, out := dirs["inbound"], dirs["outbound"]
	if in.Fields == nil || out.Fields == nil {
		t.Fatalf("want one inbound and one outbound connection, got %v", dirs)
	}
	if in.Fields["community_id"] != out.Fields["community_id"] || in.Fields["community_id"] == "" {
		t.Error("both ends must share a community id")
	}
	if in.Fields["service"] != "testsvc" || out.Fields["service"] != "testsvc" {
		t.Errorf("service mapping: in=%v out=%v", in.Fields["service"], out.Fields["service"])
	}
	cl.Close()
	sv.Close()
	ln.Close()
	evs, _ = tr.Poll(time.Now())
	var removed, closed int
	for _, e := range evs {
		if e.Kind == KindListenerRemoved && e.Fields["port"] == port {
			removed++
			if e.Fields["pid"] != os.Getpid() {
				t.Error("removed event lost process info")
			}
		}
		if e.Kind == KindConnectionClosed && (e.Fields["lport"] == port || e.Fields["rport"] == port) {
			closed++
		}
	}
	if removed != 1 || closed != 2 {
		t.Errorf("removed=%d closed=%d, want 1 and 2", removed, closed)
	}
}
