package netmod

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseAddr(t *testing.T) {
	addr, port := parseAddr("0100007F:1F90", "tcp")
	if addr != "127.0.0.1" || port != 8080 {
		t.Errorf("v4: got %s:%d", addr, port)
	}
	addr, port = parseAddr("B80D01AC:1F90", "tcp")
	if addr != "172.1.13.184" || port != 8080 {
		t.Errorf("v4 ac: got %s:%d", addr, port)
	}
	addr, _ = parseAddr("00000000000000000000000001000000:1F90", "tcp6")
	if addr != "0000:0000:0000:0000:0000:0000:0000:0001" {
		t.Errorf("v6 ::1: got %s", addr)
	}
}

type netrec struct {
	evs []ConnEvent
}

func (r *netrec) NetEvent(e ConnEvent) { r.evs = append(r.evs, e) }

// fakeNetProc builds /proc/net tables under root for one listener and one
// connection.
func fakeNetProc(t *testing.T, root string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 100 1 0
   1: 0100007F:1F90 0100007F:D431 01 00000000:00000000 02:00000000 00000000  1000        0 200 1 0
`
	udp := `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  10: 0100007F:2000 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 300 2 0 0
`
	if err := os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(tcp), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "net", "udp"), []byte(udp), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fakePIDSocket makes root/<pid>/fd/3 a symlink to socket:[ino] and writes
// the comm.
func fakePIDSocket(t *testing.T, root string, pid int, ino uint64, comm string) {
	t.Helper()
	d := filepath.Join(root, fmt.Sprint(pid), "fd")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, fmt.Sprint(pid), "comm"), []byte(comm+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fmt.Sprintf("socket:[%d]", ino), filepath.Join(d, "3")); err != nil {
		t.Fatal(err)
	}
}

func TestListenerAndConnection(t *testing.T) {
	root := t.TempDir()
	fakeNetProc(t, root)
	fakePIDSocket(t, root, 500, 100, "sshd")
	fakePIDSocket(t, root, 501, 200, "curl")

	r := &netrec{}
	m := New(r, root)
	m.interval = 20 * time.Millisecond

	// baseline: no events
	m.sample(true)
	if len(r.evs) != 0 {
		t.Fatalf("baseline emitted: %v", r.evs)
	}

	// add a new connection
	f, err := os.OpenFile(filepath.Join(root, "net", "tcp"), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(f, "   2: 0100007F:1F90 0100007F:D432 01 00000000:00000000 02:00000000 00000000  1000        0 400 1 0")
	f.Close()
	fakePIDSocket(t, root, 502, 400, "nc")

	m.sample(false)
	if len(r.evs) != 1 {
		t.Fatalf("want 1 new event, got %v", r.evs)
	}
	e := r.evs[0]
	if e.Kind != "connection_new" || e.LAddr != "127.0.0.1" || e.LPort != 8080 ||
		e.RAddr != "127.0.0.1" || e.RPort != 54322 || e.State != "ESTABLISHED" ||
		e.PID != 502 || e.Comm != "nc" {
		t.Fatalf("bad event: %+v", e)
	}

	// drop the connection: gone event
	f, _ = os.OpenFile(filepath.Join(root, "net", "tcp"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	fmt.Fprintln(f, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode")
	fmt.Fprintln(f, "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 100 1 0")
	f.Close()
	before := len(r.evs)
	m.sample(false)
	if len(r.evs) != before+2 {
		t.Fatalf("want 2 connection_gone, got %v", r.evs[before:])
	}
	for _, e := range r.evs[before:] {
		if e.Kind != "connection_gone" {
			t.Fatalf("want connection_gone, got %v", e)
		}
	}
}


func TestRunStops(t *testing.T) {
	root := t.TempDir()
	fakeNetProc(t, root)
	r := &netrec{}
	m := New(r, root)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := m.Run(ctx); err != nil {
		t.Fatal(err)
	}
}
