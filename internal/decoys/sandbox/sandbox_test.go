package sandbox

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PurdueBlueTeam/phylax/internal/decoys"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/honeytokens"
)

// The test binary doubles as the decoy child: the module re-executes
// os.Executable() with ChildEnv set.
func TestMain(m *testing.M) {
	MaybeRunChild()
	os.Exit(m.Run())
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

type collector struct {
	mu  sync.Mutex
	evs []event.Event
}

func (c *collector) emit(e event.Event) error {
	c.mu.Lock()
	c.evs = append(c.evs, e)
	c.mu.Unlock()
	return nil
}

func (c *collector) wait(t *testing.T, pred func(event.Event) bool) event.Event {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		for _, e := range c.evs {
			if pred(e) {
				c.mu.Unlock()
				return e
			}
		}
		c.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("event never arrived")
	return event.Event{}
}

func start(t *testing.T, o Options) (*Module, *collector, context.CancelFunc, chan error) {
	t.Helper()
	if o.User == "" {
		o.User = "-" // tests are not root; see TestChildDropsRoot for the real drop
	}
	m, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	col := &collector{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Start(ctx, col.emit) }()
	select {
	case <-m.Ready():
	case err := <-done:
		cancel()
		t.Fatalf("module ended before ready: %v", err)
	case <-time.After(15 * time.Second):
		cancel()
		t.Fatal("child never became ready")
	}
	t.Cleanup(cancel)
	return m, col, cancel, done
}

func TestChildServesDecoyAndRelaysEvents(t *testing.T) {
	port := freePort(t)
	m, col, cancel, done := start(t, Options{Spec: Spec{Host: "rocky-ecom", Bind: "127.0.0.1",
		Listeners: []decoys.Listener{{Kind: decoys.KindRedis, Port: port}},
		Tokens:    []honeytokens.Token{{ID: "ht-1", Host: "ubuntu-email", Kind: honeytokens.KindDBCred, User: "svc_a1", Secret: "Falcon!Secret77"}}}})
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "AUTH Falcon!Secret77\r\n")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = bufio.NewReader(c).ReadString('\n')
	c.Close()
	e := col.wait(t, func(e event.Event) bool {
		return e.Kind == decoys.KindHit && e.Fields["honeytoken"] == "ht-1"
	})
	if e.Fields["token_origin"] != "ubuntu-email" {
		t.Errorf("token origin lost across the process boundary: %v", e.Fields)
	}
	if m.PID() == 0 || m.PID() == os.Getpid() {
		t.Errorf("decoys must run in a separate process (child pid %d, ours %d)", m.PID(), os.Getpid())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("clean stop returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("module did not stop")
	}
}

func TestChildHasNoNewPrivsAndStopsWithParent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("no_new_privs is Linux only")
	}
	m, _, cancel, done := start(t, Options{Spec: Spec{Host: "h", Bind: "127.0.0.1",
		Listeners: []decoys.Listener{{Kind: decoys.KindRedis, Port: freePort(t)}}}})
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", m.PID()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "NoNewPrivs:\t1") {
		t.Errorf("child lacks no_new_privs:\n%s", b)
	}
	pid := m.PID()
	cancel()
	<-done
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("child %d outlived the module", pid)
}

func TestChildDropsRoot(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("needs root to prove the credential drop (the agent runs as root; this machine's tests do not)")
	}
	m, _, cancel, _ := start(t, Options{User: "nobody", Spec: Spec{Host: "h", Bind: "127.0.0.1",
		Listeners: []decoys.Listener{{Kind: decoys.KindRedis, Port: freePort(t)}}}})
	defer cancel()
	b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", m.PID()))
	var uidLine, groups string
	for _, l := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(l, "Uid:"):
			uidLine = l
		case strings.HasPrefix(l, "Groups:"):
			groups = strings.TrimSpace(strings.TrimPrefix(l, "Groups:"))
		}
	}
	if !m.Dropped() || strings.Contains(uidLine, "\t0\t") || strings.HasSuffix(uidLine, "\t0") {
		t.Errorf("child still root: %q", uidLine)
	}
	if groups != "" {
		t.Errorf("supplementary groups kept: %q", groups)
	}
}

func TestScoredPortRefusedBeforeBinding(t *testing.T) {
	_, err := New(Options{Spec: Spec{Listeners: []decoys.Listener{{Kind: decoys.KindSSH, Port: 22}}, ScoredPorts: []uint16{22}}})
	if err == nil {
		t.Fatal("scored port accepted")
	}
}

func TestPersistentSSHHostKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, HostKeyFile)
	a, err := LoadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("host key changed between loads")
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
			t.Errorf("host key mode %v", fi.Mode())
		}
	}
	// A damaged key is an error, never silently replaced.
	if err := os.WriteFile(path, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateHostKey(path); err == nil {
		t.Fatal("damaged key was accepted or replaced")
	}
}

func TestSSHDecoyPresentsPersistedKeyAcrossRestarts(t *testing.T) {
	pemBytes, err := LoadOrCreateHostKey(filepath.Join(t.TempDir(), HostKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := Signer(pemBytes)
	want := ssh.FingerprintSHA256(signer.PublicKey())
	for range 2 { // two child lifetimes
		port := freePort(t)
		_, _, cancel, done := start(t, Options{Spec: Spec{Host: "h", Bind: "127.0.0.1", HostKeyPEM: string(pemBytes),
			Listeners: []decoys.Listener{{Kind: decoys.KindSSH, Port: port}}}})
		var got string
		_, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password("x")},
			HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error { got = ssh.FingerprintSHA256(k); return nil },
			Timeout:         5 * time.Second})
		_ = err // the login is refused; the host key was seen
		if got != want {
			t.Errorf("host key %s, want persisted %s", got, want)
		}
		cancel()
		<-done
	}
}
