package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/svcinstall"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
	"golang.org/x/crypto/ssh"
)

// fakeSSH is an in-process SSH server that answers a fixed script. It is the
// network edge the pusher does not own; everything below it is real code.
type fakeSSH struct {
	mu       sync.Mutex
	user     string
	pass     string
	version  string
	hostname string
	dfOut    string
	sentinel string
	hang     bool // never answer the sentinel
	install  int  // exit status of the one-liner
	installE string
	enforce  string
	onInstal func()
	rmExit   int // exit status of the cleanup rm -rf

	logins int
	fails  int
	cmds   []string
}

func (s *fakeSSH) config() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			if c.User() == s.user && string(pw) == s.pass {
				s.logins++
				return nil, nil
			}
			s.fails++
			return nil, errors.New("denied")
		},
	}
	if s.version != "" {
		cfg.ServerVersion = s.version
	}
	return cfg
}

// startFakeSSH starts the fake server on 127.0.0.1 and returns its address.
func startFakeSSH(t *testing.T, s *fakeSSH) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	cfg := s.config()
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeSSH(s, c, cfg)
		}
	}()
	return ln.Addr().String()
}

func serveFakeSSH(s *fakeSSH, c net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go s.session(ch, creqs)
	}
}

func (s *fakeSSH) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for r := range reqs {
		if r.Type != "exec" {
			r.Reply(false, nil)
			continue
		}
		var p struct{ Command string }
		ssh.Unmarshal(r.Payload, &p)
		r.Reply(true, nil)
		s.exec(ch, p.Command)
		ch.Close()
		return
	}
}

func (s *fakeSSH) exec(ch ssh.Channel, cmd string) {
	reply := func(code uint32) {
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
	}
	s.mu.Lock()
	s.cmds = append(s.cmds, cmd)
	switch {
	case cmd == "echo PHYLAXOK" && s.hang:
		s.mu.Unlock()
		time.Sleep(5 * time.Second) // hold the channel until the client gives up
		return
	case cmd == "echo PHYLAXOK":
		out := s.sentinel
		s.mu.Unlock()
		io.WriteString(ch, out)
		reply(0)
		return
	case cmd == "hostname -s":
		out := s.hostname + "\n"
		s.mu.Unlock()
		io.WriteString(ch, out)
		reply(0)
		return
	case strings.HasPrefix(cmd, "df -Pk"):
		out := s.dfOut
		s.mu.Unlock()
		io.WriteString(ch, out)
		reply(0)
		return
	case cmd == "getenforce":
		out := s.enforce + "\n"
		s.mu.Unlock()
		io.WriteString(ch, out)
		reply(0)
		return
	case strings.Contains(cmd, "|sh"):
		code, stderr, fn := s.install, s.installE, s.onInstal
		s.mu.Unlock()
		if fn != nil {
			fn()
		}
		if stderr != "" {
			io.WriteString(ch.Stderr(), stderr)
		}
		reply(uint32(code))
		return
	case strings.HasPrefix(cmd, "rm -rf "):
		code := s.rmExit
		s.mu.Unlock()
		reply(uint32(code))
		return
	default:
		s.mu.Unlock()
		reply(0)
		return
	}
}

func (s *fakeSSH) commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.cmds...)
}

func fakeSSHDefaults() *fakeSSH {
	return &fakeSSH{
		user: "root", pass: "pw", hostname: "h1", sentinel: "PHYLAXOK\n",
		dfOut: "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100000 1000 99000 2% /\n",
	}
}

// newPushEnroller is a fresh Enroller whose release dir holds the fake release
// files the one-liner generator checks.
func newPushEnroller(t *testing.T) *enrFixture {
	t.Helper()
	f := newEnrollerWith(t, func(o *Options) { o.ReleaseDir = t.TempDir() })
	writeReleases(t, f.e.opt.ReleaseDir)
	return f
}

// tokenFromOneLiner returns the enrollment token in a Linux one-liner.
func tokenFromOneLiner(t *testing.T, line string) string {
	t.Helper()
	i, j := strings.Index(line, "/l/"), strings.LastIndex(line, "|sh")
	if i < 0 || j < i {
		t.Fatalf("not a Linux one-liner: %q", line)
	}
	return line[i+len("/l/") : j]
}

func pushTarget(addr string) Target {
	return Target{Host: "h1", Addr: addr, User: "root", Pass: vault.NewSecretString("pw"), Hostname: "h1"}
}

func TestSSHPushRunsOneLiner(t *testing.T) {
	f := newPushEnroller(t)
	var connected atomic.Bool
	srv := fakeSSHDefaults()
	srv.onInstal = func() { connected.Store(true) }
	addr := startFakeSSH(t, srv)
	f.e.opt.Connected = func(h string) bool { return h == "h1" && connected.Load() }
	hk, err := OpenHostKeys(filepath.Join(f.dir, "known_hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	const ctl = "10.0.0.5:7443"
	p := &SSHPusher{Controller: ctl, HostKeys: hk, Timeout: 5 * time.Second}
	if err := p.Push(context.Background(), f.e, pushTarget(addr)); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if !connected.Load() {
		t.Fatal("the fake never ran the one-liner")
	}

	cmds := srv.commands()
	var line string
	for _, c := range cmds {
		if strings.Contains(c, "|sh") {
			if line != "" {
				t.Fatalf("two one-liners: %q and %q", line, c)
			}
			line = c
		}
		for _, gone := range []string{"base64", "agent install", "--bootstrap", "sha256sum", "rm -rf"} {
			if strings.Contains(c, gone) {
				t.Errorf("command %q contains %q, which the push no longer does", c, gone)
			}
		}
		if strings.Contains(c, "pw") {
			t.Errorf("a command line carries the password: %q", c)
		}
	}
	if line == "" {
		t.Fatalf("the push ran no one-liner: %q", cmds)
	}
	tok := tokenFromOneLiner(t, line)
	if host, err := f.e.Tokens().Peek(tok); err != nil || host != "h1" {
		t.Fatalf("the one-liner token: host %q, err %v; want the live h1 token", host, err)
	}
	want, err := f.e.OneLiner(OSLinux, ctl, tok)
	if err != nil {
		t.Fatal(err)
	}
	if line != want {
		t.Fatalf("push ran\n%q\nwant the console one-liner\n%q", line, want)
	}
}

func TestSSHPushFailedInstallRemovesDir(t *testing.T) {
	for _, tc := range []struct {
		rmExit int
		want   string
	}{{0, " removed"}, {1, " NOT removed"}} {
		f := newPushEnroller(t)
		srv := fakeSSHDefaults()
		srv.install, srv.installE, srv.rmExit = 1, "boom\n", tc.rmExit
		addr := startFakeSSH(t, srv)
		p := &SSHPusher{Controller: "10.0.0.5:7443", Timeout: 5 * time.Second}
		err := p.Push(context.Background(), f.e, pushTarget(addr))
		var pe *PushError
		if !errors.As(err, &pe) || pe.Class != ClassInstall {
			t.Fatalf("err = %v, want class %s", err, ClassInstall)
		}
		cmds := srv.commands()
		var token string
		for _, c := range cmds {
			if strings.Contains(c, "|sh") {
				token = tokenFromOneLiner(t, c)
			}
		}
		if token == "" {
			t.Fatalf("no one-liner ran: %q", cmds)
		}
		dir := "/opt/" + svcinstall.DeriveNames([]byte(token)).Dir
		if last := cmds[len(cmds)-1]; last != "rm -rf '"+dir+"'" {
			t.Fatalf("last command = %q, want the install dir removed", last)
		}
		if !strings.Contains(pe.Detail, "install dir "+dir+tc.want) {
			t.Errorf("rm exit %d: detail = %q, want %q", tc.rmExit, pe.Detail, tc.want)
		}
	}
}

func TestSSHPushHostnameMismatchMintsNothing(t *testing.T) {
	f := newPushEnroller(t)
	srv := fakeSSHDefaults()
	srv.hostname = "other"
	addr := startFakeSSH(t, srv)
	hk, err := OpenHostKeys(filepath.Join(f.dir, "known_hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	p := &SSHPusher{Controller: "10.0.0.5:7443", HostKeys: hk, Timeout: 5 * time.Second}
	err = p.Push(context.Background(), f.e, pushTarget(addr))
	var pe *PushError
	if !errors.As(err, &pe) || pe.Class != ClassHostname {
		t.Fatalf("err = %v, want class %s", err, ClassHostname)
	}
	for _, c := range srv.commands() {
		if strings.Contains(c, "|sh") {
			t.Fatalf("a mismatched hostname still ran the one-liner: %q", c)
		}
	}
	if n := f.e.tokens.liveLocked(); n != 0 {
		t.Fatalf("a mismatched hostname minted %d token(s)", n)
	}
}

func TestSSHPushClasses(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*fakeSSH)
		tgt   func(string) Target
		want  Class
	}{
		{name: "auth_refused", setup: func(s *fakeSSH) {},
			tgt: func(a string) Target {
				return Target{Host: "h1", Addr: a, User: "root", Pass: vault.NewSecretString("bad"), Hostname: "h1"}
			},
			want: ClassAuth},
		{name: "timeout", setup: func(s *fakeSSH) { s.hang = true }, want: ClassTimeout},
		{name: "no_shell", setup: func(s *fakeSSH) { s.sentinel = "" }, want: ClassNoShell},
		{name: "no_space", setup: func(s *fakeSSH) {
			s.dfOut = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100000 99000 1024 99% /\n"
		}, want: ClassNoSpace},
		{name: "selinux_denial", setup: func(s *fakeSSH) {
			s.install, s.installE, s.enforce = 1, "Permission denied\n", "Enforcing"
		}, want: ClassSELinux},
		{name: "windows_openssh", setup: func(s *fakeSSH) {
			s.version = "SSH-2.0-OpenSSH_for_Windows_8.1"
		}, want: ClassWindowsSSH},
		{name: "no_heartbeat", setup: func(s *fakeSSH) {}, want: ClassNoHeartbeat},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newPushEnroller(t)
			srv := fakeSSHDefaults()
			if tc.setup != nil {
				tc.setup(srv)
			}
			addr := startFakeSSH(t, srv)
			if tc.name == "no_heartbeat" {
				f.e.opt.Connected = func(string) bool { return false }
			}
			hk, err := OpenHostKeys(filepath.Join(f.dir, "known_hosts.json"))
			if err != nil {
				t.Fatal(err)
			}
			p := &SSHPusher{Controller: "10.0.0.5:7443", HostKeys: hk, Timeout: 300 * time.Millisecond}
			tgt := pushTarget(addr)
			if tc.tgt != nil {
				tgt = tc.tgt(addr)
			}
			err = p.Push(context.Background(), f.e, tgt)
			var pe *PushError
			if !errors.As(err, &pe) {
				t.Fatalf("err = %v, want *PushError class %s", err, tc.want)
			}
			if pe.Class != tc.want {
				t.Fatalf("class = %s (%v), want %s", pe.Class, err, tc.want)
			}
			if pe.Next() == "" {
				t.Errorf("class %s has no next step", tc.want)
			}
		})
	}
}
