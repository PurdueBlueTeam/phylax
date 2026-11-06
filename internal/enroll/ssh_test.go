package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	phyagent "github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/svcinstall"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
	"golang.org/x/crypto/ssh"
)

// sshCmd is one exec request a fake server saw.
type sshCmd struct {
	cmd   string
	stdin []byte
}

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
	corrupt  bool // flip a byte of the uploaded binary
	install  int  // exit status of the install command
	installE string
	enforce  string
	onInstal func()
	rmExit   int // exit status of the cleanup rm -rf

	logins   int
	fails    int
	cmds     []sshCmd
	uploaded []byte
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
	var stdin []byte
	var decoded []byte
	if strings.Contains(cmd, "base64 -d") {
		stdin, _ = io.ReadAll(ch)
		decoded, _ = base64.StdEncoding.DecodeString(strings.ReplaceAll(string(stdin), "\n", ""))
	}
	s.mu.Lock()
	s.cmds = append(s.cmds, sshCmd{cmd: cmd, stdin: stdin})
	if strings.Contains(cmd, "base64 -d") && !strings.Contains(cmd, "boot.json") && !strings.Contains(cmd, "name.key") {
		if s.corrupt && len(decoded) > 0 {
			decoded[0] ^= 0xff
		}
		s.uploaded = decoded
	}
	switch {
	case cmd == "echo PHYLAXOK" && s.hang:
		s.mu.Unlock()
		time.Sleep(5 * time.Second) // hold the channel until the client gives up
		return
	case cmd == "echo PHYLAXOK":
		out := s.sentinel
		s.mu.Unlock()
		io.WriteString(ch, out)
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return
	case cmd == "hostname -s":
		out := s.hostname + "\n"
		s.mu.Unlock()
		io.WriteString(ch, out)
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return
	case strings.HasPrefix(cmd, "sha256sum "):
		sum := sha256.Sum256(s.uploaded)
		out := hex.EncodeToString(sum[:]) + "  " + strings.TrimSpace(strings.TrimPrefix(cmd, "sha256sum ")) + "\n"
		s.mu.Unlock()
		io.WriteString(ch, out)
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return
	case strings.HasPrefix(cmd, "df -Pk"):
		out := s.dfOut
		s.mu.Unlock()
		io.WriteString(ch, out)
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return
	case cmd == "getenforce":
		out := s.enforce + "\n"
		s.mu.Unlock()
		io.WriteString(ch, out)
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return
	case strings.Contains(cmd, "agent install"):
		code, stderr, fn := s.install, s.installE, s.onInstal
		s.mu.Unlock()
		if fn != nil {
			fn()
		}
		if stderr != "" {
			io.WriteString(ch.Stderr(), stderr)
		}
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
		return
	case strings.HasPrefix(cmd, "rm -rf "):
		code := s.rmExit
		s.mu.Unlock()
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
		return
	default:
		s.mu.Unlock()
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return
	}
}

func (s *fakeSSH) commands() []sshCmd {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sshCmd(nil), s.cmds...)
}

func fakeSSHDefaults() *fakeSSH {
	return &fakeSSH{
		user: "root", pass: "pw", hostname: "h1", sentinel: "PHYLAXOK\n",
		dfOut: "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100000 1000 99000 2% /\n",
	}
}

func TestSSHPushInstalls(t *testing.T) {
	f := newEnroller(t)
	var connected atomic.Bool
	srv := fakeSSHDefaults()
	srv.onInstal = func() { connected.Store(true) }
	addr := startFakeSSH(t, srv)
	f.e.opt.Connected = func(h string) bool { return connected.Load() }

	bin := []byte("#!/bin/sh\necho this is the agent binary\n")
	secret := []byte("0123456789abcdef")
	hk, err := OpenHostKeys(filepath.Join(f.dir, "known_hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	p := &SSHPusher{Binary: bin, Controller: "10.0.0.5:7443", NameSecret: secret,
		HostKeys: hk, Timeout: 5 * time.Second}
	tgt := Target{Host: "h1", Addr: addr, User: "root", Pass: vault.NewSecretString("pw"), Hostname: "h1"}
	if err := p.Push(context.Background(), f.e, tgt); err != nil {
		t.Fatalf("Push: %v", err)
	}

	cmds := srv.commands()
	var installCmd string
	var bundle *phyagent.Bundle
	foundBin := false
	for _, c := range cmds {
		if strings.Contains(c.cmd, "base64 -d") && strings.Contains(c.cmd, ".tmp") {
			raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(c.stdin), "\n", ""))
			if err != nil {
				t.Fatalf("upload stdin is not base64: %v", err)
			}
			if strings.Contains(c.cmd, "boot.json") {
				bundle, err = phyagent.ParseBundle(raw)
				if err != nil {
					t.Fatalf("bundle upload does not parse: %v\n%s", err, raw)
				}
			} else if string(raw) == string(bin) {
				foundBin = true
			}
		}
		if strings.Contains(c.cmd, "agent install --bootstrap") {
			installCmd = c.cmd
		}
	}
	if !foundBin {
		t.Fatalf("no upload command carried the binary exactly: %+v", cmds)
	}
	if bundle == nil || bundle.Host != "h1" || bundle.Token == "" {
		t.Fatalf("uploaded bundle = %+v", bundle)
	}
	if !strings.Contains(installCmd, "agent install --bootstrap") {
		t.Fatalf("no install command: %+v", cmds)
	}
	if !strings.Contains(installCmd, "--secret-file") {
		t.Errorf("install command does not use --secret-file: %q", installCmd)
	}
	if strings.Contains(installCmd, "--secret ") {
		t.Errorf("install command carries --secret: %q", installCmd)
	}
	var secretHex string
	for _, c := range cmds {
		if strings.Contains(c.cmd, "name.key") && strings.Contains(c.cmd, "base64 -d") {
			secretHex = strings.TrimSpace(string(mustDecode(t, c.stdin)))
		}
	}
	if secretHex != hex.EncodeToString(secret) {
		t.Errorf("secret upload = %q, want %q", secretHex, hex.EncodeToString(secret))
	}
	for _, c := range cmds {
		if strings.Contains(c.cmd, "pw") {
			t.Errorf("a command line carries the password: %q", c.cmd)
		}
		if strings.Contains(c.cmd, bundle.Token) {
			t.Errorf("a command line carries the token: %q", c.cmd)
		}
		if strings.Contains(c.cmd, secretHex) {
			t.Errorf("a command line carries the name secret: %q", c.cmd)
		}
	}
}

func mustDecode(t *testing.T, b []byte) []byte {
	t.Helper()
	out, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(b), "\n", ""))
	if err != nil {
		t.Fatalf("not base64: %v", err)
	}
	return out
}

func TestSSHPushHashMismatchExecutesNothing(t *testing.T) {
	f := newEnroller(t)
	srv := fakeSSHDefaults()
	srv.corrupt = true
	addr := startFakeSSH(t, srv)
	hk, err := OpenHostKeys(filepath.Join(f.dir, "known_hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	p := &SSHPusher{Binary: []byte("#!/bin/sh\necho the real agent\n"), Controller: "10.0.0.5:7443",
		NameSecret: []byte("0123456789abcdef"), HostKeys: hk, Timeout: 5 * time.Second}
	tgt := Target{Host: "h1", Addr: addr, User: "root", Pass: vault.NewSecretString("pw"), Hostname: "h1"}
	err = p.Push(context.Background(), f.e, tgt)
	var pe *PushError
	if !errors.As(err, &pe) || pe.Class != ClassHashMismatch {
		t.Fatalf("err = %v, want class %s", err, ClassHashMismatch)
	}
	for _, c := range srv.commands() {
		if strings.Contains(c.cmd, "agent install") {
			t.Fatalf("a corrupted binary was installed: %q", c.cmd)
		}
	}
}

func TestSSHPushFailedInstallRemovesDir(t *testing.T) {
	for _, tc := range []struct {
		rmExit int
		want   string
	}{{0, " removed"}, {1, " NOT removed"}} {
		f := newEnroller(t)
		srv := fakeSSHDefaults()
		srv.install, srv.installE, srv.rmExit = 1, "boom\n", tc.rmExit
		addr := startFakeSSH(t, srv)
		secret := []byte("0123456789abcdef")
		p := &SSHPusher{Binary: []byte("bin"), Controller: "10.0.0.5:7443",
			NameSecret: secret, Timeout: 5 * time.Second}
		tgt := Target{Host: "h1", Addr: addr, User: "root", Pass: vault.NewSecretString("pw"), Hostname: "h1"}
		err := p.Push(context.Background(), f.e, tgt)
		var pe *PushError
		if !errors.As(err, &pe) || pe.Class != ClassInstall {
			t.Fatalf("err = %v, want class %s", err, ClassInstall)
		}
		dir := "/opt/" + svcinstall.DeriveNames(secret).Dir
		cmds := srv.commands()
		if last := cmds[len(cmds)-1].cmd; last != "rm -rf '"+dir+"'" {
			t.Fatalf("last command = %q, want the install dir removed", last)
		}
		if !strings.Contains(pe.Detail, "install dir "+dir+tc.want) {
			t.Errorf("rm exit %d: detail = %q, want %q", tc.rmExit, pe.Detail, tc.want)
		}
	}
}

func TestSSHPushHostnameMismatchUploadsNothing(t *testing.T) {
	f := newEnroller(t)
	srv := fakeSSHDefaults()
	srv.hostname = "other"
	addr := startFakeSSH(t, srv)
	hk, err := OpenHostKeys(filepath.Join(f.dir, "known_hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	p := &SSHPusher{Binary: []byte("bin"), Controller: "10.0.0.5:7443",
		NameSecret: []byte("0123456789abcdef"), HostKeys: hk, Timeout: 5 * time.Second}
	tgt := Target{Host: "h1", Addr: addr, User: "root", Pass: vault.NewSecretString("pw"), Hostname: "h1"}
	err = p.Push(context.Background(), f.e, tgt)
	var pe *PushError
	if !errors.As(err, &pe) || pe.Class != ClassHostname {
		t.Fatalf("err = %v, want class %s", err, ClassHostname)
	}
	for _, c := range srv.commands() {
		if strings.Contains(c.cmd, "base64 -d") {
			t.Fatalf("a mismatched hostname still uploaded: %q", c.cmd)
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
			f := newEnroller(t)
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
			p := &SSHPusher{Binary: []byte("bin"), Controller: "10.0.0.5:7443",
				NameSecret: []byte("0123456789abcdef"), HostKeys: hk, Timeout: 300 * time.Millisecond}
			tgt := Target{Host: "h1", Addr: addr, User: "root", Pass: vault.NewSecretString("pw"), Hostname: "h1"}
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
