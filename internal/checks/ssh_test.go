package checks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type sshSrv struct {
	mu       sync.Mutex
	logins   int
	fails    int
	versions []string
	ciphers  [][]string
	pty      []ptyReq
	cmds     []string
	noPTY    bool          // refuse pty-req
	slow     time.Duration // delay before echoing the command
	password string
}

type ptyReq struct {
	term string
	w, h uint32
}

func startSSH(t *testing.T, s *sshSrv) (string, int) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := ssh.NewSignerFromKey(k)
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.versions = append(s.versions, string(c.ClientVersion()))
			if string(pw) == s.password && c.User() == "alice" {
				s.logins++
				return nil, nil
			}
			s.fails++
			return nil, fmt.Errorf("denied")
		},
	}
	cfg.AddHostKey(signer)
	return listenSSH(t, cfg, s)
}

func listenSSH(t *testing.T, cfg *ssh.ServerConfig, s *sshSrv) (string, int) {
	return listen2(t, func(c net.Conn) {
		sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
		if err != nil {
			return
		}
		defer sc.Close()
		go ssh.DiscardRequests(reqs)
		for nc := range chans {
			if nc.ChannelType() != "session" {
				nc.Reject(ssh.UnknownChannelType, "no")
				continue
			}
			ch, creqs, _ := nc.Accept()
			go serveSession(s, ch, creqs)
		}
	})
}

func listen2(t *testing.T, h func(net.Conn)) (string, int) { return listen(t, h) }

func serveSession(s *sshSrv, ch ssh.Channel, reqs <-chan *ssh.Request) {
	hasPTY := false
	for r := range reqs {
		switch r.Type {
		case "pty-req":
			if s.noPTY {
				r.Reply(false, nil)
				continue
			}
			var p struct {
				Term         string
				W, H, PW, PH uint32
				Modes        string
			}
			ssh.Unmarshal(r.Payload, &p)
			s.mu.Lock()
			s.pty = append(s.pty, ptyReq{p.Term, p.W, p.H})
			s.mu.Unlock()
			hasPTY = true
			r.Reply(true, nil)
		case "shell":
			if !hasPTY {
				r.Reply(false, nil)
				continue
			}
			r.Reply(true, nil)
			go func() {
				ch.Write([]byte("Welcome\r\n$ "))
				buf := make([]byte, 256)
				n, err := ch.Read(buf)
				if err != nil {
					return
				}
				cmd := strings.TrimSpace(string(buf[:n]))
				s.mu.Lock()
				s.cmds = append(s.cmds, cmd)
				s.mu.Unlock()
				time.Sleep(s.slow)
				switch cmd {
				case "hostname":
					ch.Write([]byte("sshbox\r\n$ "))
				default:
					ch.Write([]byte(cmd + ": command not found\r\n$ "))
				}
			}()
		default:
			r.Reply(false, nil)
		}
	}
}

func TestSSHScorerBehaviour(t *testing.T) {
	s := &sshSrv{password: "pw"}
	h, p := startSSH(t, s)
	spec := Spec{Type: SSH, Host: h, Port: p}
	good := cred("alice", "pw")
	to := 800 * time.Millisecond // Timeout/8 = 100ms

	start := time.Now()
	r := runOne(spec, &Item{Command: "hostname", Contains: true, Output: "sshbox"}, &good, Options{Timeout: to})
	if !r.OK {
		t.Fatalf("%+v", r)
	}
	if el := time.Since(start); el < 100*time.Millisecond {
		t.Errorf("must wait Timeout/8 before reading, finished in %v", el)
	}
	s.mu.Lock()
	if len(s.pty) != 1 || s.pty[0] != (ptyReq{"xterm", 80, 40}) {
		t.Errorf("pty-req %+v, want xterm 80 cols x 40 rows", s.pty)
	}
	if len(s.cmds) != 1 || s.cmds[0] != "hostname" {
		t.Errorf("typed command %v", s.cmds)
	}
	if !strings.HasPrefix(s.versions[0], "SSH-2.0-") {
		t.Errorf("version %q", s.versions[0])
	}
	s.mu.Unlock()

	// wrong output / regex
	if r = runOne(spec, &Item{Command: "hostname", Contains: true, Output: "other"}, &good, Options{Timeout: to}); r.OK || r.Class != ClassContent {
		t.Fatalf("%+v", r)
	}
	if r = runOne(spec, &Item{Command: "hostname", UseRegex: true, Output: `ssh\w+`}, &good, Options{Timeout: to}); !r.OK {
		t.Fatalf("%+v", r)
	}
	// stderr is merged under the PTY, so a failing command passes in the default branch; strict catches it
	nf := Item{Command: "nosuchcmd"}
	if r = runOne(spec, &nf, &good, Options{Timeout: to}); !r.OK {
		t.Fatalf("scorer passes a command that errors: %+v", r)
	}
	if r = runOne(spec, &nf, &good, Options{Timeout: to, Strict: true}); r.OK || !r.ScorerOK {
		t.Fatalf("strict must reject it: %+v", r)
	}
	// bad password: auth class, password never in the result
	bad := cred("alice", "hunter2-secret")
	r = runOne(spec, nil, &bad, Options{Timeout: to})
	if r.OK || r.Class != ClassAuth {
		t.Fatalf("%+v", r)
	}
	if strings.Contains(r.Err+r.Debug, "hunter2-secret") {
		t.Error("password leaked into the result")
	}
	// login only (no command): shell is still required
	if r = runOne(spec, nil, &good, Options{Timeout: to}); !r.OK {
		t.Fatalf("%+v", r)
	}
	// no credential is a config error
	if r = runOne(spec, nil, nil, Options{Timeout: to}); r.Class != ClassConfig {
		t.Fatalf("%+v", r)
	}
}

func TestSSHPTYRefusedAndSlowProfile(t *testing.T) {
	s := &sshSrv{password: "pw", noPTY: true}
	h, p := startSSH(t, s)
	good := cred("alice", "pw")
	r := runOne(Spec{Type: SSH, Host: h, Port: p}, nil, &good, Options{Timeout: 800 * time.Millisecond})
	if r.OK || !strings.Contains(r.Err, "pts") {
		t.Fatalf("PermitTTY no must fail: %+v", r)
	}
	// a shell that answers after Timeout/8 misses the read, like the scorer
	s2 := &sshSrv{password: "pw", slow: 500 * time.Millisecond}
	h2, p2 := startSSH(t, s2)
	r = runOne(Spec{Type: SSH, Host: h2, Port: p2}, &Item{Command: "hostname", Contains: true, Output: "sshbox"}, &good, Options{Timeout: 800 * time.Millisecond})
	if r.OK || r.Class != ClassContent {
		t.Fatalf("slow profile must miss the read: %+v", r)
	}
}

func TestSSHBadAttemptsOffByDefault(t *testing.T) {
	s := &sshSrv{password: "pw"}
	h, p := startSSH(t, s)
	spec := Spec{Type: SSH, Host: h, Port: p}
	good := cred("alice", "pw")
	if r := runOne(spec, nil, &good, Options{Timeout: 800 * time.Millisecond}); !r.OK {
		t.Fatalf("%+v", r)
	}
	s.mu.Lock()
	if s.fails != 0 {
		t.Errorf("badattempts must be off by default, saw %d failures", s.fails)
	}
	s.mu.Unlock()
	if r := runOne(spec, nil, &good, Options{Timeout: 800 * time.Millisecond, BadAttempts: 3}); !r.OK {
		t.Fatalf("%+v", r)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fails != 3 || s.logins != 2 {
		t.Errorf("fails=%d logins=%d", s.fails, s.logins)
	}
	if len(s.versions) != 5 { // 1 + (3+1)
		t.Errorf("versions %v", s.versions)
	}
}
