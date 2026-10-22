package decoys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/PurdueBlueTeam/phylax/pools"
)

var (
	hostKeyOnce sync.Once
	hostKey     ssh.Signer
	hostKeyErr  error
)

func sshHostKey() (ssh.Signer, error) {
	hostKeyOnce.Do(func() {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			hostKeyErr = err
			return
		}
		hostKey, hostKeyErr = ssh.NewSignerFromKey(priv)
	})
	return hostKey, hostKeyErr
}

// serveSSH speaks real SSH (so scanners and ssh clients negotiate normally),
// accepts a login after AcceptAfter password attempts or on a honey credential
// or key, and gives a fake shell. Exec requests are answered by the fake shell
// too: nothing is run.
func (m *Module) serveSSH(ctx context.Context, s *sess, c net.Conn) {
	signer, err := sshHostKey()
	if err != nil {
		return
	}
	banners := pools.Lines("ssh_banners.txt")
	banner := strings.TrimPrefix(banners[m.bannerIdx%len(banners)], "SSH-2.0-")
	var lastFP string
	cfg := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-" + banner,
		MaxAuthTries:  m.cfg.MaxAuthAttempts,
		PasswordCallback: func(cm ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			_, matched := s.credential(cm.User(), string(pw), "password")
			s.mu.Lock()
			n := s.attempts
			s.mu.Unlock()
			if matched || n >= m.cfg.AcceptAfter {
				return &ssh.Permissions{}, nil
			}
			s.pause()
			return nil, errors.New("permission denied")
		},
		PublicKeyCallback: func(cm ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			fp := ssh.FingerprintSHA256(key)
			if fp != lastFP { // the library calls back for the query and again for the signed attempt
				lastFP = fp
				if _, ok := s.fingerprintUse(cm.User(), fp); ok {
					return &ssh.Permissions{}, nil
				}
			} else if s.matchedFP(fp) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("permission denied")
		},
	}
	cfg.AddHostKey(signer)
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	user := sc.User()
	var wg sync.WaitGroup
	defer wg.Wait()
	nch := 0
	for nc := range chans {
		nch++
		if nc.ChannelType() != "session" || nch > 4 {
			_ = nc.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer ch.Close()
			m.sshSession(s, sc, ch, creqs, user)
		}()
	}
}

func (s *sess) matchedFP(fp string) bool {
	if s.m.cfg.Tokens == nil {
		return false
	}
	_, ok := s.m.cfg.Tokens.MatchFingerprint(fp)
	return ok
}

func (m *Module) sshSession(s *sess, sc *ssh.ServerConn, ch ssh.Channel, reqs <-chan *ssh.Request, user string) {
	sh := NewShell(m.cfg.Host, safeUser(user))
	started := false
	for r := range reqs {
		switch r.Type {
		case "pty-req", "env", "window-change", "signal":
			_ = r.Reply(true, nil)
		case "shell":
			_ = r.Reply(!started, nil)
			if started {
				continue
			}
			started = true
			go func() {
				defer ch.Close()
				_, _ = io.WriteString(ch, crlf("Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)\n\nLast login: Tue Mar  5 09:58:17 2024 from 10.0.0.5\n"))
				m.shellLoop(s, ch, sh)
				_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
				_ = sc.Close()
			}()
		case "exec":
			var p struct{ Command string }
			if err := ssh.Unmarshal(r.Payload, &p); err != nil {
				_ = r.Reply(false, nil)
				continue
			}
			_ = r.Reply(true, nil)
			if s.command(p.Command) {
				s.pause()
				out, _ := sh.Run(p.Command)
				_, _ = io.WriteString(ch, crlf(out))
			}
			_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
			_ = ch.Close()
		case "subsystem":
			var p struct{ Name string }
			_ = ssh.Unmarshal(r.Payload, &p)
			s.command("subsystem:" + trunc(p.Name, 32))
			_ = r.Reply(false, nil)
		default:
			_ = r.Reply(false, nil)
		}
	}
}

// safeUser keeps the shell prompt user to a plain account name.
func safeUser(u string) string {
	out := make([]byte, 0, len(u))
	for i := 0; i < len(u) && len(out) < 32; i++ {
		c := u[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return "root"
	}
	return string(out)
}
