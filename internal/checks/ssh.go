package checks

import (
	"bytes"
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// The scorer picks a client banner at random from 27 strings; this is the
// same family (OpenSSH 7.4-9.7 variants, OpenSSH_for_Windows, PuTTY).
var sshBanners = []string{
	"OpenSSH_7.4", "OpenSSH_7.6p1 Ubuntu-4ubuntu0.7", "OpenSSH_7.9p1 Debian-10+deb10u2", "OpenSSH_8.0",
	"OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "OpenSSH_8.4p1 Debian-5+deb11u1", "OpenSSH_8.8", "OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
	"OpenSSH_9.0", "OpenSSH_9.2p1 Debian-2+deb12u1", "OpenSSH_9.3p1 Ubuntu-1ubuntu3", "OpenSSH_9.6", "OpenSSH_9.7",
	"OpenSSH_9.1 FreeBSD-20230316", "OpenSSH_for_Windows_7.7", "OpenSSH_for_Windows_8.1", "OpenSSH_for_Windows_8.6",
	"PuTTY_Release_0.79", "PuTTY_Release_0.81",
}

type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *safeBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func (p *probe) sshConfig(user, pass string, scorerCiphers bool) *ssh.ClientConfig {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		ClientVersion:   "SSH-2.0-" + sshBanners[p.rng.IntN(len(sshBanners))],
		Timeout:         p.opts.timeout(),
	}
	if scorerCiphers {
		cfg.Ciphers = append(ssh.SupportedAlgorithms().Ciphers, "3des-cbc")
	}
	return cfg
}

func (p *probe) sshConnect(ctx context.Context, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	c, err := p.dialSpec(ctx)
	if err != nil {
		return nil, err
	}
	sc, chans, reqs, err := ssh.NewClientConn(c, p.spec.addr(), cfg)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return ssh.NewClient(sc, chans, reqs), nil
}

func probeSSH(ctx context.Context, p *probe) error {
	if err := p.needCred(); err != nil {
		return err
	}
	user := p.userAt()
	// BadAttempts (off by default): N extra full connections with a random
	// password, own banner and the default cipher list, before the real login.
	for range p.opts.BadAttempts {
		cl, err := p.sshConnect(ctx, p.sshConfig(user, randHex(p.rng, 16), false))
		if err == nil {
			_ = cl.Close()
		} else if isNetErr(err) {
			return classify(err, "connection error")
		}
	}
	cfg := p.sshConfig(user, p.cred.Pass.Reveal(), true)
	cl, err := p.sshConnect(ctx, cfg)
	if err != nil {
		if f, ok := err.(*failure); ok {
			return f
		}
		if isNetErr(err) {
			return classify(err, "connection error")
		}
		return failDebug(ClassAuth, err.Error(), "error logging in to ssh server")
	}
	defer cl.Close()
	p.step("login")
	sess, err := cl.NewSession()
	if err != nil {
		return failDebug(ClassProtocol, err.Error(), "couldn't create session")
	}
	defer sess.Close()
	// pty-req xterm, 40 rows x 80 columns, ECHO off, 14400 baud.
	modes := ssh.TerminalModes{ssh.ECHO: 0, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := sess.RequestPty("xterm", 40, 80, modes); err != nil {
		return failDebug(ClassProtocol, err.Error(), "couldn't allocate pts: pty-req failed")
	}
	var stdout, stderr safeBuf
	sess.Stdout, sess.Stderr = &stdout, &stderr
	stdin, err := sess.StdinPipe()
	if err != nil {
		return failDebug(ClassProtocol, err.Error(), "failed to start shell")
	}
	if err := sess.Shell(); err != nil {
		return failDebug(ClassProtocol, err.Error(), "failed to start shell")
	}
	p.step("shell")
	if p.item.Command != "" {
		if _, err := stdin.Write([]byte(p.item.Command + "\n")); err != nil {
			return failDebug(ClassProtocol, err.Error(), "failed to write command")
		}
	}
	// Timeout/8 before reading, exactly like the scorer; a slow profile that
	// misses it fails there too.
	wait := p.opts.timeout() / 8
	if p.opts.Sleep != nil {
		p.opts.Sleep(ctx, wait)
	} else {
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
	}
	p.step("wait")
	out := stdout.String()
	switch {
	case p.item.Command == "" && p.item.Output == "":
		// login + PTY + shell is the whole check
	case p.item.UseRegex:
		re, err := regexp.Compile(p.item.Output)
		if err != nil {
			return fail(ClassConfig, "bad regex: %v", err)
		}
		if !re.MatchString(out) {
			return failDebug(ClassContent, out, "command output didn't match regex")
		}
	case p.item.Contains:
		if !strings.Contains(out, p.item.Output) {
			return failDebug(ClassContent, out, "command output didn't contain string")
		}
	default:
		// Quotient: stderr must be empty, but under a PTY stderr is merged
		// into stdout, so this branch can never fail.
		if stderr.String() != "" {
			return failDebug(ClassContent, stderr.String(), "command wrote to stderr")
		}
		if p.strict() {
			if p.item.Output != "" && !strings.Contains(out, p.item.Output) {
				p.strictIssue("output does not contain the expected string")
			}
			if p.item.Output == "" && p.item.Command != "" {
				l := strings.ToLower(out)
				if strings.TrimSpace(out) == "" {
					p.strictIssue("command produced no output")
				}
				if strings.Contains(l, "command not found") || strings.Contains(l, "no such file") || strings.Contains(l, "not recognized") {
					p.strictIssue("command output looks like an error")
				}
			}
		}
	}
	return nil
}

func isNetErr(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	m := err.Error()
	return strings.Contains(m, "connection refused") || strings.Contains(m, "i/o timeout") ||
		strings.Contains(m, "connection reset") || strings.Contains(m, "no route")
}
