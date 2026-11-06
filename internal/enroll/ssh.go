package enroll

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/svcinstall"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
	"golang.org/x/crypto/ssh"
)

const (
	maxCommandOut = 64 << 10 // any single command's stdout/stderr
	pushRoot      = "/opt"   // the Linux one-liner's default install root
	// pushNeedBytes is the space the one-liner needs below pushRoot: the
	// release (at most 64 MiB, the bootstrap handler's bound) plus the boot
	// config and slack.
	pushNeedBytes = 80 << 20
)

// Target is one host the SSH push installs the agent on.
type Target struct {
	Host     string // manifest name
	Addr     string // host:port for ssh (default port 22)
	User     string
	Pass     vault.Secret
	Hostname string // expected `hostname -s`, normally Host
}

// SSHPusher installs the Linux agent over SSH with password auth. It runs the
// pinned console one-liner through the shell channel, so the host downloads
// the binary and the bootstrap config itself (design S2: one install path).
type SSHPusher struct {
	Controller string // host:port as the host sees the controller
	HostKeys   *HostKeys
	Timeout    time.Duration                                           // per host, default 30s
	Dial       func(context.Context, string, string) (net.Conn, error) // tests; nil means net.Dialer
}

// Push installs the agent on t. Every failure is a *PushError with a class.
func (p *SSHPusher) Push(ctx context.Context, e *Enroller, t Target) error {
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if t.Hostname == "" {
		t.Hostname = t.Host
	}
	fail := func(class Class, detail string) error {
		return &PushError{Host: t.Host, Class: class, Detail: vault.RedactString(detail, t.Pass)}
	}
	hk := p.HostKeys
	if hk == nil {
		hk = e.hostKeys
	}
	if hk == nil {
		return fail(ClassInstall, "known_hosts.json is not open")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cfg := &ssh.ClientConfig{
		User:            t.User,
		Auth:            []ssh.AuthMethod{ssh.Password(t.Pass.Reveal())},
		HostKeyCallback: hk.Callback(t.Host),
		ClientVersion:   "SSH-2.0-Phylax",
		Timeout:         timeout,
	}
	dial := p.Dial
	if dial == nil {
		d := &net.Dialer{}
		dial = d.DialContext
	}
	conn, err := dial(ctx, "tcp", t.Addr)
	if err != nil {
		if ctx.Err() != nil {
			return fail(ClassTimeout, "connect: "+err.Error())
		}
		return fail(ClassAuth, "connect: "+err.Error())
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, t.Addr, cfg)
	if err != nil {
		conn.Close()
		switch {
		case errors.Is(err, ErrHostKeyChanged):
			// Refused hard: a changed key may be a man in the middle.
			if e.opt.Alert != nil {
				e.opt.Alert(t.Host, event.ReasonKeyMismatch, err.Error())
			}
			return fail(ClassHostKey, err.Error())
		case ctx.Err() != nil:
			return fail(ClassTimeout, "handshake: "+err.Error())
		}
		return fail(ClassAuth, "handshake: "+err.Error())
	}
	client := ssh.NewClient(sc, chans, reqs)
	defer client.Close()
	if strings.Contains(string(sc.ServerVersion()), "Windows") {
		return fail(ClassWindowsSSH, string(sc.ServerVersion()))
	}

	out, errOut, code, err := runSSH(ctx, client, "echo PHYLAXOK")
	if ctx.Err() != nil {
		return fail(ClassTimeout, "shell sentinel")
	}
	if err != nil || code != 0 || !strings.Contains(out, "PHYLAXOK") {
		return fail(ClassNoShell, strings.TrimSpace(out+" "+errOut))
	}

	out, errOut, code, err = runSSH(ctx, client, "hostname -s")
	if ctx.Err() != nil {
		return fail(ClassTimeout, "hostname")
	}
	if err != nil || code != 0 {
		return fail(ClassNoShell, "hostname: "+strings.TrimSpace(errOut))
	}
	if got := strings.TrimSpace(out); got != t.Hostname {
		return fail(ClassHostname, fmt.Sprintf("host reports %q, manifest says %q", got, t.Hostname))
	}

	// Room for the download the one-liner makes, before a token exists.
	out, errOut, code, err = runSSH(ctx, client, "df -Pk "+pushRoot)
	if ctx.Err() != nil {
		return fail(ClassTimeout, "df")
	}
	if err != nil || code != 0 {
		return fail(ClassNoSpace, "df: "+strings.TrimSpace(errOut))
	}
	avail, ok := dfAvailableKiB(out)
	if !ok || avail*1024 < pushNeedBytes {
		return fail(ClassNoSpace, fmt.Sprintf("%d KiB available under %s, %d KiB needed", avail, pushRoot, pushNeedBytes>>10))
	}

	// Only now, after the hostname and space checks, does a token exist. The
	// bootstrap handler names the install directory after the same token.
	tok, err := e.MintToken(t.Host, DefaultTokenTTL)
	if err != nil {
		return err
	}
	dir := pushRoot + "/" + svcinstall.DeriveNames([]byte(tok)).Dir
	line, err := e.OneLiner(OSLinux, p.Controller, tok)
	if err != nil {
		return err
	}
	// From here a failure removes the install directory the one-liner may have
	// created (best effort, on its own short deadline since ctx may be the
	// reason for the failure) so a retry starts clean, and the detail says
	// whether that worked.
	failClean := func(class Class, detail string) error {
		rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer rcancel()
		_, rmErr, rmCode, err := runSSH(rctx, client, "rm -rf '"+dir+"'")
		if err != nil || rmCode != 0 {
			return fail(class, fmt.Sprintf("%s; install dir %s NOT removed: %v %s", detail, dir, err, strings.TrimSpace(rmErr)))
		}
		return fail(class, detail+"; install dir "+dir+" removed")
	}
	out, errOut, code, err = runSSH(ctx, client, line)
	if ctx.Err() != nil {
		return failClean(ClassTimeout, "one-liner")
	}
	if err != nil || code != 0 {
		if strings.Contains(out+errOut, "Permission denied") {
			if ge, _, _, gerr := runSSH(ctx, client, "getenforce"); gerr == nil && strings.TrimSpace(ge) == "Enforcing" {
				return failClean(ClassSELinux, strings.TrimSpace(out+errOut))
			}
		}
		return failClean(ClassInstall, fmt.Sprintf("the one-liner exited %d: %s", code, strings.TrimSpace(out+errOut)))
	}

	// A fresh login proves the password still works after the install.
	fresh, err := dial(ctx, "tcp", t.Addr)
	if err != nil {
		return fail(ClassAuth, "fresh login: "+err.Error())
	}
	fsc, fch, freq, err := ssh.NewClientConn(fresh, t.Addr, cfg)
	if err != nil {
		fresh.Close()
		if ctx.Err() != nil {
			return fail(ClassTimeout, "fresh login: "+err.Error())
		}
		return fail(ClassAuth, "fresh login: "+err.Error())
	}
	ssh.NewClient(fsc, fch, freq).Close()

	// The agent must connect; the wait runs inside the remaining timeout.
	for {
		if e.opt.Connected == nil || e.opt.Connected(t.Host) {
			return nil
		}
		if ctx.Err() != nil {
			return fail(ClassNoHeartbeat, "the agent did not connect before the push timeout")
		}
		select {
		case <-ctx.Done():
			return fail(ClassNoHeartbeat, "the agent did not connect before the push timeout")
		case <-time.After(25 * time.Millisecond):
		}
	}
}

// runSSH runs one command on its own session. Output is capped at 64 KiB per
// stream.
func runSSH(ctx context.Context, client *ssh.Client, cmd string) (stdout, stderr string, code int, err error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", "", 0, err
	}
	defer sess.Close()
	var ob, eb boundedBuf
	ob.max, eb.max = maxCommandOut, maxCommandOut
	sess.Stdout = &ob
	sess.Stderr = &eb
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		sess.Close()
		<-done
		err = ctx.Err()
	}
	if ee, ok := err.(*ssh.ExitError); ok {
		code, err = ee.ExitStatus(), nil
	}
	return ob.String(), eb.String(), code, err
}

// boundedBuf keeps at most max bytes and discards the rest, so a chatty
// command cannot exhaust memory.
type boundedBuf struct {
	max int
	b   bytes.Buffer
}

func (b *boundedBuf) Write(p []byte) (int, error) {
	if room := b.max - b.b.Len(); room > 0 {
		if len(p) > room {
			b.b.Write(p[:room])
		} else {
			b.b.Write(p)
		}
	}
	return len(p), nil
}

func (b *boundedBuf) String() string { return b.b.String() }

// dfAvailableKiB reads the available 1 KiB blocks from `df -Pk` output.
func dfAvailableKiB(out string) (int64, bool) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 {
		return 0, false
	}
	f := strings.Fields(lines[len(lines)-1])
	if len(f) < 4 {
		return 0, false
	}
	v, err := strconv.ParseInt(f[3], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
