package enroll

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/svcinstall"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
	"golang.org/x/crypto/ssh"
)

const (
	maxPushBinary = 64 << 20 // the release bound, same as the bootstrap handler
	maxCommandOut = 64 << 10 // any single command's stdout/stderr
	pushChunk     = 36 << 10 // binary bytes per base64 line (48 KiB encoded)
)

// Target is one host the SSH push installs the agent on.
type Target struct {
	Host     string // manifest name
	Addr     string // host:port for ssh (default port 22)
	User     string
	Pass     vault.Secret
	Hostname string // expected `hostname -s`, normally Host
}

// SSHPusher installs the Linux agent over SSH with password auth. It uploads
// the binary and bundle base64 over stdin (no SFTP; shortcut: no SFTP
// fallback, upgrade when a host refuses a shell command channel).
type SSHPusher struct {
	Binary     []byte // linux/amd64 agent binary (<= 64 MiB)
	Controller string // host:port the agent will dial (put into the bundle)
	NameSecret []byte // derives the randomised service, binary and directory names
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
	if len(p.Binary) > maxPushBinary {
		return fail(ClassInstall, fmt.Sprintf("binary is larger than %d MiB", maxPushBinary>>20))
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

	out, errOut, code, err := runSSH(ctx, client, "echo PHYLAXOK", nil)
	if ctx.Err() != nil {
		return fail(ClassTimeout, "shell sentinel")
	}
	if err != nil || code != 0 || !strings.Contains(out, "PHYLAXOK") {
		return fail(ClassNoShell, strings.TrimSpace(out+" "+errOut))
	}

	out, errOut, code, err = runSSH(ctx, client, "hostname -s", nil)
	if ctx.Err() != nil {
		return fail(ClassTimeout, "hostname")
	}
	if err != nil || code != 0 {
		return fail(ClassNoShell, "hostname: "+strings.TrimSpace(errOut))
	}
	if got := strings.TrimSpace(out); got != t.Hostname {
		return fail(ClassHostname, fmt.Sprintf("host reports %q, manifest says %q", got, t.Hostname))
	}

	names := svcinstall.DeriveNames(p.NameSecret)
	dir := "/opt/" + names.Dir
	state := dir + "/state"
	if _, errOut, code, err = runSSH(ctx, client, "mkdir -p '"+dir+"' '"+state+"'", nil); err != nil || code != 0 {
		return fail(ClassNoShell, "cannot create the install directory: "+strings.TrimSpace(errOut))
	}
	out, errOut, code, err = runSSH(ctx, client, "df -Pk '"+dir+"'", nil)
	if ctx.Err() != nil {
		return fail(ClassTimeout, "df")
	}
	if err != nil || code != 0 {
		return fail(ClassNoSpace, "df: "+strings.TrimSpace(errOut))
	}
	avail, ok := dfAvailableKiB(out)
	need := int64(len(p.Binary))*2 + 16<<20
	if !ok || avail*1024 < need {
		return fail(ClassNoSpace, fmt.Sprintf("%d KiB available, %d KiB needed", avail, need>>10))
	}

	// Only now, after the hostname and space checks, does a token exist.
	b, err := e.Bundle(t.Host, BundleOptions{Controllers: []string{p.Controller}, TTL: DefaultTokenTTL})
	if err != nil {
		return err
	}
	boot, err := json.Marshal(b)
	if err != nil {
		return err
	}
	binCmd := fmt.Sprintf("base64 -d > '%[1]s/.%[2]s.tmp' && chmod 700 '%[1]s/.%[2]s.tmp' && mv '%[1]s/.%[2]s.tmp' '%[1]s/%[2]s'",
		dir, names.Binary)
	out, errOut, code, err = runSSH(ctx, client, binCmd, p.Binary)
	if ctx.Err() != nil {
		return fail(ClassTimeout, "binary upload")
	}
	if err != nil || code != 0 {
		return fail(ClassInstall, "binary upload: "+strings.TrimSpace(out+errOut))
	}
	bootCmd := fmt.Sprintf("base64 -d > '%[1]s/boot.json.tmp' && chmod 600 '%[1]s/boot.json.tmp' && mv '%[1]s/boot.json.tmp' '%[1]s/boot.json'", state)
	out, errOut, code, err = runSSH(ctx, client, bootCmd, boot)
	if ctx.Err() != nil {
		return fail(ClassTimeout, "bundle upload")
	}
	if err != nil || code != 0 {
		return fail(ClassInstall, "bundle upload: "+strings.TrimSpace(out+errOut))
	}

	install := fmt.Sprintf("'%s/%s' agent install --bootstrap '%s/boot.json' --secret %s",
		dir, names.Binary, state, hex.EncodeToString(p.NameSecret))
	out, errOut, code, err = runSSH(ctx, client, install, nil)
	if ctx.Err() != nil {
		return fail(ClassTimeout, "agent install")
	}
	if err != nil || code != 0 {
		if strings.Contains(out+errOut, "Permission denied") {
			if ge, _, _, gerr := runSSH(ctx, client, "getenforce", nil); gerr == nil && strings.TrimSpace(ge) == "Enforcing" {
				return fail(ClassSELinux, strings.TrimSpace(out+errOut))
			}
		}
		return fail(ClassInstall, fmt.Sprintf("agent install exited %d: %s", code, strings.TrimSpace(out+errOut)))
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

// runSSH runs one command on its own session. stdin is uploaded as base64 in
// 48 KiB lines. Output is capped at 64 KiB per stream.
func runSSH(ctx context.Context, client *ssh.Client, cmd string, stdin []byte) (stdout, stderr string, code int, err error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", "", 0, err
	}
	defer sess.Close()
	var ob, eb boundedBuf
	ob.max, eb.max = maxCommandOut, maxCommandOut
	sess.Stdout = &ob
	sess.Stderr = &eb
	var pw *io.PipeWriter
	var wg sync.WaitGroup
	if stdin != nil {
		pr, lpw := io.Pipe()
		pw = lpw
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = lpw.CloseWithError(writeBase64(lpw, stdin))
		}()
		sess.Stdin = pr
		defer pr.Close()
	}
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		sess.Close()
		<-done
		err = ctx.Err()
	}
	if pw != nil {
		_ = pw.Close()
		wg.Wait()
	}
	if ee, ok := err.(*ssh.ExitError); ok {
		code, err = ee.ExitStatus(), nil
	}
	return ob.String(), eb.String(), code, err
}

// writeBase64 writes data as base64 lines of 48 KiB.
func writeBase64(w io.Writer, data []byte) error {
	buf := make([]byte, base64.StdEncoding.EncodedLen(pushChunk)+1)
	for off := 0; off < len(data); off += pushChunk {
		end := off + pushChunk
		if end > len(data) {
			end = len(data)
		}
		n := base64.StdEncoding.EncodedLen(end - off)
		base64.StdEncoding.Encode(buf, data[off:end])
		buf[n] = '\n'
		if _, err := w.Write(buf[:n+1]); err != nil {
			return err
		}
	}
	return nil
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
