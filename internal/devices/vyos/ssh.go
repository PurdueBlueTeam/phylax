package vyos

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const maxSSHOutput = 8 << 20

// SSHConfig says how to reach the router's shell.
type SSHConfig struct {
	Addr     string // host:port as seen from the proxy (default Transport.Host:22)
	User     string
	Auth     []ssh.AuthMethod
	HostKey  ssh.HostKeyCallback // required: pinned host key
	Dial     func(ctx context.Context, addr string) (net.Conn, error)
	Timeout  time.Duration // connect + auth (default 15s)
	ExecWait time.Duration // per command when ctx has no deadline (default 60s)
}

type limitedBuf struct {
	b   bytes.Buffer
	max int
}

func (l *limitedBuf) Write(p []byte) (int, error) {
	if l.b.Len()+len(p) > l.max {
		return 0, errors.New("vyos: command output too large")
	}
	return l.b.Write(p)
}

// ExitError is a non-zero remote exit status.
type ExitError struct {
	Status         int
	Stdout, Stderr string
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("vyos: remote command exited %d: %s", e.Status, strings.TrimSpace(e.Stderr+e.Stdout))
}

// run opens a brand-new SSH connection, runs cmd with stdin, and closes it.
// One connection per call keeps every call a fresh-connection test and avoids
// a long-lived session the red team could ride.
func (c *SSHConfig) run(ctx context.Context, cmd, stdin string) (string, error) {
	if c.HostKey == nil {
		return "", errors.New("vyos: SSH host key callback is required (pin the router's key)")
	}
	if _, ok := ctx.Deadline(); !ok {
		w := c.ExecWait
		if w == 0 {
			w = 60 * time.Second
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, w)
		defer cancel()
	}
	to := c.Timeout
	if to == 0 {
		to = 15 * time.Second
	}
	dctx, dcancel := context.WithTimeout(ctx, to)
	defer dcancel()
	dial := c.Dial
	if dial == nil {
		var d net.Dialer
		dial = func(ctx context.Context, addr string) (net.Conn, error) { return d.DialContext(ctx, "tcp", addr) }
	}
	conn, err := dial(dctx, c.Addr)
	if err != nil {
		return "", err
	}
	cc := &ssh.ClientConfig{User: c.User, Auth: c.Auth, HostKeyCallback: c.HostKey, Timeout: to}
	_ = conn.SetDeadline(time.Now().Add(to)) // bounds the handshake only
	sc, chans, reqs, err := ssh.NewClientConn(conn, c.Addr, cc)
	if err != nil {
		conn.Close()
		return "", fmt.Errorf("vyos: ssh handshake: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	client := ssh.NewClient(sc, chans, reqs)
	defer client.Close()
	// Closing the client aborts a hung command when ctx ends.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			client.Close()
		case <-stop:
		}
	}()
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, errb := &limitedBuf{max: maxSSHOutput}, &limitedBuf{max: 1 << 20}
	sess.Stdout, sess.Stderr = out, errb
	if stdin != "" {
		sess.Stdin = strings.NewReader(stdin)
	}
	err = sess.Run(cmd)
	if ctx.Err() != nil {
		return out.b.String(), ctx.Err()
	}
	var ee *ssh.ExitError
	if errors.As(err, &ee) {
		return out.b.String(), &ExitError{Status: ee.ExitStatus(), Stdout: out.b.String(), Stderr: errb.b.String()}
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return out.b.String(), err
	}
	return out.b.String(), nil
}
