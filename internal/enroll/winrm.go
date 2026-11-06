package enroll

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/checks/probe"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

// WinRMTarget is one Windows host the WinRM push installs the agent on.
type WinRMTarget struct {
	Target
	Port   int
	TLS    bool
	Domain string
}

// WinRMPusher installs the Windows agent over WinRM. It runs the same pinned
// one-liner script the console line downloads, so the host fetches the binary
// and the bootstrap config itself (design S2: one install path).
type WinRMPusher struct {
	Controller string        // host:port the host dials for the bootstrap download and the link
	Timeout    time.Duration // per host, default 120s
	Dial       func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Push installs the agent on t. Every failure is a *PushError with a class.
func (p *WinRMPusher) Push(ctx context.Context, e *Enroller, t WinRMTarget) error {
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	if t.Hostname == "" {
		t.Hostname = t.Host
	}
	fail := func(class Class, detail string) error {
		return &PushError{Host: t.Host, Class: class, Detail: vault.RedactString(detail, t.Pass)}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Target.Addr is the SSH host:port form; only its host part is relevant
	// here because WinRM has its own port.
	host := t.Addr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		host = t.Host
	}
	port := t.Port
	if port <= 0 {
		port = 5985
	}
	user := t.User
	if t.Domain != "" && !strings.Contains(user, `\`) {
		user = t.Domain + `\` + user
	}
	sh, err := probe.OpenWinRM(ctx, probe.WinRMConfig{
		Host: host, Port: port, TLS: t.TLS, User: user, Pass: t.Pass.Reveal(), Dial: p.Dial,
	})
	if err != nil {
		switch {
		case errors.Is(err, probe.ErrWinRMAuth):
			return fail(ClassAuth, err.Error())
		case ctx.Err() != nil:
			return fail(ClassTimeout, "connect: "+err.Error())
		default:
			return fail(ClassWinRMUnreachable, err.Error())
		}
	}
	defer func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer ccancel()
		_ = sh.Close(cctx)
	}()

	out, errOut, exit, err := sh.Run(ctx, `$env:COMPUTERNAME`)
	if err != nil {
		if ctx.Err() != nil {
			return fail(ClassTimeout, "hostname check: "+err.Error())
		}
		return fail(ClassWinRMUnreachable, "hostname check: "+err.Error())
	}
	if exit != 0 {
		return fail(ClassInstall, "hostname check exited "+strconv.Itoa(exit)+": "+strings.TrimSpace(errOut))
	}
	if got := strings.TrimSpace(out); got != t.Hostname {
		return fail(ClassHostname, "host reports "+got+", manifest says "+t.Hostname)
	}

	// Only now, after the hostname check, does a token exist.
	tok, err := e.MintToken(t.Host, DefaultTokenTTL)
	if err != nil {
		return err
	}
	script, err := e.windowsScript(p.Controller, tok)
	if err != nil {
		return err
	}
	_, errOut, exit, err = sh.Run(ctx, script)
	if err != nil {
		if ctx.Err() != nil {
			return fail(ClassTimeout, "install script: "+err.Error())
		}
		return fail(ClassWinRMUnreachable, "install script: "+err.Error())
	}
	if exit != 0 {
		return fail(ClassInstall, "the install script exited "+strconv.Itoa(exit)+": "+strings.TrimSpace(errOut))
	}

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
