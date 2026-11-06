package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/enroll"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/ui"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

// The enrollment page's backend (Task 11): the host list, one-line minting and
// the pushes. Token minting happens only here, behind the UI's session, CSRF
// and audit checks; the `phylax enroll` command is the other way, and it needs
// the controller's data directory.

// EnrollHosts lists every manifest host with its enrollment state, then any
// enrolled agent the manifest does not name (a host enrolled before the
// manifest changed).
func (o *WebOps) EnrollHosts(ctx context.Context) ([]ui.EnrollRow, error) {
	c := o.c
	seen := map[string]bool{}
	var rows []ui.EnrollRow
	if m, err := c.currentManifest(); err == nil && m != nil {
		names := make([]string, 0, len(m.Hosts))
		for name := range m.Hosts {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			seen[name] = true
			rows = append(rows, c.enrollRow(ctx, name))
		}
	}
	agents, err := c.st.Agents(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range agents {
		if a.ID == ControllerAgent || seen[a.ID] {
			continue
		}
		rows = append(rows, c.enrollRow(ctx, a.ID))
	}
	return rows, nil
}

func (c *Controller) enrollRow(ctx context.Context, host string) ui.EnrollRow {
	row := ui.EnrollRow{Host: host, State: "not_enrolled"}
	if _, err := c.st.Agent(ctx, host); err == nil {
		row.State = "enrolled"
	}
	if c.enr.Revoked(host) {
		row.State = "revoked"
	}
	if s, ok := c.AgentStatus(host); ok {
		row.Connected = s.Connected
	}
	return row
}

// EnrollLine mints a one-time token for host and returns its console one-liner.
func (o *WebOps) EnrollLine(ctx context.Context, host, osName, by string) (string, error) {
	c := o.c
	if osName != enroll.OSLinux && osName != enroll.OSWindows {
		return "", fmt.Errorf("%w: os must be linux or windows", ui.ErrInvalid)
	}
	ctl := c.cfg.Advertise
	if ctl == "" {
		return "", fmt.Errorf("%w: the controller has no advertised address (serve -advertise HOST:PORT)", ui.ErrInvalid)
	}
	tok, err := c.enr.MintToken(host, 0)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ui.ErrInvalid, err)
	}
	line, err := c.enr.OneLiner(osName, ctl, tok)
	if err != nil {
		return "", err
	}
	c.log.Info("enroll: one-liner minted", "host", host, "os", osName, "by", by)
	return line, nil
}

// EnrollPush installs the agent on host with the method that matches its OS
// (SSH on Linux, WinRM on Windows) and the manifest's default credential.
//
// shortcut: the push runs inside the request (30 s SSH, 120 s WinRM per host),
// so a slow WinRM host can outlast the UI server's 60 s write timeout; the push
// itself finishes and is audited. Upgrade to a background job with a status row
// if pushes from the page must always answer.
func (o *WebOps) EnrollPush(ctx context.Context, host, by string) error {
	c := o.c
	m, err := c.currentManifest()
	if err != nil {
		return fmt.Errorf("%w: %v", ui.ErrConflict, err)
	}
	h, ok := m.Hosts[host]
	if !ok {
		return fmt.Errorf("%w: %s is not a manifest host", ui.ErrNotFound, host)
	}
	ctl := c.cfg.Advertise
	if ctl == "" {
		return fmt.Errorf("%w: the controller has no advertised address (serve -advertise HOST:PORT)", ui.ErrInvalid)
	}
	user, pass, err := c.manifestCredential(h)
	if err != nil {
		return err
	}
	c.log.Info("enroll: push", "host", host, "method", enrollMethod(h), "by", by)
	return uiPushError(c.pushHost(ctx, ctl, host, h, user, pass))
}

// ReenrollAll revokes every manifest host's key and pushes each one again in
// dependency order (the domain controller first), one host at a time.
func (o *WebOps) ReenrollAll(ctx context.Context, by string) error {
	c := o.c
	m, err := c.currentManifest()
	if err != nil {
		return fmt.Errorf("%w: %v", ui.ErrConflict, err)
	}
	ctl := c.cfg.Advertise
	if ctl == "" {
		return fmt.Errorf("%w: the controller has no advertised address (serve -advertise HOST:PORT)", ui.ErrInvalid)
	}
	order := enroll.ReenrollOrder(m)
	c.log.Info("enroll: re-enroll all", "hosts", len(order), "by", by)
	method := func(host string) string { return enrollMethod(m.Hosts[host]) }
	push := func(ctx context.Context, host string) error {
		h := m.Hosts[host]
		user, pass, err := c.manifestCredential(h)
		if err != nil {
			return err
		}
		return c.pushHost(ctx, ctl, host, h, user, pass)
	}
	var errs []error
	for _, r := range c.enr.ReenrollAll(ctx, order, method, push) {
		if r.Err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.Target.Host, uiPushError(r.Err)))
		}
	}
	return errors.Join(errs...)
}

// manifestCredential reads a host's default credential secret ("user:pass").
func (c *Controller) manifestCredential(h manifest.Host) (user, pass string, err error) {
	if h.DefaultCredential == "" {
		return "", "", fmt.Errorf("%w: host has no default_credentials secret", ui.ErrInvalid)
	}
	if c.opt.Vault == nil {
		return "", "", fmt.Errorf("%w: the vault is not open", ui.ErrConflict)
	}
	sec, _, err := c.opt.Vault.Get(h.DefaultCredential)
	if err != nil {
		return "", "", fmt.Errorf("%w: vault secret %s: %v", ui.ErrConflict, h.DefaultCredential, err)
	}
	user, pass, ok := strings.Cut(sec.Reveal(), ":")
	if !ok || user == "" {
		return "", "", fmt.Errorf("%w: vault secret %s must be user:password", ui.ErrInvalid, h.DefaultCredential)
	}
	return user, pass, nil
}

// pushHost runs the push that matches the host's OS from the controller.
func (c *Controller) pushHost(ctx context.Context, ctl, host string, h manifest.Host, user, pass string) error {
	t := enroll.Target{Host: host, User: user, Pass: vault.NewSecretString(pass), Hostname: host}
	if h.IsWindows() {
		t.Addr = h.IP
		if t.Addr == "" {
			t.Addr = host
		}
		return (&enroll.WinRMPusher{Controller: ctl, Timeout: 120 * time.Second}).Push(ctx, c.enr,
			enroll.WinRMTarget{Target: t, Port: 5985})
	}
	addr := h.IP
	if addr == "" {
		addr = host
	}
	t.Addr = net.JoinHostPort(addr, "22")
	return (&enroll.SSHPusher{Controller: ctl, Timeout: 30 * time.Second}).Push(ctx, c.enr, t)
}

// enrollMethod is how a host is finished: a host with no default credential
// only gets the console one-liner, Windows uses WinRM and the rest SSH.
func enrollMethod(h manifest.Host) string {
	switch {
	case h.DefaultCredential == "":
		return "console"
	case h.IsWindows():
		return "winrm"
	default:
		return "ssh"
	}
}

// uiPushError turns a pusher's typed failure into the page's class and next
// step; every other error passes through.
func uiPushError(err error) error {
	if err == nil {
		return nil
	}
	var pe *enroll.PushError
	if errors.As(err, &pe) {
		return &ui.PushError{Class: string(pe.Class), Detail: pe.Detail, Next: pe.Next()}
	}
	return err
}
