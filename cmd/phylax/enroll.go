package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/controller"
	"github.com/PurdueBlueTeam/phylax/internal/enroll"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/store"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

func init() {
	register(command{
		name:    "enroll",
		summary: "enrollment helpers: line | push | status",
		run: func(ctx context.Context, args []string) error {
			return runEnroll(ctx, args, os.Stdout, os.Stderr)
		},
	})
}

const enrollUsage = `usage: phylax enroll [-config FILE | -data-dir DIR] [-release-dir DIR] [-vault FILE] <subcommand> [flags]

  line -os linux|windows -ctl HOST:PORT HOST   print the pinned console one-liner (mints a token)
  push -ctl HOST:PORT [-parallel N] HOST...    install over SSH (Linux) or WinRM (Windows)
  reenroll-all -ctl HOST:PORT [-yes]           revoke and reinstall every host in dependency order
  status                                       print each manifest host: enrolled, connected, revoked

The command uses the controller's data dir (the same tokens, identity and
store serve uses) and refuses while serve is running: use the Operator page
then.
`

// enrollPushAddr is the SSH address of a manifest host. Tests replace it to
// point at a fake server (the network edge the command does not own).
var enrollPushAddr = func(h manifest.Host) string {
	return net.JoinHostPort(h.IP, "22")
}

// enrollBase is what every subcommand needs from the controller's data dir.
type enrollBase struct {
	cfg     controller.Config
	m       *manifest.Manifest
	id      *link.Identity
	planKey ed25519.PublicKey
}

func runEnroll(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	cfgPath, dataDir, releaseDir, vaultPath, rest, err := takeEnrollCommon(args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		fmt.Fprint(stderr, enrollUsage)
		return errors.New("enroll: missing subcommand")
	}
	sub, subargs := rest[0], rest[1:]
	base, err := loadEnrollBase(cfgPath, dataDir, releaseDir)
	if err != nil {
		return err
	}
	unlock, err := enroll.LockDataDir(base.cfg.DataDir)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	defer unlock()
	switch sub {
	case "line":
		return enrollLine(base, subargs, stdout)
	case "push":
		return enrollPush(ctx, base, vaultPath, subargs, stdout)
	case "reenroll-all":
		return enrollReenrollAll(ctx, base, vaultPath, subargs, stdout)
	case "status":
		return enrollStatus(ctx, base, subargs, stdout)
	}
	fmt.Fprint(stderr, enrollUsage)
	return fmt.Errorf("enroll: unknown subcommand %q", sub)
}

// takeEnrollCommon pulls the data-dir flags from anywhere in args, so both
// `enroll -data-dir D line ...` and `enroll line -data-dir D ...` work.
func takeEnrollCommon(args []string) (cfgPath, dataDir, releaseDir, vaultPath string, rest []string, err error) {
	flags := []struct {
		name string
		dst  *string
	}{
		{"config", &cfgPath}, {"data-dir", &dataDir}, {"release-dir", &releaseDir}, {"vault", &vaultPath},
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		matched := false
		for _, f := range flags {
			for _, p := range []string{"-" + f.name, "--" + f.name} {
				if a == p {
					if i+1 >= len(args) {
						return "", "", "", "", nil, fmt.Errorf("enroll: -%s needs a value", f.name)
					}
					*f.dst = args[i+1]
					i++
					matched = true
					break
				}
				if v, ok := strings.CutPrefix(a, p+"="); ok {
					*f.dst = v
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			rest = append(rest, a)
		}
	}
	return cfgPath, dataDir, releaseDir, vaultPath, rest, nil
}

func loadEnrollBase(cfgPath, dataDir, releaseDir string) (*enrollBase, error) {
	var cfg controller.Config
	var err error
	if cfgPath != "" {
		if cfg, err = controller.LoadConfig(cfgPath); err != nil {
			return nil, err
		}
	} else {
		cfg.DataDir = dataDir
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("%w (use -config or -data-dir)", err)
		}
	}
	if releaseDir != "" {
		cfg.ReleaseDir = releaseDir
	}
	b := &enrollBase{cfg: cfg}
	if cfg.ManifestPath != "" {
		if b.m, err = manifest.LoadDir(cfg.ManifestPath, manifest.Options{}); err != nil {
			return nil, fmt.Errorf("manifest: %w", err)
		}
	}
	raw, err := os.ReadFile(cfg.IdentityPath)
	if err != nil {
		return nil, fmt.Errorf("enroll: controller identity %s: %w (run phylax serve first)", cfg.IdentityPath, err)
	}
	if b.id, err = link.ParseIdentity(raw); err != nil {
		return nil, fmt.Errorf("enroll: controller identity %s: %w", cfg.IdentityPath, err)
	}
	if b.planKey, err = loadEnrollPlanKey(filepath.Join(cfg.DataDir, "plan.key")); err != nil {
		return nil, err
	}
	return b, nil
}

// loadEnrollPlanKey reads the controller's plan key; a missing file is not an
// error here (line and status do not need it), push checks for one.
func loadEnrollPlanKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("enroll: plan key: %w", err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, fmt.Errorf("enroll: plan key %s: not PEM", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("enroll: plan key %s: %w", path, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("enroll: plan key %s: not Ed25519", path)
	}
	return priv.Public().(ed25519.PublicKey), nil
}

func (b *enrollBase) hostKnown() func(string) bool {
	if b.m == nil {
		return nil
	}
	return func(host string) bool { _, ok := b.m.Hosts[host]; return ok }
}

func (b *enrollBase) enroller(st *store.Store) (*enroll.Enroller, error) {
	return enroll.New(enroll.Options{
		DataDir: b.cfg.DataDir, MaxLiveTokens: b.cfg.MaxLiveTokens,
		Store: st, Identity: b.id, PlanKey: b.planKey, ReleaseDir: b.cfg.ReleaseDir,
		HostKnown: b.hostKnown(),
	})
}

func enrollLine(b *enrollBase, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("enroll line", flag.ContinueOnError)
	osName := fs.String("os", "", "host OS: linux or windows")
	ctl := fs.String("ctl", "", "controller host:port as the host sees it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *osName == "" || *ctl == "" {
		return errors.New("usage: phylax enroll line -os linux|windows -ctl HOST:PORT HOST")
	}
	e, err := b.enroller(nil)
	if err != nil {
		return err
	}
	tok, err := e.MintToken(fs.Arg(0), 0)
	if err != nil {
		return err
	}
	line, err := e.OneLiner(*osName, *ctl, tok)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, line)
	return nil
}

func enrollPush(ctx context.Context, b *enrollBase, vaultPath string, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("enroll push", flag.ContinueOnError)
	ctl := fs.String("ctl", "", "controller host:port the agent will dial")
	parallel := fs.Int("parallel", 8, "hosts pushed at once")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 || *ctl == "" {
		return errors.New("usage: phylax enroll push -ctl HOST:PORT [-parallel N] HOST...")
	}
	if b.m == nil {
		return errors.New("enroll push needs a manifest (manifest_path)")
	}
	if len(b.planKey) == 0 {
		return fmt.Errorf("enroll push: no plan key in %s (run phylax serve first)", b.cfg.DataDir)
	}
	e, err := b.enroller(nil)
	if err != nil {
		return err
	}
	var v *vault.Vault
	targets := make([]enroll.Target, 0, fs.NArg())
	winrm := map[string]enroll.WinRMTarget{}
	for _, host := range fs.Args() {
		h, ok := b.m.Hosts[host]
		if !ok {
			return fmt.Errorf("enroll push: %q is not a manifest host", host)
		}
		if h.DefaultCredential == "" {
			return fmt.Errorf("enroll push: host %s has no default_credentials secret", host)
		}
		if v == nil {
			if vaultPath == "" {
				return errors.New("enroll push: -vault is required for the manifest's default credentials")
			}
			if v, err = openVault(vaultPath); err != nil {
				return fmt.Errorf("enroll push: vault: %w", err)
			}
		}
		sec, _, err := v.Get(h.DefaultCredential)
		if err != nil {
			return fmt.Errorf("enroll push: host %s: vault secret %s: %w", host, h.DefaultCredential, err)
		}
		user, pass, ok := strings.Cut(sec.Reveal(), ":")
		if !ok || user == "" {
			return fmt.Errorf("enroll push: host %s: vault secret %s must be user:password", host, h.DefaultCredential)
		}
		t := enroll.Target{Host: host, User: user, Pass: vault.NewSecretString(pass), Hostname: host}
		if h.IsWindows() {
			// WinRM uses its own port; Addr only supplies the host.
			t.Addr = h.IP
			if t.Addr == "" {
				t.Addr = host
			}
			winrm[host] = enroll.WinRMTarget{Target: t, Port: 5985}
		} else {
			t.Addr = enrollPushAddr(h)
		}
		targets = append(targets, t)
	}
	pusher := &enroll.SSHPusher{Controller: *ctl, Timeout: 30 * time.Second}
	wpusher := &enroll.WinRMPusher{Controller: *ctl, Timeout: 120 * time.Second}
	results := enroll.PushAll(ctx, targets, *parallel, func(ctx context.Context, t enroll.Target) error {
		if wt, ok := winrm[t.Host]; ok {
			return wpusher.Push(ctx, e, wt)
		}
		return pusher.Push(ctx, e, t)
	})
	failed := 0
	for _, r := range results {
		if r.Err == nil {
			fmt.Fprintf(stdout, "%s ok\n", r.Target.Host)
			continue
		}
		failed++
		var pe *enroll.PushError
		if errors.As(r.Err, &pe) {
			if pe.Class == enroll.ClassHostKey {
				fmt.Fprintf(stdout, "!!! %s: SSH HOST KEY CHANGED; possible man in the middle, nothing was sent\n", r.Target.Host)
			}
			fmt.Fprintf(stdout, "%s FAIL %s: %s\n", r.Target.Host, pe.Class, pe.Next())
			continue
		}
		fmt.Fprintf(stdout, "%s FAIL: %v\n", r.Target.Host, r.Err)
	}
	if failed > 0 {
		return fmt.Errorf("enroll: push failed for %d of %d hosts", failed, len(results))
	}
	return nil
}

// enrollHostMethod is how a host is finished: a console-only host has no
// default credential, else Windows uses WinRM and the rest use SSH.
func enrollHostMethod(h manifest.Host) string {
	switch {
	case h.DefaultCredential == "":
		return "console"
	case h.IsWindows():
		return "winrm"
	default:
		return "ssh"
	}
}

func enrollReenrollAll(ctx context.Context, b *enrollBase, vaultPath string, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("enroll reenroll-all", flag.ContinueOnError)
	ctl := fs.String("ctl", "", "controller host:port the agent will dial")
	yes := fs.Bool("yes", false, "run the destructive re-enrollment")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *ctl == "" {
		return errors.New("usage: phylax enroll reenroll-all -ctl HOST:PORT [-yes]")
	}
	if b.m == nil {
		return errors.New("enroll reenroll-all needs a manifest (manifest_path)")
	}
	e, err := b.enroller(nil)
	if err != nil {
		return err
	}
	order := enroll.ReenrollOrder(b.m)
	method := func(host string) string { return enrollHostMethod(b.m.Hosts[host]) }
	fmt.Fprintln(stdout, "re-enrollment order:")
	for i, host := range order {
		fmt.Fprintf(stdout, "%d. %s %s\n", i+1, host, method(host))
	}
	fmt.Fprintln(stdout, "repeat the T+0 console phase first (design: Re-enrollment after a reset)")
	if !*yes {
		fmt.Fprintln(stdout, "nothing changed; re-run with -yes to revoke and push")
		return nil
	}
	if len(b.planKey) == 0 {
		return fmt.Errorf("enroll reenroll-all: no plan key in %s (run phylax serve first)", b.cfg.DataDir)
	}

	var v *vault.Vault
	credential := func(host string) (user, pass string, err error) {
		h := b.m.Hosts[host]
		if v == nil {
			if vaultPath == "" {
				return "", "", errors.New("enroll reenroll-all: -vault is required for the manifest's default credentials")
			}
			if v, err = openVault(vaultPath); err != nil {
				return "", "", fmt.Errorf("enroll reenroll-all: vault: %w", err)
			}
		}
		sec, _, err := v.Get(h.DefaultCredential)
		if err != nil {
			return "", "", fmt.Errorf("enroll reenroll-all: host %s: vault secret %s: %w", host, h.DefaultCredential, err)
		}
		user, pass, ok := strings.Cut(sec.Reveal(), ":")
		if !ok || user == "" {
			return "", "", fmt.Errorf("enroll reenroll-all: host %s: vault secret %s must be user:password", host, h.DefaultCredential)
		}
		return user, pass, nil
	}
	sshPusher := &enroll.SSHPusher{Controller: *ctl, Timeout: 30 * time.Second}
	winrmPusher := &enroll.WinRMPusher{Controller: *ctl, Timeout: 120 * time.Second}
	push := func(ctx context.Context, host string) error {
		h := b.m.Hosts[host]
		user, pass, err := credential(host)
		if err != nil {
			return err
		}
		t := enroll.Target{Host: host, User: user, Pass: vault.NewSecretString(pass), Hostname: host}
		if h.IsWindows() {
			t.Addr = h.IP
			if t.Addr == "" {
				t.Addr = host
			}
			return winrmPusher.Push(ctx, e, enroll.WinRMTarget{Target: t, Port: 5985})
		}
		t.Addr = enrollPushAddr(h)
		return sshPusher.Push(ctx, e, t)
	}
	results := e.ReenrollAll(ctx, order, method, push)
	failed := 0
	for _, r := range results {
		host := r.Target.Host
		if r.Err == nil {
			if method(host) == "console" {
				fmt.Fprintf(stdout, "%s console: key revoked; finish it with the console one-liner\n", host)
			} else {
				fmt.Fprintf(stdout, "%s ok\n", host)
			}
			continue
		}
		failed++
		var pe *enroll.PushError
		if errors.As(r.Err, &pe) {
			if pe.Class == enroll.ClassHostKey {
				fmt.Fprintf(stdout, "!!! %s: SSH HOST KEY CHANGED; possible man in the middle, nothing was sent\n", host)
			}
			fmt.Fprintf(stdout, "%s FAIL %s: %s\n", host, pe.Class, pe.Next())
			continue
		}
		fmt.Fprintf(stdout, "%s FAIL: %v\n", host, r.Err)
	}
	if failed > 0 {
		return fmt.Errorf("enroll: re-enroll failed for %d of %d hosts", failed, len(results))
	}
	return nil
}

func enrollStatus(ctx context.Context, b *enrollBase, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("enroll status", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: phylax enroll status")
	}
	if b.m == nil {
		return errors.New("enroll status needs a manifest (manifest_path)")
	}
	st, err := store.Open(ctx, filepath.Join(b.cfg.DataDir, "phylax.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	e, err := b.enroller(st)
	if err != nil {
		return err
	}
	agents, err := st.Agents(ctx)
	if err != nil {
		return err
	}
	enrolled := map[string]bool{}
	for _, a := range agents {
		if a.ID != controller.ControllerAgent {
			enrolled[a.ID] = true
		}
	}
	hosts := make([]string, 0, len(b.m.Hosts))
	for h := range b.m.Hosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	// Connected is false from here: this process has no live sessions; the UI
	// page shows the live state.
	fmt.Fprintf(stdout, "%-24s %-9s %-10s %s\n", "HOST", "ENROLLED", "CONNECTED", "REVOKED")
	for _, h := range hosts {
		fmt.Fprintf(stdout, "%-24s %-9t %-10t %t\n", h, enrolled[h], false, e.Revoked(h))
	}
	return nil
}
