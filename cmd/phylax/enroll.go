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
  push -ctl HOST:PORT [-parallel N] HOST...    install the Linux agent over SSH
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
	name := filepath.Join(b.cfg.ReleaseDir, "phylax-linux-amd64")
	bin, err := os.ReadFile(name)
	if err != nil {
		return fmt.Errorf("enroll push: release file %s: %w", name, err)
	}
	if len(bin) == 0 || len(bin) > 64<<20 {
		return fmt.Errorf("enroll push: release file %s has %d bytes; want 1 to 64 MiB", name, len(bin))
	}
	e, err := b.enroller(nil)
	if err != nil {
		return err
	}
	var v *vault.Vault
	targets := make([]enroll.Target, 0, fs.NArg())
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
		targets = append(targets, enroll.Target{Host: host, Addr: enrollPushAddr(h), User: user,
			Pass: vault.NewSecretString(pass), Hostname: host})
	}
	secrets := make(map[string][]byte, len(targets))
	for _, t := range targets {
		sec, err := e.HostNameSecret(t.Host)
		if err != nil {
			return err
		}
		secrets[t.Host] = sec
	}
	pusher := &enroll.SSHPusher{Binary: bin, Controller: *ctl, Timeout: 30 * time.Second}
	results := enroll.PushAll(ctx, targets, *parallel, func(ctx context.Context, t enroll.Target) error {
		p := *pusher
		p.NameSecret = secrets[t.Host]
		return p.Push(ctx, e, t)
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
