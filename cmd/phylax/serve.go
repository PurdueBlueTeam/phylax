package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/controller"
	"github.com/PurdueBlueTeam/phylax/internal/enroll"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

func init() {
	register(command{name: "serve", summary: "run the controller", run: runServe})
}

func runServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "controller config file (JSON)")
	dataDir := fs.String("data-dir", "", "data directory (when no config file)")
	listen := fs.String("listen", "", "agent listen address override")
	uiListen := fs.String("ui-listen", "", "operator UI address (loopback only; \"off\" disables)")
	plansDir := fs.String("plans", "", "plan template directory")
	vaultPath := fs.String("vault", "", "secrets vault file (enables controller-side device and Splunk plan nodes; needs a manifest)")
	bundlesDir := fs.String("bundles", "", "write one enrollment bootstrap bundle per manifest host to this directory")
	advertise := fs.String("advertise", "", "controller host:port the agent dials (required with -bundles)")
	bundleTTL := fs.Duration("bundle-ttl", 8*time.Hour, "enrollment token lifetime for -bundles")
	bundleSafe := fs.Bool("bundle-safe", false, "start the bundled agents in safe mode")
	servedDir := fs.String("served-dir", "", "directory the web root serves; phylax and phylax.exe are hashed for the enrollment watch")
	enrollWindow := fs.Duration("enroll-window", 0, "how long enrollment stays open (default -bundle-ttl)")
	releaseDir := fs.String("release-dir", "", "directory holding phylax-linux-amd64 and phylax-windows-amd64.exe for bootstrap downloads")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundlesDir != "" && *advertise == "" {
		return fmt.Errorf("-bundles needs -advertise HOST:PORT (the address the agent dials)")
	}
	if *servedDir != "" && *bundlesDir == "" {
		return fmt.Errorf("-served-dir needs -bundles (it watches the bundles that are served)")
	}
	var cfg controller.Config
	if *cfgPath != "" {
		c, err := controller.LoadConfig(*cfgPath)
		if err != nil {
			return err
		}
		cfg = c
	} else {
		cfg.DataDir = *dataDir
	}
	if *listen != "" {
		cfg.AgentListen = *listen
	}
	if *uiListen != "" {
		cfg.UIListen = *uiListen
	}
	if *plansDir != "" {
		cfg.PlansPath = *plansDir
	}
	if *releaseDir != "" {
		cfg.ReleaseDir = *releaseDir
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("%w (use -config or -data-dir)", err)
	}
	// serve is the single writer of the data dir while it runs; the enroll
	// commands refuse until it stops.
	unlock, err := enroll.LockDataDir(cfg.DataDir)
	if errors.Is(err, enroll.ErrServeRunning) {
		return fmt.Errorf("serve: data dir %s is locked by another phylax serve or enroll", cfg.DataDir)
	}
	if err != nil {
		return err
	}
	defer unlock()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	opt := controller.Options{Logger: log, Version: version, Advertise: *advertise}
	var m *manifest.Manifest
	if cfg.ManifestPath != "" {
		var err error
		m, err = manifest.LoadDir(cfg.ManifestPath, manifest.Options{})
		if err != nil {
			return fmt.Errorf("manifest: %w", err)
		}
		opt.HostKnown = func(h string) bool { _, ok := m.Hosts[h]; return ok }
		opt.Guard = func(h string) actions.ScoringGuard { return actions.GuardFromManifest(m, h) }
	}
	c, err := controller.New(ctx, cfg, opt)
	if err != nil {
		return err
	}
	defer c.Close()
	if *vaultPath != "" {
		if m == nil {
			return fmt.Errorf("-vault needs a manifest (manifest_path)")
		}
		v, err := openVault(*vaultPath)
		if err != nil {
			return err
		}
		if _, err := c.EnableDeviceExec(controller.DeviceExecOptions{
			DirectoryOptions: controller.DirectoryOptions{Manifest: func() *manifest.Manifest { return m }, Vault: v}}); err != nil {
			return err
		}
	}
	if *bundlesDir != "" {
		if m == nil {
			return fmt.Errorf("-bundles needs a manifest (manifest_path)")
		}
		if err := writeBundles(c, m, *bundlesDir, *advertise, *bundleTTL, *bundleSafe); err != nil {
			return err
		}
		log.Info("enrollment bundles written", "dir", *bundlesDir, "hosts", len(m.Hosts), "safe", *bundleSafe)
		if *servedDir != "" {
			served, err := servedBinaries(*servedDir)
			if err != nil {
				return err
			}
			window := *enrollWindow
			if window <= 0 {
				window = *bundleTTL
			}
			hosts := manifestHosts(m)
			if err := c.WatchEnrollment(*bundlesDir, hosts, served, window); err != nil {
				return err
			}
			log.Info("enrollment watch started", "dir", *bundlesDir, "hosts", len(hosts), "window", window)
		}
	}
	if cfg.ManifestPath != "" {
		// Agent configs are generated from the manifest (and rules) and pushed
		// on connect and whenever those files change.
		if err := c.LoadAndSetConfigInputs(ctx); err != nil {
			return fmt.Errorf("agent config inputs: %w", err)
		}
		go func() {
			if err := c.WatchConfigInputs(ctx, 5*time.Second); err != nil {
				log.Error("config watcher stopped", "err", err)
			}
		}()
	}
	go func() {
		if err := c.RunModules(ctx, module.Registered()); err != nil {
			log.Error("controller module runner stopped", "err", err)
		}
	}()
	log.Info("plan-signing public key (bootstrap plan_key)", "plan_key", hex.EncodeToString(c.PlanPublicKey()))
	log.Info("controller key pin", "pin", c.Pin().String(), "curl", c.Pin().Curl())
	if cfg.UIListen != "off" {
		if err := startUI(ctx, c, cfg, log); err != nil {
			return err
		}
	}
	return c.Run(ctx)
}

// writeBundles writes one bootstrap bundle per manifest host, named
// <host>.json, so a person can download it on the console host and enroll.
func writeBundles(c *controller.Controller, m *manifest.Manifest, dir, advertise string, ttl time.Duration, safe bool) error {
	return c.Enroller().WriteBundles(dir, manifestHosts(m), enroll.BundleOptions{Controllers: []string{advertise}, TTL: ttl, Safe: safe})
}

// manifestHosts lists the manifest's host names, sorted.
func manifestHosts(m *manifest.Manifest) []string {
	hosts := make([]string, 0, len(m.Hosts))
	for h := range m.Hosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

// servedBinaries lists the agent binaries a web root serves. A missing
// phylax.exe is normal on a Linux-only kit; a web root with neither binary is
// an error, because an empty served set would accept every reported hash.
func servedBinaries(dir string) ([]string, error) {
	var out []string
	for _, name := range []string{"phylax", "phylax.exe"} {
		p := filepath.Join(dir, name)
		switch _, err := os.Stat(p); {
		case err == nil:
			out = append(out, p)
		case !errors.Is(err, os.ErrNotExist):
			return nil, fmt.Errorf("served binaries: %w", err)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("served binaries: no phylax or phylax.exe in %s", dir)
	}
	return out, nil
}

// startUI serves the operator UI on its own loopback listener. The first run
// creates the "admin" operator and prints its password once on stderr; it is
// stored only as an argon2id hash.
func startUI(ctx context.Context, c *controller.Controller, cfg controller.Config, log *slog.Logger) error {
	srv, _, err := c.NewUI(controller.UIOptions{Addr: cfg.UIListen, PlansDir: cfg.PlansPath, Logger: log})
	if err != nil {
		return fmt.Errorf("ui: %w", err)
	}
	ln, err := net.Listen("tcp", srv.Addr())
	if err != nil {
		return fmt.Errorf("ui listen: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			ln.Close()
		}
	}()
	pw, created, err := srv.EnsureAdmin(ctx)
	if err != nil {
		return fmt.Errorf("ui: %w", err)
	}
	if created {
		fmt.Fprintf(os.Stderr, "\nFirst run: operator account created.\n  user:     admin\n  password: %s\nThis password is shown once and is not stored; change it on the Account page.\n\n", pw)
	}
	ok = true
	log.Info("operator UI listening", "url", "http://"+ln.Addr().String()+"/")
	go func() {
		if err := srv.Serve(ctx, ln); err != nil {
			log.Error("operator UI stopped", "err", err)
		}
	}()
	return nil
}

// openVault opens and unlocks the vault; the passphrase comes from the
// PHYLAX_VAULT_PASSPHRASE environment variable and is cleared from it.
func openVault(path string) (*vault.Vault, error) {
	pass := os.Getenv("PHYLAX_VAULT_PASSPHRASE")
	if pass == "" {
		return nil, fmt.Errorf("-vault: set PHYLAX_VAULT_PASSPHRASE")
	}
	os.Unsetenv("PHYLAX_VAULT_PASSPHRASE")
	v, err := vault.Open(path, vault.Options{})
	if err != nil {
		return nil, err
	}
	if err := v.Unlock([]byte(pass)); err != nil {
		return nil, err
	}
	return v, nil
}
