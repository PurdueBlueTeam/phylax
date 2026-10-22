package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/controller"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
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
	if err := fs.Parse(args); err != nil {
		return err
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
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("%w (use -config or -data-dir)", err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	opt := controller.Options{Logger: log, Version: version}
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
	log.Info("plan-signing public key (bootstrap plan_key)", "plan_key", hex.EncodeToString(c.PlanPublicKey()))
	log.Info("controller key pin", "pin", c.Pin().String(), "curl", c.Pin().Curl())
	if cfg.UIListen != "off" {
		if err := startUI(ctx, c, cfg, log); err != nil {
			return err
		}
	}
	return c.Run(ctx)
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
