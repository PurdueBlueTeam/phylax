package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/controller"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

func init() {
	register(command{name: "serve", summary: "run the controller", run: runServe})
}

func runServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "controller config file (JSON)")
	dataDir := fs.String("data-dir", "", "data directory (when no config file)")
	listen := fs.String("listen", "", "agent listen address override")
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
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("%w (use -config or -data-dir)", err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	opt := controller.Options{Logger: log, Version: version}
	if cfg.ManifestPath != "" {
		m, err := manifest.LoadDir(cfg.ManifestPath, manifest.Options{})
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
	return c.Run(ctx)
}
