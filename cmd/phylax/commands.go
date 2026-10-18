package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/controller"
)

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	stateDir := fs.String("state-dir", "/var/lib/phylax", "controller state directory")
	listen := fs.String("listen", "0.0.0.0:7443", "listen address for all connection types")
	bundle := fs.String("bundle", "", "agent binary to serve for bootstrap")
	advertise := fs.String("advertise", "", "address reported in bootstrap configs (default: listen address)")
	fs.Parse(args)

	c, err := controller.New(*stateDir, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}
	defer c.Store().Close()
	if *bundle != "" {
		b, err := os.ReadFile(*bundle)
		if err != nil {
			fmt.Fprintln(os.Stderr, "serve:", err)
			os.Exit(1)
		}
		c.SetBinary(b)
		c.Logf("serving binary %d bytes sha256 %s", len(b), c.BinarySHA256Hex())
	}
	if *advertise != "" {
		c.SetAdvertise(*advertise)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); c.Stop() }()
	if err := c.Run(*listen); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}
}

func cmdAgent(args []string) {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	stateDir := fs.String("state-dir", "/var/lib/phylax/agent", "agent state directory")
	bundlePath := fs.String("bundle", "/opt/phylax/bootstrap.json", "bootstrap bundle path")
	fs.Parse(args)

	b, err := os.ReadFile(*bundlePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(1)
	}
	var bundle agent.Bundle
	if err := json.Unmarshal(b, &bundle); err != nil {
		fmt.Fprintln(os.Stderr, "agent: bad bundle:", err)
		os.Exit(1)
	}
	a, err := agent.New(*stateDir, bundle, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(1)
	}
	defer a.Close()
	a.Publish("agent_started", map[string]any{"version": version, "host": bundle.Host})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(1)
	}
}

func cmdInit(args []string) { fmt.Println("init: not implemented yet (M1)") }

func cmdSetController(args []string) { fmt.Println("set-controller: not implemented yet (M1)") }
