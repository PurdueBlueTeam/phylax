package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
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
func cmdPlan(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: phylax plan <run|status|dag> [flags]")
		os.Exit(2)
	}
	switch args[0] {
	case "run":
		cmdPlanRun(args[1:])
	case "status":
		cmdPlanStatus(args[1:])
	case "dag":
		cmdPlanDAG(args[1:])
	default:
		fmt.Fprintln(os.Stderr, "unknown plan subcommand:", args[0])
		os.Exit(2)
	}
}

func planBaseFlags(fs *flag.FlagSet) (*string, *string) {
	base := fs.String("base", "https://127.0.0.1:7443", "controller console base URL")
	ca := fs.String("ca", "", "CA cert file (empty: skip verification)")
	return base, ca
}

func planHTTP(base string, caFile string) *http.Client {
	tlsCfg := &tls.Config{}
	if caFile == "" {
		tlsCfg.InsecureSkipVerify = true // console tool against our own pinned controller
	} else if b, err := os.ReadFile(caFile); err == nil {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(b)
		tlsCfg.RootCAs = pool
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
}

func cmdPlanRun(args []string) {
	fs := flag.NewFlagSet("plan run", flag.ExitOnError)
	base, ca := planBaseFlags(fs)
	host := fs.String("host", "", "target host")
	planFile := fs.String("plan", "", "plan document (JSON or YAML)")
	dry := fs.Bool("dry", false, "dry run (check phases only)")
	fs.Parse(args)
	if *host == "" || *planFile == "" {
		fmt.Fprintln(os.Stderr, "plan run: -host and -plan are required")
		os.Exit(2)
	}
	doc, err := os.ReadFile(*planFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan run:", err)
		os.Exit(1)
	}
	body, _ := json.Marshal(map[string]any{"host": *host, "dry": *dry, "plan": doc})
	resp, err := planHTTP(*base, *ca).Post(*base+"/plan/run", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan run:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		fmt.Fprintln(os.Stderr, "plan run:", resp.Status, string(out))
		os.Exit(1)
	}
	fmt.Println(string(out))
}

func cmdPlanStatus(args []string) {
	fs := flag.NewFlagSet("plan status", flag.ExitOnError)
	base, ca := planBaseFlags(fs)
	fs.Parse(args)
	resp, err := planHTTP(*base, *ca).Get(*base + "/plan/status")
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan status:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var status []map[string]any
	_ = json.Unmarshal(b, &status)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(status)
}

func cmdPlanDAG(args []string) {
	fs := flag.NewFlagSet("plan dag", flag.ExitOnError)
	base, ca := planBaseFlags(fs)
	planFile := fs.String("plan", "", "plan document (JSON or YAML)")
	out := fs.String("out", "", "write SVG here (default: stdout)")
	fs.Parse(args)
	if *planFile == "" {
		fmt.Fprintln(os.Stderr, "plan dag: -plan is required")
		os.Exit(2)
	}
	doc, err := os.ReadFile(*planFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan dag:", err)
		os.Exit(1)
	}
	resp, err := planHTTP(*base, *ca).Post(*base+"/plan/dag", "application/octet-stream", bytes.NewReader(doc))
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan dag:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "plan dag:", resp.Status)
		os.Exit(1)
	}
	if *out != "" {
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "plan dag:", err)
			os.Exit(1)
		}
	} else {
		os.Stdout.Write(b)
	}
}
