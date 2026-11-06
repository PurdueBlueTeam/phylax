package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/deadman"
	"github.com/PurdueBlueTeam/phylax/internal/svcinstall"
)

func init() {
	register(command{name: "agent", summary: "host agent: run | rollback <id> | install | uninstall | unit", run: runAgent})
}

const agentUsage = `usage: phylax agent <subcommand> [flags]

  run                 run the agent (foreground, or as a Windows service)
  rollback <id>       fire a dead-man rollback (target of the OS timer)
  install             copy binary + bootstrap and register the service (privileged)
  uninstall           remove the service
  unit                print the systemd unit install would write
`

func defaultStateDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "phylax")
	}
	return "/var/lib/phylax"
}

func runAgent(ctx context.Context, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, agentUsage)
		return errors.New("missing subcommand")
	}
	switch args[0] {
	case "run":
		return agentRun(ctx, args[1:])
	case "rollback":
		return agentRollback(ctx, args[1:])
	case "install", "unit":
		return agentInstall(ctx, args[0] == "unit", args[1:])
	case "uninstall":
		return agentUninstall(ctx, args[1:])
	}
	fmt.Fprint(os.Stderr, agentUsage)
	return fmt.Errorf("unknown subcommand %q", args[0])
}

func agentRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("agent run", flag.ContinueOnError)
	dir := fs.String("state-dir", defaultStateDir(), "agent state directory")
	boot := fs.String("bootstrap", "", "bootstrap file to adopt if the state dir has none")
	svcName := fs.String("service-name", "phylax", "Windows service name")
	memMB := fs.Int64("memory-limit-mb", 80, "soft Go memory limit in MB (0 = off)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	l := agent.Layout{Root: *dir}
	if *boot != "" {
		if _, err := os.Stat(l.Bootstrap()); errors.Is(err, os.ErrNotExist) {
			if err := adoptBootstrap(l, *boot); err != nil {
				return err
			}
		}
	}
	run := func(ctx context.Context) error {
		ex, err := agentExec(l)
		if err != nil {
			return err
		}
		a, err := agent.New(agent.Config{
			Exec:   ex,
			Layout: l, Version: version, Logger: slog.New(slog.NewTextHandler(os.Stderr, nil)),
			Backstop:    osBackstop(l),
			MemoryLimit: *memMB << 20,
		})
		if err != nil {
			return err
		}
		return a.Run(ctx)
	}
	if isSvc, err := svcinstall.RunService(*svcName, run); isSvc || err != nil {
		return err
	}
	return run(ctx)
}

func adoptBootstrap(l agent.Layout, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	b, err := agent.ParseBundle(data)
	if err != nil {
		return err
	}
	if err := l.SaveBundle(b); err != nil {
		return err
	}
	if !b.Safe {
		return nil
	}
	sm, err := actions.NewSafeMode(l.SafeModeFile())
	if err != nil {
		return fmt.Errorf("agent: safe mode state: %w", err)
	}
	if err := sm.Set(true); err != nil {
		return fmt.Errorf("agent: safe mode: %w", err)
	}
	return nil
}

// osBackstop builds the OS timer for a state dir; tests replace it so they
// never touch systemd or the task scheduler.
var osBackstop = func(l agent.Layout) deadman.Backstop {
	return deadman.DefaultBackstop(deadman.Command{Args: []string{"agent", "rollback", "--state-dir", l.Root}})
}

func agentRollback(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("agent rollback", flag.ContinueOnError)
	dir := fs.String("state-dir", defaultStateDir(), "agent state directory")
	// Go's flag package stops at the first positional argument; accept the id
	// on either side of the flags, as the OS timer passes it last.
	var id string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		if id != "" {
			return errors.New("usage: phylax agent rollback [--state-dir D] <id>")
		}
		id, rest = fs.Arg(0), fs.Args()[1:]
	}
	if id == "" {
		return errors.New("usage: phylax agent rollback [--state-dir D] <id>")
	}
	l := agent.Layout{Root: *dir}
	// The action rollback handlers need the host environment (accounts,
	// services); without it the OS timer could not undo action changes.
	hs := map[string]deadman.Handler{}
	if env, err := agentEnv(l); err == nil {
		hs = actions.DeadmanHandlers(env)
	}
	e, err := agent.Rollback(ctx, l, id, agent.RollbackOptions{Backstop: osBackstop(l), Handlers: hs})
	if err != nil {
		return fmt.Errorf("rollback %s: %w", id, err)
	}
	fmt.Printf("%s: %s\n", e.ID, e.State)
	return nil
}

type installFlags struct {
	stateDir, boot, name, binName, dir, secret, secretFile string
	memMax, cpu                                            string
}

func parseInstallFlags(name string, args []string) (*installFlags, error) {
	f := &installFlags{}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&f.boot, "bootstrap", "", "bootstrap file (required for install)")
	fs.StringVar(&f.name, "name", "", "service name (default: derived from --secret, else \"phylax\")")
	fs.StringVar(&f.binName, "binary-name", "", "installed binary file name (default: derived or \"phylax\")")
	fs.StringVar(&f.dir, "dir", "", "install directory (default: derived under /opt or %ProgramFiles%)")
	fs.StringVar(&f.stateDir, "state-dir", "", "state directory (default: <dir>/state)")
	fs.StringVar(&f.secret, "secret", "", "hex secret to derive randomised names from")
	fs.StringVar(&f.secretFile, "secret-file", "", "read the hex secret from this file (the install deletes it)")
	fs.StringVar(&f.memMax, "memory-max", "256M", "systemd MemoryMax")
	fs.StringVar(&f.cpu, "cpu-quota", "50%", "systemd CPUQuota")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if f.secretFile != "" {
		if f.secret != "" {
			return nil, errors.New("--secret and --secret-file are mutually exclusive")
		}
		b, err := readSecretFile(f.secretFile)
		if err != nil {
			return nil, err
		}
		f.secret = strings.TrimSpace(string(b))
	}
	n := svcinstall.Names{Service: "phylax", Binary: "phylax", Dir: "phylax"}
	if f.secret != "" {
		sec, err := hex.DecodeString(f.secret)
		if err != nil || len(sec) < 8 {
			return nil, errors.New("--secret must be at least 8 bytes of hex")
		}
		n = svcinstall.DeriveNames(sec)
	}
	if f.name == "" {
		f.name = n.Service
	}
	if f.binName == "" {
		f.binName = n.Binary
		if runtime.GOOS == "windows" {
			f.binName += ".exe"
		}
	}
	if f.dir == "" {
		root := "/opt"
		if runtime.GOOS == "windows" {
			root = os.Getenv("ProgramFiles")
		}
		f.dir = filepath.Join(root, n.Dir)
	}
	if f.stateDir == "" {
		f.stateDir = filepath.Join(f.dir, "state")
	}
	return f, nil
}

// readSecretFile bounds and reads the secret file; os.Remove happens in
// agentInstall after a dry run is ruled out.
func readSecretFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("--secret-file: %w", err)
	}
	if fi.Size() > 1024 {
		return nil, errors.New("--secret-file is larger than 1 KiB")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--secret-file: %w", err)
	}
	return b, nil
}

func (f *installFlags) spec(bin string) svcinstall.Spec {
	return svcinstall.Spec{Name: f.name, DisplayName: f.name, Description: f.name, Binary: bin,
		Args:      []string{"agent", "run", "--state-dir", f.stateDir, "--service-name", f.name},
		MemoryMax: f.memMax, CPUQuota: f.cpu, WatchdogSec: 30}
}

func agentInstall(ctx context.Context, dry bool, args []string) error {
	f, err := parseInstallFlags("agent install", args)
	if err != nil {
		return err
	}
	bin := filepath.Join(f.dir, f.binName)
	if dry {
		u, err := svcinstall.SystemdUnit(f.spec(bin))
		fmt.Print(u)
		return err
	}
	if f.secretFile != "" {
		// The install step reads and deletes the secret file.
		_ = os.Remove(f.secretFile)
	}
	if f.boot == "" {
		return errors.New("--bootstrap is required")
	}
	if err := adoptBootstrap(agent.Layout{Root: f.stateDir}, f.boot); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(f.dir, 0o755); err != nil {
		return err
	}
	if err := copyExe(exe, bin); err != nil {
		return err
	}
	return svcinstall.New().Install(ctx, f.spec(bin))
}

func copyExe(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return atomicfile.Write(dst, 0o755, func(w io.Writer) error { _, err := io.Copy(w, in); return err })
}

func agentUninstall(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("agent uninstall", flag.ContinueOnError)
	name := fs.String("name", "phylax", "service name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*name) == "" {
		return errors.New("--name required")
	}
	return svcinstall.New().Uninstall(ctx, *name)
}
