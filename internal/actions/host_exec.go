package actions

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// hostExec is the escape hatch of the design (Execution engine, "host.exec"):
// it runs one binary with typed arguments, needs its own node approval record
// and is labeled "runs a host binary" everywhere. It spawns its child through
// the host command runner, which registers the child with the agent's tag
// scope so only the step's own process tree is tagged (design: what may be
// tagged, R6).
type hostExec struct{}

func init() { Register(func() []Action { return []Action{hostExec{}} }) }

func (hostExec) Spec() Spec {
	return Spec{
		Name: hostExecName,
		Doc:  "runs a host binary (the escape hatch; needs its own approval record)",
		// Service, not destructive: a destructive or lockout node gets a
		// default dead-man, and running a binary has no automatic undo. The
		// separate per-node approval for host.exec is what gates it (design:
		// approval classes; SS010 keeps it out of auto plans).
		Risk: RiskService,
		Params: []ParamSpec{
			{Name: "argv", Type: StringList, Required: true, Max: 64},
		},
	}
}

const (
	hostExecName = "host.exec"
	maxHostArgv  = 4096
)

func (hostExec) Locks(Params) []string                      { return nil }
func (hostExec) Touches(Params) []Touch                     { return nil }
func (hostExec) Verify(context.Context, *Env, Params) error { return nil }

func (hostExec) Plan(_ context.Context, _ *Env, p Params) (Plan, error) {
	argv := p.List("argv")
	if err := checkArgv(argv); err != nil {
		return Plan{}, err
	}
	return Plan{Diff: "run " + strings.Join(argv, " "), Notes: []string{"runs a host binary"}}, nil
}

// Capture records nothing: a host binary's effects cannot be undone
// automatically, so the plan lint keeps host.exec out of automatic plans.
func (hostExec) Capture(context.Context, *Env, Params) (Rollback, error) {
	return Rollback{}, nil
}

func (hostExec) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	argv := p.List("argv")
	if err := checkArgv(argv); err != nil {
		return nil, err
	}
	res, err := env.lx().runner().Run(ctx, Cmd{Argv: argv, Started: env.spawnHook(ctx)})
	if err != nil {
		return nil, fmt.Errorf("host.exec %s: %w", argv[0], err)
	}
	out := Output{"stdout": res.Stdout, "exit": strconv.Itoa(res.ExitCode)}
	if res.ExitCode != 0 {
		return out, fmt.Errorf("host.exec %s exited %d: %s", argv[0], res.ExitCode, strings.TrimSpace(res.Stderr+res.Stdout))
	}
	return out, nil
}

func checkArgv(argv []string) error {
	if len(argv) == 0 {
		return errors.New("host.exec: argv is required")
	}
	if !filepath.IsAbs(argv[0]) {
		return errors.New("host.exec: argv[0] must be an absolute path")
	}
	for _, a := range argv {
		if len(a) > maxHostArgv {
			return fmt.Errorf("host.exec: argument longer than %d bytes", maxHostArgv)
		}
	}
	return nil
}

// pidStartTicks is a Linux process's start time (field 22 of
// /proc/<pid>/stat), which tells a reused pid from the process we spawned.
// Other platforms return 0 (the scope then matches on the pid alone).
func pidStartTicks(pid int) uint64 {
	if pid <= 0 {
		return 0
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 || i+2 >= len(b) {
		return 0
	}
	f := strings.Fields(string(b[i+2:]))
	// f[0] is field 3 (state), so starttime (field 22) is f[19].
	if len(f) < 20 {
		return 0
	}
	v, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return 0
	}
	return v
}
