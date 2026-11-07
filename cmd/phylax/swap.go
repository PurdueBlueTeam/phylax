package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/svcinstall"
)

// maxSwapPlanBytes bounds a swap plan file (one plan, a few hundred bytes).
const maxSwapPlanBytes = 64 << 10

// swapSlack is the helper's budget on top of WaitSec for the stop, the
// install/restart and the swap itself (each service call is bounded, this is
// the whole plan). A variable so a test can shrink it.
var swapSlack = 2 * time.Minute

// runSwap performs one swap plan: stop the agent, swap the binary
// (replace_binary) or install the renamed service (rename), start it, and wait
// for the agent's first controller ack. Without an ack within WaitSec it puts
// the old state back and returns an error, so a bad binary or a bad name never
// leaves the host without an agent (design: Lifecycle, binary replacement).
func runSwap(ctx context.Context, p svcinstall.SwapPlan, inst svcinstall.Installer) error {
	if p.WaitSec <= 0 {
		p.WaitSec = 30
	}
	if p.Service == "" || p.StateDir == "" {
		return errors.New("agent swap: the plan needs a service and a state directory")
	}
	// One deadline for the whole plan: a hung service manager ends the helper
	// with an error instead of leaving it running forever. The revert below runs
	// on its own budget, so it still gets to undo a failed swap.
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.WaitSec)*time.Second+swapSlack)
	defer cancel()
	// The agent must be gone before the binary is replaced (Windows keeps a
	// running image locked) and before a second agent opens the same spool.
	if err := inst.Stop(ctx, p.Service); err != nil {
		return fmt.Errorf("agent swap: stop %s: %w", p.Service, err)
	}
	start := time.Now()
	switch p.Kind {
	case "replace_binary":
		if err := replaceBinary(p); err != nil {
			_ = inst.Restart(ctx, p.Service)
			return err
		}
		if err := inst.Restart(ctx, p.Service); err != nil {
			restoreBinary(p)
			return fmt.Errorf("agent swap: restart %s: %w", p.Service, err)
		}
		if err := waitStarted(p.StateDir, start, p.WaitSec); err != nil {
			// The new agent is running (it just never reached the controller):
			// stop it before the binary moves under its feet, then start the old
			// one.
			rctx, rcancel := revertCtx(ctx)
			_ = inst.Stop(rctx, p.Service)
			restoreBinary(p)
			_ = inst.Restart(rctx, p.Service)
			rcancel()
			return fmt.Errorf("agent swap: reverted: %w", err)
		}
		_ = os.Remove(p.OldBinary + ".old")
		return nil
	case "rename":
		if err := inst.Install(ctx, svcinstall.Spec{Name: p.NewService, DisplayName: p.NewService,
			Description: p.NewService, Binary: p.NewBinary, Args: p.Args}); err != nil {
			_ = inst.Restart(ctx, p.Service)
			return fmt.Errorf("agent swap: install %s: %w", p.NewService, err)
		}
		if err := waitStarted(p.StateDir, start, p.WaitSec); err != nil {
			rctx, rcancel := revertCtx(ctx)
			_ = inst.Uninstall(rctx, p.NewService)
			_ = inst.Restart(rctx, p.Service)
			rcancel()
			return fmt.Errorf("agent swap: reverted: %w", err)
		}
		return inst.Uninstall(ctx, p.Service)
	}
	return fmt.Errorf("agent swap: unknown kind %q", p.Kind)
}

// revertCtx is the revert's own budget: the plan's deadline may already have
// fired when a swap fails to come up.
func revertCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 2*swapSlack)
}

// replaceBinary renames the running binary aside and moves the new one into
// its place.
func replaceBinary(p svcinstall.SwapPlan) error {
	old := p.OldBinary + ".old"
	_ = os.Remove(old) // a previous swap's leftover
	if err := os.Rename(p.OldBinary, old); err != nil {
		return fmt.Errorf("agent swap: move the old binary aside: %w", err)
	}
	if err := moveFile(p.NewBinary, p.OldBinary); err != nil {
		_ = os.Rename(old, p.OldBinary)
		return fmt.Errorf("agent swap: install the new binary: %w", err)
	}
	return nil
}

// restoreBinary puts the old binary back after a failed swap.
func restoreBinary(p svcinstall.SwapPlan) {
	old := p.OldBinary + ".old"
	if err := os.Rename(p.OldBinary, p.NewBinary); err != nil {
		_ = os.Remove(p.OldBinary)
	}
	_ = os.Rename(old, p.OldBinary)
}

// moveFile renames src to dst, falling back to copy-and-remove when the two are
// on different file systems.
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := atomicfile.Write(dst, 0o755, func(w io.Writer) error { _, err := io.Copy(w, in); return err }); err != nil {
		return err
	}
	return os.Remove(src)
}

// waitStarted polls <state>/started.json until the agent reports a start after
// the swap.
func waitStarted(stateDir string, after time.Time, sec int) error {
	deadline := time.Now().Add(time.Duration(sec) * time.Second)
	for {
		if startedAfter(stateDir, after) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no controller ack within %d s", sec)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func startedAfter(stateDir string, after time.Time) bool {
	raw, err := os.ReadFile(filepath.Join(stateDir, "started.json"))
	if err != nil || len(raw) > maxSwapPlanBytes {
		return false
	}
	var st svcinstall.Started
	if json.Unmarshal(raw, &st) != nil {
		return false
	}
	return st.PID > 0 && st.Time.After(after)
}

// agentSwap is the detached `phylax agent swap` helper. The agent.replace_binary
// and agent.rename actions start it; it is never run by hand.
func agentSwap(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("agent swap", flag.ContinueOnError)
	dir := fs.String("state-dir", "", "agent state directory")
	plan := fs.String("plan", "", "swap plan JSON file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *plan == "" {
		return errors.New("usage: phylax agent swap -plan FILE")
	}
	raw, err := os.ReadFile(*plan)
	if err != nil {
		return err
	}
	if len(raw) > maxSwapPlanBytes {
		return errors.New("agent swap: plan file too large")
	}
	var p svcinstall.SwapPlan
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("agent swap: %w", err)
	}
	if p.StateDir == "" {
		p.StateDir = *dir
	}
	err = runSwap(ctx, p, svcinstall.New())
	if rm := os.Remove(*plan); rm != nil && !errors.Is(rm, os.ErrNotExist) {
		return errors.Join(err, rm)
	}
	return err
}

// startSwapHelper starts the swap helper detached: it must outlive the agent
// it is about to stop.
func startSwapHelper(planPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "agent", "swap", "-plan", planPath)
	cmd.SysProcAttr = detachAttr()
	if err := cmd.Start(); err != nil {
		// A Job Object that does not allow breakaway refuses the first attempt;
		// the detached process still outlives the service without it.
		cmd.SysProcAttr = detachAttrFallback()
		if err := cmd.Start(); err != nil {
			return err
		}
	}
	return cmd.Process.Release()
}
