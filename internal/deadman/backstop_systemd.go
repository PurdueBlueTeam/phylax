package deadman

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Systemd arms a transient systemd timer: `systemd-run --on-active=N ...
// <phylax> agent rollback <id>`. The timer and its service belong to systemd,
// not to the agent, so they fire even if the agent is killed. Only the timer is
// stopped on Disarm: a rollback already running keeps running.
type Systemd struct {
	Command Command
	// User uses the per-user manager (--user) instead of the system manager.
	User bool
	// Run defaults to ExecRunner.
	Run Runner
	// Now defaults to time.Now.
	Now func() time.Time
}

// UnitName is the transient unit base name for an entry id.
func UnitName(id string) string { return "phylax-deadman-" + id }

func (s *Systemd) base() []string {
	if s.User {
		return []string{"--user"}
	}
	return nil
}

func (s *Systemd) run() Runner {
	if s.Run != nil {
		return s.Run
	}
	return ExecRunner
}

func (s *Systemd) Arm(ctx context.Context, id string, deadline time.Time) error {
	if !ValidID(id) {
		return ErrBadID
	}
	cmd, err := s.Command.resolve()
	if err != nil {
		return err
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	// Replace semantics for re-arm after an agent restart.
	if err := s.Disarm(ctx, id); err != nil {
		return err
	}
	args := append(s.base(),
		"--unit="+UnitName(id),
		fmt.Sprintf("--on-active=%ds", ceilSeconds(deadline.Sub(now()))),
		"--timer-property=AccuracySec=1s",
		"--timer-property=RemainAfterElapse=no",
		"--description=Phylax dead-man rollback "+id,
		"--collect",
		"--",
	)
	args = append(args, cmd.argv(id)...)
	if _, err := s.run()(ctx, "systemd-run", args...); err != nil {
		return err
	}
	return nil
}

func (s *Systemd) Disarm(ctx context.Context, id string) error {
	if !ValidID(id) {
		return ErrBadID
	}
	args := append(s.base(), "stop", UnitName(id)+".timer")
	out, err := s.run()(ctx, "systemctl", args...)
	if err != nil && !strings.Contains(strings.ToLower(string(out)+err.Error()), "not loaded") {
		return err
	}
	return nil
}
