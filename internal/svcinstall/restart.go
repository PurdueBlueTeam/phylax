package svcinstall

import (
	"context"
	"time"
)

// Installer installs, stops and removes the service on the current platform.
type Installer interface {
	// Install registers the service, enables it at boot with restart-always
	// semantics and starts it.
	Install(ctx context.Context, s Spec) error
	Uninstall(ctx context.Context, name string) error
	// Stop stops the service and waits until it is stopped. A service that is
	// already stopped is not an error: the swap helper needs the agent gone
	// before it replaces a running binary or starts a second agent on the same
	// state directory.
	Stop(ctx context.Context, name string) error
	// Restart starts the service again (a stopped service starts, a running one
	// restarts).
	Restart(ctx context.Context, name string) error
}

// SwapPlan is the JSON the swap helper (`phylax agent swap`) reads: one
// agent.replace_binary or agent.rename, reverted when the new agent does not
// reach its first controller ack within WaitSec.
type SwapPlan struct {
	Kind       string   // "replace_binary" | "rename"
	Service    string   // the running service: stopped first, restarted on a revert
	OldBinary  string   // replace_binary: the running binary
	NewBinary  string   // replace_binary: the verified new file; rename: a copy of the running binary at the new path
	NewService string   // rename only
	StateDir   string   // where the agent writes started.json
	WaitSec    int      // default 30
	Args       []string // rename: the install args for the new service
}

// Started is <state>/started.json: the agent writes it after the first
// controller ack of each process, so the swap helper can tell a working new
// agent from one that never connected.
type Started struct {
	PID  int       `json:"pid"`
	Time time.Time `json:"time"`
}
