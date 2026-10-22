// Package firewall applies host firewall policy safely (design: Execution,
// "fw.apply"; Topology, "Rule hygiene and bring-up"; "Dead-man switch").
//
// Linux: the typed render.HostPolicy is translated to nftables objects
// (tables, chains, named sets, rules) and installed natively over netlink with
// github.com/google/nftables in ONE batch, so the kernel swaps our tables
// atomically. We never touch a table we do not own; foreign tables are only
// detected and reported. Before applying, the previous state of our tables is
// snapshotted and a dead-man entry is armed whose rollback restores exactly
// that snapshot. After applying, the kernel state is read back and diffed
// against what was declared.
//
// Windows: the render.WinPolicy is applied through the Windows Firewall COM
// API (HNetCfg.FwPolicy2), touching only rules in the Phylax groups. The
// translation, snapshot, rollback, verify and drift logic is platform
// independent and runs against a Backend interface, so it is unit tested with a
// fake on Linux.
//
// Everything shared between the platforms lives in this file.
package firewall

import (
	"errors"
	"time"
)

// Mode selects what Apply installs.
type Mode string

// Modes.
const (
	// ModeEnforce installs the policy as rendered.
	ModeEnforce Mode = "enforce"
	// ModeShadow (Linux only) installs the policy with every drop replaced by a
	// log rule and accept policies, so nothing is blocked but would-be drops are
	// logged. On Windows the agent evaluates shadow offline; Apply refuses it.
	ModeShadow Mode = "shadow"
)

// Errors shared by both platforms.
var (
	// ErrNoManagement: the policy would drop by default but declares no
	// management rule, so applying it could cut the agent link.
	ErrNoManagement = errors.New("firewall: policy has default-drop but no management rules; refusing (set AllowNoManagement to override)")
	// ErrShadowUnsupported: shadow mode is not a firewall operation on Windows.
	ErrShadowUnsupported = errors.New("firewall: shadow mode is evaluated by the agent on Windows, not installed")
)

// Dead-man entry kinds registered by this package.
const (
	KindNftRestore = "fw.nft.restore"
	KindWinRestore = "fw.win.restore"
)

// SnapshotVersion is the snapshot schema version.
const SnapshotVersion = 1

// ErrVerify is returned (wrapped) when the kernel state read back after an
// apply differs from what was declared. Apply has already rolled back.
var ErrVerify = errors.New("firewall: verification failed after apply")

// ApplyOptions tunes Apply.
type ApplyOptions struct {
	Mode              Mode
	AllowNoManagement bool
	// DeadmanID and Timeout arm the dead-man switch before the change. Both
	// must be set for it to be armed; NodeID is recorded in the entry.
	DeadmanID string
	NodeID    string
	Timeout   time.Duration
}
