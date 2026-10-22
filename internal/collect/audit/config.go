//go:build linux

package audit

import (
	"log/slog"
	"os"
	"time"
)

// Event kinds emitted by the module.
const (
	KindProcessStart = "process_start" // design rule-format event type for exec
	KindFileChange   = "file_change"
	KindNetConnect   = "net_connect"
	KindGap          = "telemetry_gap"
	KindRulesChanged = "audit.rules_changed"
)

// Audit rule keys. Everything we install carries a key with KeyPrefix so that
// verification and cleanup never touch rules we do not own.
const (
	KeyPrefix = "phylax"
	KeyExec   = "phylax_exec"
	KeyFIM    = "phylax_fim"
	KeyNet    = "phylax_net"
	KeySelf   = "phylax_self"
)

// Config tunes the module. The zero value is usable; New fills defaults.
type Config struct {
	// Mode is "auto" (multicast when auditd runs, else unicast), "multicast"
	// or "unicast".
	Mode string

	// WebRoots are content roots watched (recursively) and swept.
	WebRoots []string
	// ExtraWatches are additional persistence paths (files or directories).
	ExtraWatches []string
	// SelfPaths are the agent's own binary, unit and config; watched under
	// KeySelf so that tampering by anyone else is reported.
	SelfPaths []string
	// ExcludePaths are prefixes whose events are dropped to avoid feedback
	// loops (spool, state, logs). Events whose writer is the agent's own pid
	// are always dropped.
	ExcludePaths []string
	// NetRules adds connect/accept rules (default off; high volume).
	NetRules bool

	// BacklogLimit is the kernel audit backlog (default 8192). Zero value
	// means default; ManageSettings=false leaves global settings untouched.
	BacklogLimit uint32
	// ManageSettings lets the module set backlog, failure mode, enabled and
	// (unicast) the audit pid. Default true (see NoManageSettings).
	NoManageSettings bool
	// NoRules skips rule installation (read-only observer).
	NoRules bool
	// RemoveRulesOnExit deletes the rules this module installed on shutdown.
	// Production leaves them in place (the kernel keeps recording while the
	// agent restarts); tests clean up after themselves.
	RemoveRulesOnExit bool

	// VerifyInterval is the rule/health check period (default 10 s).
	VerifyInterval time.Duration

	// Sweep: SweepInterval 0 means default 5 min; negative disables.
	SweepInterval time.Duration
	// SweepFilesPerSec throttles hashing (default 400).
	SweepFilesPerSec int
	// SweepHashMaxBytes: larger files are compared by size and mtime only
	// (default 8 MiB).
	SweepHashMaxBytes int64
	// SweepMaxEntries bounds one snapshot (default 200000).
	SweepMaxEntries int
	// SweepDepth bounds directory depth (default 8).
	SweepDepth int
	// SweepStartDelay delays the baseline sweep (default 5 s).
	SweepStartDelay time.Duration

	// Per-event caps.
	MaxArgs      int // default 512
	MaxArgBytes  int // default 4096
	MaxArgvBytes int // default 32768
	MaxPaths     int // default 16

	// RatePerSec / Burst cap emitted events (default 2000 / 4000). Excess
	// events are dropped and reported in telemetry_gap{reason=rate_limited}.
	RatePerSec float64
	Burst      int
	// QueueLen bounds the reader to parser queue (default 16384).
	QueueLen int

	// ProcRoot is the procfs mount (default /proc).
	ProcRoot string
	// Key overrides nothing today; reserved for test isolation of rules.
	// TestKeySuffix is appended to every rule key (tests only).
	TestKeySuffix string

	Logger *slog.Logger

	// self identity (overridable for tests)
	selfPID int
}

func (c *Config) defaults() {
	if c.Mode == "" {
		c.Mode = "auto"
	}
	if c.BacklogLimit == 0 {
		c.BacklogLimit = 8192
	}
	if c.VerifyInterval <= 0 {
		c.VerifyInterval = 10 * time.Second
	}
	if c.SweepInterval == 0 {
		c.SweepInterval = 5 * time.Minute
	}
	if c.SweepFilesPerSec <= 0 {
		c.SweepFilesPerSec = 400
	}
	if c.SweepHashMaxBytes <= 0 {
		c.SweepHashMaxBytes = 8 << 20
	}
	if c.SweepMaxEntries <= 0 {
		c.SweepMaxEntries = 200000
	}
	if c.SweepDepth <= 0 {
		c.SweepDepth = 8
	}
	if c.SweepStartDelay <= 0 {
		c.SweepStartDelay = 5 * time.Second
	}
	if c.MaxArgs <= 0 {
		c.MaxArgs = 512
	}
	if c.MaxArgBytes <= 0 {
		c.MaxArgBytes = 4096
	}
	if c.MaxArgvBytes <= 0 {
		c.MaxArgvBytes = 32768
	}
	if c.MaxPaths <= 0 {
		c.MaxPaths = 16
	}
	if c.RatePerSec <= 0 {
		c.RatePerSec = 2000
	}
	if c.Burst <= 0 {
		c.Burst = 4000
	}
	if c.QueueLen <= 0 {
		c.QueueLen = 16384
	}
	if c.ProcRoot == "" {
		c.ProcRoot = "/proc"
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.selfPID == 0 {
		c.selfPID = os.Getpid()
	}
}

func (c *Config) limits() Limits {
	return Limits{MaxArgs: c.MaxArgs, MaxArgBytes: c.MaxArgBytes, MaxArgvBytes: c.MaxArgvBytes, MaxPaths: c.MaxPaths}
}
