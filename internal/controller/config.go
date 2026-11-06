// Package controller is the core of `phylax serve`: the agent-facing listener,
// enrollment tokens, the per-agent ingest pipeline (reorder buffer, store,
// ack), heartbeat and silence tracking.
package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Duration is a time.Duration that reads from JSON as a string ("30s").
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"30s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// Config is the controller configuration file (JSON).
type Config struct {
	// AgentListen is the single agent-port listener (default "0.0.0.0:7443").
	AgentListen string `json:"agent_listen"`
	// DataDir holds the event store, token file and (by default) the identity.
	DataDir string `json:"data_dir"`
	// IdentityPath defaults to DataDir/identity.pem; created on first run.
	IdentityPath string `json:"identity_path"`
	// ManifestPath is the manifest directory. Optional: when set, enrollment
	// tokens can only be minted for hosts the manifest declares.
	ManifestPath string `json:"manifest_path"`
	// RulesPath is the detection rules directory (*.yml); with ManifestPath it
	// makes the controller generate and sign every agent's config. Optional:
	// without it hosts get no detect module.
	RulesPath string `json:"rules_path"`
	// LedgerPath is the signed reference ledger; agents receive its hash in
	// their config and load the file from their state directory.
	LedgerPath string `json:"ledger_path"`
	// UIListen is the operator web UI address (default "127.0.0.1:8443"; must
	// be loopback; "off" disables the UI).
	UIListen string `json:"ui_listen"`
	// PlansPath is the plan template directory (YAML files).
	PlansPath string `json:"plans_path"`
	// Team is the team number used in report and inject file names and in the
	// IR From line (1..99). Required before an IR or inject can be drafted.
	Team int `json:"team"`
	// NextIncident and NextInject are the first numbers offered for new
	// drafts (default 1); later drafts continue after the highest used.
	NextIncident int `json:"next_incident"`
	NextInject   int `json:"next_inject"`
	// ForbiddenWords must not appear in a submission (the school name, in
	// every spelling); the pre-submit validator fails when one does.
	ForbiddenWords []string `json:"forbidden_words"`
	// SilenceThreshold: an enrolled agent not heard from for this long raises
	// an agent.silent alert (default 30s).
	SilenceThreshold  Duration `json:"silence_threshold"`
	HelloTimeout      Duration `json:"hello_timeout"`       // default 10s
	ReadIdle          Duration `json:"read_idle"`           // default 20s
	MaxHandshakes     int      `json:"max_handshakes"`      // default 128
	MaxConns          int      `json:"max_conns"`           // default 4096
	ReorderWindow     uint64   `json:"reorder_window"`      // sequences ahead of the ack accepted (default 65536)
	MaxBufferedEvents int      `json:"max_buffered_events"` // per-agent reorder buffer cap (default 16384)
	MaxLiveTokens     int      `json:"max_live_tokens"`     // default 1024
	ReleaseDir        string   `json:"release_dir"`         // phylax-linux-amd64 and phylax-windows-amd64.exe
	// Advertise is the controller host:port the agent dials (serve
	// -advertise): the address in the one-liner and in the bootstrap config.
	Advertise string `json:"advertise"`
	// BenchOff disables the bench recorder, which is on by default in every
	// mode including observe mode.
	BenchOff bool `json:"bench_off"`
	// BenchInterval is how often the recorder samples (default 10s).
	BenchInterval Duration `json:"bench_interval"`
	// BenchMaxMB bounds the bench file before it rotates to <path>.1 (default
	// 64).
	BenchMaxMB int `json:"bench_max_mb"`
	// VaultPath is the secrets vault file; when set it is part of a snapshot.
	VaultPath string `json:"vault_path"`
	// SnapshotDirs are the directories the controller writes its encrypted
	// state snapshots to (a mounted share or the backup box path). Empty
	// disables the snapshot writer.
	SnapshotDirs []string `json:"snapshot_dirs"`
	// SnapshotInterval is how often a snapshot is written (default 15m).
	SnapshotInterval Duration `json:"snapshot_interval"`
}

func (c *Config) applyDefaults() {
	if c.AgentListen == "" {
		c.AgentListen = "0.0.0.0:7443"
	}
	if c.UIListen == "" {
		c.UIListen = "127.0.0.1:8443"
	}
	if c.IdentityPath == "" && c.DataDir != "" {
		c.IdentityPath = filepath.Join(c.DataDir, "identity.pem")
	}
	def := func(d *Duration, v time.Duration) {
		if *d <= 0 {
			*d = Duration(v)
		}
	}
	def(&c.SilenceThreshold, 30*time.Second)
	def(&c.HelloTimeout, 10*time.Second)
	def(&c.ReadIdle, 20*time.Second)
	if c.ReorderWindow == 0 {
		c.ReorderWindow = 1 << 16
	}
	if c.MaxBufferedEvents <= 0 {
		c.MaxBufferedEvents = 16384
	}
	if c.MaxLiveTokens <= 0 {
		c.MaxLiveTokens = 1024
	}
	if c.NextIncident <= 0 {
		c.NextIncident = 1
	}
	if c.NextInject <= 0 {
		c.NextInject = 1
	}
	def(&c.BenchInterval, 10*time.Second)
	if c.BenchMaxMB <= 0 {
		c.BenchMaxMB = 64
	}
	def(&c.SnapshotInterval, 15*time.Minute)
}

// Validate applies defaults and checks the config.
func (c *Config) Validate() error {
	c.applyDefaults()
	if c.DataDir == "" {
		return fmt.Errorf("controller config: data_dir is required")
	}
	if c.Team < 0 || c.Team > 99 {
		return fmt.Errorf("controller config: team must be 1..99 (or 0 when unset)")
	}
	return nil
}

// LoadConfig reads and validates a config file; unknown keys are an error.
func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("controller config %s: %w", path, err)
	}
	return c, c.Validate()
}
