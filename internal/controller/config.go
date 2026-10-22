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
}

func (c *Config) applyDefaults() {
	if c.AgentListen == "" {
		c.AgentListen = "0.0.0.0:7443"
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
}

// Validate applies defaults and checks the config.
func (c *Config) Validate() error {
	c.applyDefaults()
	if c.DataDir == "" {
		return fmt.Errorf("controller config: data_dir is required")
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
