// Package module is the contract between the core and every module: capability
// manifests, health, configuration and the controller-side Host interface.
// It imports only core data packages, never another module.
package module

import (
	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// Side is the side of the link a module runs on.
type Side string

const (
	SideAgent      Side = "agent"
	SideController Side = "controller"
)

// Budget is a module's resource budget.
type Budget struct {
	CPUMillisPerSec int     `json:"cpu_ms_per_sec"`
	HeldMB          int     `json:"held_mb"`
	EventsPerSec    float64 `json:"events_per_sec"`
	Burst           int     `json:"burst"`
	BytesOutPerMin  int     `json:"bytes_out_per_min"`
	DiskMB          int     `json:"disk_mb"`
}

// Manifest is a module's capability manifest.
type Manifest struct {
	Name      string       `json:"name"`
	Sides     []Side       `json:"sides"`
	OS        []string     `json:"os,omitempty"`
	Privilege string       `json:"privilege"` // root | user | none
	Roles     []string     `json:"roles,omitempty"`
	Consumes  []string     `json:"consumes,omitempty"`
	Emits     []event.Type `json:"emits,omitempty"`
	Budget    Budget       `json:"budget"`
	Default   bool         `json:"default"`
	Tables    []string     `json:"tables,omitempty"`
	Content   []string     `json:"content,omitempty"`
	Actions   []string     `json:"actions,omitempty"`
	Pages     []string     `json:"pages,omitempty"`
	Evidence  []string     `json:"evidence,omitempty"`
}

// Validate checks the manifest's shape and naming rules.
func (m Manifest) Validate() error { panic("unimplemented: W1 Task 7") }

// Common is the generic part of every module's config block.
type Common struct {
	Enabled    bool     `json:"enabled" yaml:"enabled"`
	ActEnabled bool     `json:"act_enabled" yaml:"act_enabled"`
	Auto       []string `json:"auto,omitempty" yaml:"auto,omitempty"` // templates under plans/<module>/ that RunAuto may start
}

// State is a module's health state.
type State string

const (
	StateOK          State = "ok"
	StateDegraded    State = "degraded"
	StateUnavailable State = "unavailable"
	StateDisabled    State = "disabled"
	StateOverBudget  State = "over_budget"
	StateRestarting  State = "restarting"
	StateError       State = "error"
)

// Gap is a named missing capability or input.
type Gap struct {
	What string `json:"what"`
	Why  string `json:"why"`
}

// Usage is a module's resource use since the last report.
type Usage struct {
	CPUMillis uint64 `json:"cpu_ms"`
	HeldBytes uint64 `json:"held_bytes"`
	Events    uint64 `json:"events"`
	BytesOut  uint64 `json:"bytes_out"`
	Dropped   uint64 `json:"dropped"`
}

// Health is a module's health report.
type Health struct {
	State  State             `json:"state"`
	Detail string            `json:"detail,omitempty"`
	Gaps   []Gap             `json:"gaps,omitempty"`
	Usage  Usage             `json:"usage"`
	Info   map[string]string `json:"info,omitempty"`
}

// Effective is the enablement rule: the host's modules: entry, else the block's enabled, else the default.
func Effective(host, block *bool, def bool) bool {
	if host != nil {
		return *host
	}
	if block != nil {
		return *block
	}
	return def
}
