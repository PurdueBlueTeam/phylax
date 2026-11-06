// Package module is the contract between the core and every module: capability
// manifests, health, configuration and the controller-side Host interface.
// It imports only core data packages, never another module.
package module

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// Side is the side of the link a module runs on.
type Side string

const (
	SideAgent      Side = "agent"
	SideController Side = "controller"
)

// Manifest is a module's capability manifest.
type Manifest struct {
	Name      string       `json:"name"`
	Sides     []Side       `json:"sides"`
	OS        []string     `json:"os,omitempty"`
	Privilege string       `json:"privilege"` // root | user | none
	Roles     []string     `json:"roles,omitempty"`
	Consumes  []string     `json:"consumes,omitempty"`
	Emits     []event.Type `json:"emits,omitempty"`
	Default   bool         `json:"default"`
	Tables    []string     `json:"tables,omitempty"`
	Content   []string     `json:"content,omitempty"`
	Actions   []string     `json:"actions,omitempty"`
	Pages     []string     `json:"pages,omitempty"`
	Evidence  []string     `json:"evidence,omitempty"`
}

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{1,31}$`)

// commonKinds are the kinds every producer translates to; a module may emit
// these without a namespace prefix.
var commonKinds = map[string]bool{
	event.KindProcessStart: true,
	event.KindProcessExit:  true,
	event.KindFileChange:   true,
	event.KindConn:         true,
	event.KindListener:     true,
	event.KindAuthEvent:    true,
	event.KindDNSQuery:     true,
	event.KindTelemetryGap: true,
}

// coreModules may emit the agent.* core kinds.
var coreModules = map[string]bool{"health": true, "exec": true}

// Validate checks the manifest's shape and naming rules.
func (m Manifest) Validate() error {
	if !nameRE.MatchString(m.Name) {
		return fmt.Errorf("manifest: name %q must match %s", m.Name, nameRE)
	}
	if len(m.Sides) == 0 {
		return fmt.Errorf("manifest %s: sides is empty", m.Name)
	}
	seenSide := map[Side]bool{}
	for _, s := range m.Sides {
		if s != SideAgent && s != SideController {
			return fmt.Errorf("manifest %s: side %q", m.Name, s)
		}
		if seenSide[s] {
			return fmt.Errorf("manifest %s: duplicate side %q", m.Name, s)
		}
		seenSide[s] = true
	}
	for _, os := range m.OS {
		if os != "linux" && os != "windows" {
			return fmt.Errorf("manifest %s: os %q", m.Name, os)
		}
	}
	switch m.Privilege {
	case "root", "user", "none":
	default:
		return fmt.Errorf("manifest %s: privilege %q", m.Name, m.Privilege)
	}
	if m.Privilege == "none" && !(len(m.Sides) == 1 && m.Sides[0] == SideController) {
		return fmt.Errorf("manifest %s: privilege none needs sides exactly [controller]", m.Name)
	}
	for _, e := range m.Emits {
		if err := m.validateEmit(e.Kind); err != nil {
			return err
		}
	}
	for _, c := range m.Consumes {
		if c == "" || strings.Contains(c, "*") {
			return fmt.Errorf("manifest %s: consumes %q", m.Name, c)
		}
	}
	return nil
}

func (m Manifest) validateEmit(kind string) error {
	if kind == "" {
		return fmt.Errorf("manifest %s: empty emit kind", m.Name)
	}
	if commonKinds[kind] || strings.HasPrefix(kind, m.Name+".") {
		return nil
	}
	if coreModules[m.Name] && (strings.HasPrefix(kind, "agent.") || kind == event.KindTelemetryGap) {
		return nil
	}
	return fmt.Errorf("manifest %s: emit kind %q", m.Name, kind)
}

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
