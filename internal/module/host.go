package module

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/store"
	"github.com/PurdueBlueTeam/phylax/internal/ui"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

var (
	ErrNoConfig   = errors.New("module: no config block")
	ErrNotInScope = errors.New("module: not in the module's manifest")
	ErrProposed   = errors.New("module: plan not started; a click proposal was created")
)

// Host is what the controller gives a module.
type Host interface {
	Config(v any) error                                       // strict decode of modules/<name>.yml; ErrNoConfig when absent
	Query() store.Reader                                      // read-only event queries
	Tables() (store.ModuleDB, error)                          // the module's own tables; error unless Manifest.Tables is non-empty
	Manifest() *manifest.Manifest                             // the loaded manifest; read-only by convention
	UpdateOverrides(fn func(*manifest.Overrides) error) error // atomic read-modify-write of overrides.yml; the manifest reloads
	Emit(e event.Event) error                                 // stored under agent "controller"; kind must be in Manifest.Emits
	Subscribe(kinds []string, buf int) (<-chan event.Event, func())
	Propose(p Proposal) error // a one-click suggestion; never applies
	RunReadOnly(template string, params map[string]string) (planID string, err error)
	RunStanding(approvalID, template string, params map[string]string) (planID string, err error) // ErrProposed when out of scope
	RunAuto(template string, params map[string]string) (planID string, err error)                 // ErrProposed when an auto condition fails
	Control(m ControlMsg) error                                                                   // a signed control: fact to agents
	Secrets(names ...string) (vault.Reader, error)                                                // names must be covered by a string in the module's config block; "cred/*" grants a prefix
	UI() ui.Registrar
	Logger() *slog.Logger
}

// ControlMsg is a signed control: fact sent to agents.
type ControlMsg struct {
	Type  string         // "fact"
	Hosts []string       // agent names, or label expressions (manifest.ParseLabels)
	Fact  string         // subtype: work_window | round_clock | gpo_finding | scorer_probe_result | creds_txn
	ID    string         // a later fact with the same ID replaces the earlier one
	Data  map[string]any // typed by the subtype; at most plan.MaxFactData bytes encoded
	TTL   time.Duration  // > 0 and <= plan.MaxFactTTL
}

// EventRef identifies one stored event.
type EventRef struct {
	Agent string `json:"agent"`
	Seq   uint64 `json:"seq"`
}

// Proposal is a one-click plan suggestion.
type Proposal struct {
	Module   string // set by the Host
	Title    string // one line, shown on the button
	Template string // plan template under plans/<module>/
	Params   map[string]string
	Evidence []EventRef
	Reason   string // why a click is needed (the failed auto condition, or "tier 1")
}

// ControllerModule is a module running on the controller.
type ControllerModule interface {
	Manifest() Manifest
	Start(ctx context.Context, h Host) error // runs until ctx ends; ErrNoConfig means unavailable
	Health() Health
}

// Analyzer is a pure function over the event store.
type Analyzer struct {
	Name   string
	Inputs []string      // kinds it reads; also the trigger set
	Every  time.Duration // 0: on trigger only
	Run    func(ctx context.Context, q store.Reader, now time.Time) ([]event.Event, error)
}

// AnalyzerProvider is implemented by a module with analysers.
type AnalyzerProvider interface{ Analyzers() []Analyzer }

// Configurable is implemented by a module with a typed config block.
type Configurable interface{ ConfigBlock() any }
