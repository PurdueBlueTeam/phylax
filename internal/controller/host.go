package controller

import (
	"context"
	"errors"
	"log/slog"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/store"
	"github.com/PurdueBlueTeam/phylax/internal/ui"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

// moduleHost is the Host implementation handed to a controller module.
type moduleHost struct {
	c    *Controller
	m    module.ControllerModule
	name string
}

var _ module.Host = (*moduleHost)(nil)

// hostFor builds a module's Host handle.
func (c *Controller) hostFor(m module.ControllerModule) *moduleHost {
	return &moduleHost{c: c, m: m, name: m.Manifest().Name}
}

func (h *moduleHost) Config(v any) error              { panic("unimplemented: W1 Task 17") }
func (h *moduleHost) Query() store.Reader             { panic("unimplemented: W1 Task 17") }
func (h *moduleHost) Tables() (store.ModuleDB, error) { panic("unimplemented: W1 Task 17") }
func (h *moduleHost) Manifest() *manifest.Manifest    { panic("unimplemented: W1 Task 17a") }
func (h *moduleHost) UpdateOverrides(fn func(*manifest.Overrides) error) error {
	panic("unimplemented: W1 Task 17a")
}
func (h *moduleHost) Emit(e event.Event) error { panic("unimplemented: W1 Task 17") }
func (h *moduleHost) Subscribe(kinds []string, buf int) (<-chan event.Event, func()) {
	panic("unimplemented: W1 Task 18")
}
func (h *moduleHost) Propose(p module.Proposal) error { panic("unimplemented: W1 Task 25") }
func (h *moduleHost) RunReadOnly(template string, params map[string]string) (string, error) {
	panic("unimplemented: W1 Task 23")
}
func (h *moduleHost) RunStanding(approvalID, template string, params map[string]string) (string, error) {
	panic("unimplemented: W1 Task 24")
}
func (h *moduleHost) RunAuto(template string, params map[string]string) (string, error) {
	panic("unimplemented: W1 Task 26")
}
func (h *moduleHost) Control(m module.ControlMsg) error { panic("unimplemented: W1 Task 30") }
func (h *moduleHost) Secrets(names ...string) (vault.Reader, error) {
	panic("unimplemented: W1 Task 17")
}
func (h *moduleHost) UI() ui.Registrar     { panic("unimplemented: W1 Task 17") }
func (h *moduleHost) Logger() *slog.Logger { panic("unimplemented: W1 Task 17") }

// eventBus is the committed-event fan-out to controller modules.
type eventBus struct{}

func (b *eventBus) dropped(module string) uint64 { return 0 }
func (b *eventBus) publish(evs []event.Event)    {}

// hostsMatching resolves a label expression against the loaded manifest.
func (c *Controller) hostsMatching(expr string) ([]string, error) {
	c.cfgs.mu.Lock()
	m := c.cfgs.in
	c.cfgs.mu.Unlock()
	var man *manifest.Manifest
	if m != nil {
		man = m.Manifest
	}
	if man == nil {
		if c.cfg.ManifestPath == "" {
			return nil, errors.New("no manifest is loaded")
		}
		var err error
		if man, err = manifest.LoadDir(c.cfg.ManifestPath, manifest.Options{}); err != nil {
			return nil, err
		}
	}
	e, err := manifest.ParseLabels(expr)
	if err != nil {
		return nil, err
	}
	return man.HostsMatching(e), nil
}

var _ = context.Background
