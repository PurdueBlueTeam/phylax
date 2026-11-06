package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

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

	subMu   sync.Mutex
	subs    map[uint64]func()
	nextSub uint64
}

var _ module.Host = (*moduleHost)(nil)

// hostFor builds a module's Host handle.
func (c *Controller) hostFor(m module.ControllerModule) *moduleHost {
	return &moduleHost{c: c, m: m, name: m.Manifest().Name}
}

// currentManifest returns the controller's current manifest. Before the config
// inputs are loaded it reads the manifest directory, so a controller started
// with manifest_path always has one.
func (c *Controller) currentManifest() (*manifest.Manifest, error) {
	c.cfgs.mu.Lock()
	in := c.cfgs.in
	c.cfgs.mu.Unlock()
	if in != nil && in.Manifest != nil {
		return in.Manifest, nil
	}
	if c.cfg.ManifestPath == "" {
		return nil, errors.New("controller: no manifest is loaded")
	}
	return manifest.LoadDir(c.cfg.ManifestPath, manifest.Options{})
}

// configBlock returns the module's modules/<name>.yml block.
func (h *moduleHost) configBlock() (manifest.ModuleBlock, bool) {
	m, err := h.c.currentManifest()
	if err != nil || m == nil {
		return manifest.ModuleBlock{}, false
	}
	b, ok := m.Modules[h.name]
	return b, ok
}

func (h *moduleHost) Config(v any) error {
	b, ok := h.configBlock()
	if !ok {
		return module.ErrNoConfig
	}
	return b.Decode(v)
}

func (h *moduleHost) Query() store.Reader { return h.c.st }

func (h *moduleHost) Tables() (store.ModuleDB, error) {
	m := h.m.Manifest()
	if len(m.Tables) == 0 {
		return nil, fmt.Errorf("%w: module %s declares no tables", module.ErrNotInScope, h.name)
	}
	return h.c.st.ModuleDB(h.name), nil
}

func (h *moduleHost) Manifest() *manifest.Manifest {
	m, err := h.c.currentManifest()
	if err != nil {
		return nil
	}
	return m
}

func (h *moduleHost) UpdateOverrides(fn func(*manifest.Overrides) error) error {
	if _, ok := h.configBlock(); !ok {
		return module.ErrNoConfig
	}
	if h.c.cfg.ManifestPath == "" {
		return errors.New("controller: no manifest directory")
	}
	h.c.manMu.Lock()
	defer h.c.manMu.Unlock()
	if err := manifest.AppendOverrides(h.c.cfg.ManifestPath, fn); err != nil {
		return err
	}
	m, err := manifest.LoadDir(h.c.cfg.ManifestPath, manifest.Options{})
	if err != nil {
		return err
	}
	// A controller with loaded config inputs keeps them (rules, ledger) and
	// swaps in the new manifest; one without reloads from disk on each use.
	h.c.cfgs.mu.Lock()
	if h.c.cfgs.in != nil {
		h.c.cfgs.in.Manifest = m
		h.c.cfgs.gen++
	}
	h.c.cfgs.mu.Unlock()
	return nil
}

func (h *moduleHost) Emit(e event.Event) error {
	m := h.m.Manifest()
	ok := false
	for _, t := range m.Emits {
		if t.Kind == e.Kind {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("%w: %s", module.ErrNotInScope, e.Kind)
	}
	e.Agent = ControllerAgent
	_, err := h.c.EmitController(context.Background(), e)
	return err
}

func (h *moduleHost) Subscribe(kinds []string, buf int) (<-chan event.Event, func()) {
	m := h.m.Manifest()
	allowed := map[string]bool{}
	for _, k := range m.Consumes {
		allowed[k] = true
	}
	keep := make([]string, 0, len(kinds))
	for _, k := range kinds {
		if allowed[k] {
			keep = append(keep, k)
			continue
		}
		h.Logger().Warn("module subscribe: kind is not in the manifest consumes", "kind", k)
	}
	ch, stop := h.c.bus.subscribe(h.name, keep, buf)
	h.subMu.Lock()
	if h.subs == nil {
		h.subs = map[uint64]func(){}
	}
	h.nextSub++
	id := h.nextSub
	h.subs[id] = stop
	h.subMu.Unlock()
	return ch, func() {
		h.subMu.Lock()
		delete(h.subs, id)
		h.subMu.Unlock()
		stop()
	}
}

// stopSubscriptions closes every subscription the module opened through this
// Host. The runner calls it after each Start returns, so a restart cannot leak
// a subscriber (and its buffered events).
func (h *moduleHost) stopSubscriptions() {
	h.subMu.Lock()
	subs := h.subs
	h.subs = nil
	h.subMu.Unlock()
	for _, stop := range subs {
		stop()
	}
}

func (h *moduleHost) Propose(p module.Proposal) error {
	p.Module = h.name
	_, err := h.c.Propose(context.Background(), p)
	return err
}
func (h *moduleHost) RunReadOnly(template string, params map[string]string) (string, error) {
	return h.c.RunReadOnly(context.Background(), h.name, template, params)
}
func (h *moduleHost) RunStanding(approvalID, template string, params map[string]string) (string, error) {
	return h.c.RunStanding(context.Background(), h.name, approvalID, template, params)
}
func (h *moduleHost) RunAuto(template string, params map[string]string) (string, error) {
	panic("unimplemented: W1 Task 26")
}
func (h *moduleHost) Control(m module.ControlMsg) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return h.c.SendFact(ctx, h.name, m)
}

func (h *moduleHost) Secrets(names ...string) (vault.Reader, error) {
	if h.c.opt.Vault == nil {
		return nil, vault.ErrLocked
	}
	if l, ok := h.c.opt.Vault.(interface{ Locked() bool }); ok && l.Locked() {
		return nil, vault.ErrLocked
	}
	b, ok := h.configBlock()
	if !ok {
		return nil, module.ErrNoConfig
	}
	grants, err := blockStrings(b.Raw)
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		if !vault.Covers(grants, n) {
			return nil, fmt.Errorf("%w: %s", vault.ErrNotAllowed, n)
		}
	}
	return vault.Scoped(h.c.opt.Vault, names), nil
}

// blockStrings returns every string value in a YAML block (mapping keys are
// not values). A value ending in "/*" is a prefix grant for Secrets.
func blockStrings(raw []byte) ([]string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var out []string
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		switch n.Kind {
		case yaml.DocumentNode, yaml.SequenceNode:
			for _, c := range n.Content {
				walk(c)
			}
		case yaml.MappingNode:
			for i := 1; i < len(n.Content); i += 2 {
				walk(n.Content[i])
			}
		case yaml.ScalarNode:
			if n.Tag == "!!str" {
				out = append(out, n.Value)
			}
		}
	}
	if doc.Kind != 0 {
		walk(&doc)
	}
	return out, nil
}

func (h *moduleHost) UI() ui.Registrar {
	h.c.uiMu.Lock()
	s := h.c.ui
	h.c.uiMu.Unlock()
	if s == nil {
		return ui.Discard
	}
	return s.Registrar(h.name, func() bool { return h.c.moduleRunning(h.name) })
}

func (h *moduleHost) Logger() *slog.Logger { return h.c.log.With("module", h.name) }

// moduleRunning reports whether the controller module runner has the module
// in its running state.
func (c *Controller) moduleRunning(name string) bool {
	c.runMu.Lock()
	defer c.runMu.Unlock()
	return c.running[name]
}

// hostsMatching resolves a label expression against the loaded manifest.
func (c *Controller) hostsMatching(expr string) ([]string, error) {
	man, err := c.currentManifest()
	if err != nil {
		return nil, err
	}
	e, err := manifest.ParseLabels(expr)
	if err != nil {
		return nil, err
	}
	return man.HostsMatching(e), nil
}
