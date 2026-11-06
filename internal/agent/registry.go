package agent

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// ErrUnavailable is returned by a Factory's Build when the module cannot run
// on this host (wrong platform, missing privilege, missing prerequisite). The
// module is then reported as unavailable in the config status instead of
// crash-looping.
var ErrUnavailable = errors.New("module unavailable on this host")

// Env is what a factory may use to build a module.
type Env struct {
	Host     string
	StateDir string
	Logger   *slog.Logger
	// PlanKey is the controller's plan-signing public key (nil if none).
	PlanKey ed25519.PublicKey
	// Health is the agent as the health module's data source.
	Health HealthSource
	// Name is the factory name and Consumes its manifest's kind list. The
	// reconciler fills both for a contract module.
	Name     string
	Consumes []string

	a           *Agent
	hasManifest bool
}

// Subscribe returns a bounded stream of the agent's module events. With kinds,
// only those kinds are delivered. A kind outside a contract module's
// Manifest.Consumes is dropped from the filter. A full channel drops events
// rather than blocking the emitter. Call the returned function to unsubscribe.
func (e Env) Subscribe(buf int, kinds ...string) (<-chan event.Event, func()) {
	if len(kinds) == 0 {
		return e.a.subscribe(buf)
	}
	if e.hasManifest {
		allowed := make(map[string]bool, len(e.Consumes))
		for _, k := range e.Consumes {
			allowed[k] = true
		}
		kept := make([]string, 0, len(kinds))
		var dropped []string
		for _, k := range kinds {
			if allowed[k] {
				kept = append(kept, k)
			} else {
				dropped = append(dropped, k)
			}
		}
		if len(dropped) > 0 && e.Logger != nil {
			e.Logger.Warn("module subscribed to kinds outside its manifest", "module", e.Name, "kinds", dropped)
		}
		kinds = kept
	}
	return e.a.subscribe(buf, kinds...)
}

// Fact returns a controller fact by id; false when never received or expired.
func (e Env) Fact(id string) (event.ControllerFact, bool) { panic("unimplemented: W1 Task 31") }

// Keep stores a value that survives the module being replaced by a
// reconfiguration (for example learned detection baselines).
func (e Env) Keep(key string, v any) { e.a.kept.Store(key, v) }

// Kept returns a value stored with Keep.
func (e Env) Kept(key string) any { v, _ := e.a.kept.Load(key); return v }

// Factory builds one kind of module from the signed agent config. Packages
// register their factory from init (platform build tags decide which exist).
type Factory struct {
	Name string
	// Manifest is the module's capability manifest; zero for a pre-contract module.
	Manifest module.Manifest
	// Section reports the fingerprint of the module's settings in cfg and
	// whether the module should run. An unchanged fingerprint leaves the
	// running module alone; a changed one replaces it.
	Section func(cfg *plan.AgentConfig) (fingerprint string, enabled bool)
	// Build creates the module and its limits. Return ErrUnavailable (wrapped)
	// when it cannot run here.
	Build func(env Env, cfg *plan.AgentConfig) (ModuleSpec, error)
}

var (
	regMu     sync.Mutex
	factories = map[string]Factory{}
)

// RegisterFactory adds a module factory to the process-wide registry. It
// panics on a duplicate name (a programming error caught at start-up).
func RegisterFactory(f Factory) {
	regMu.Lock()
	defer regMu.Unlock()
	if f.Name == "" || f.Section == nil || f.Build == nil {
		panic("agent: incomplete factory")
	}
	if _, dup := factories[f.Name]; dup {
		panic(fmt.Sprintf("agent: duplicate factory %q", f.Name))
	}
	if f.Manifest.Name != "" {
		if f.Manifest.Name != f.Name {
			panic(fmt.Sprintf("agent: factory %q manifest names %q", f.Name, f.Manifest.Name))
		}
		if err := f.Manifest.Validate(); err != nil {
			panic(fmt.Sprintf("agent: factory %q: %v", f.Name, err))
		}
	}
	factories[f.Name] = f
}

// Registered returns the process-wide factory registry, sorted by name.
func Registered() []Factory { return registered(nil) }

// moduleManifests returns the manifests of the agent's factories, for hello.
func (a *Agent) moduleManifests() []module.Manifest {
	var out []module.Manifest
	for _, f := range registered(a.cfg.Factories) {
		if f.Manifest.Name != "" {
			out = append(out, f.Manifest)
		}
	}
	return out
}

// registered returns the factories sorted by name, with extra overriding.
func registered(extra []Factory) []Factory {
	regMu.Lock()
	m := make(map[string]Factory, len(factories)+len(extra))
	for k, v := range factories {
		m[k] = v
	}
	regMu.Unlock()
	for _, f := range extra {
		m[f.Name] = f
	}
	out := make([]Factory, 0, len(m))
	for _, f := range m {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ---- event stream ----

type tap struct {
	ch      chan event.Event
	kinds   map[string]bool // nil: every kind
	dropped uint64
}

func (t *tap) wants(e event.Event) bool {
	return t.kinds == nil || t.kinds[e.Kind]
}

func (a *Agent) subscribe(buf int, kinds ...string) (<-chan event.Event, func()) {
	if buf <= 0 {
		buf = 1024
	}
	t := &tap{ch: make(chan event.Event, buf)}
	if kinds != nil {
		t.kinds = make(map[string]bool, len(kinds))
		for _, k := range kinds {
			t.kinds[k] = true
		}
	}
	a.tapMu.Lock()
	if a.subWait > 0 {
		a.subWait--
	}
	// Replay what was published while the consumer was starting (bounded by
	// the tap's capacity: the newest events win).
	h := a.held
	if len(h) > buf {
		h = h[len(h)-buf:]
	}
	for _, e := range h {
		if t.wants(e) {
			t.ch <- e
		}
	}
	a.taps = append(a.taps, t)
	a.settleLocked()
	a.tapMu.Unlock()
	return t.ch, func() {
		a.tapMu.Lock()
		for i, x := range a.taps {
			if x == t {
				a.taps = append(a.taps[:i:i], a.taps[i+1:]...)
				break
			}
		}
		a.tapMu.Unlock()
	}
}

// Start-up window: a module is reported running before it has subscribed to
// the event stream, so events published locally in between would be lost to
// local detection. The agent therefore holds a bounded buffer of published
// events while a module marked ModuleSpec.Subscriber has not yet subscribed
// (or a reconfiguration is in progress), and replays it to each subscriber as
// it arrives. The hold is bounded in size and time so a subscriber that never
// shows up cannot make the agent hoard events.
const (
	heldMax     = 4096
	holdTimeout = 15 * time.Second
)

// expectSubscriber records that spec's module will call Subscribe soon.
func (a *Agent) expectSubscriber(spec ModuleSpec) {
	if !spec.Subscriber {
		return
	}
	a.tapMu.Lock()
	a.subWait++
	a.holdUntil = time.Now().Add(holdTimeout)
	a.tapMu.Unlock()
}

// holdBegin / holdEnd bracket a reconfiguration, during which modules are
// being built and added in arbitrary order.
func (a *Agent) holdBegin() {
	a.tapMu.Lock()
	a.holds++
	a.holdUntil = time.Now().Add(holdTimeout)
	a.tapMu.Unlock()
}

func (a *Agent) holdEnd() {
	a.tapMu.Lock()
	if a.holds > 0 {
		a.holds--
	}
	a.settleLocked()
	a.tapMu.Unlock()
}

// settleLocked drops the buffer once nobody is awaited any more.
func (a *Agent) settleLocked() {
	if a.holds == 0 && a.subWait == 0 {
		a.held = nil
	}
}

// Held reports how many events are buffered awaiting a subscriber (tests).
func (a *Agent) Held() int {
	a.tapMu.Lock()
	defer a.tapMu.Unlock()
	return len(a.held)
}

// Subscribers reports how many modules currently listen to the event stream.
// A module is reported running before it subscribes, and events published in
// between are not replayed, so readiness checks (tests) wait on this.
func (a *Agent) Subscribers() int {
	a.tapMu.Lock()
	defer a.tapMu.Unlock()
	return len(a.taps)
}

// publish hands e to every subscriber without blocking.
func (a *Agent) publish(e event.Event) {
	a.tapMu.Lock()
	defer a.tapMu.Unlock()
	waiting := a.holds > 0 || a.subWait > 0
	if waiting && !a.holdUntil.IsZero() && time.Now().After(a.holdUntil) {
		a.holds, a.subWait, a.held, waiting = 0, 0, nil, false // give up waiting
	}
	if len(a.taps) == 0 && !waiting {
		return
	}
	if e.Agent == "" {
		e.Agent = a.bundle.Host
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if waiting {
		if len(a.held) >= heldMax {
			a.held = append(a.held[:0], a.held[1:]...)
		}
		a.held = append(a.held, e)
	}
	for _, t := range a.taps {
		if !t.wants(e) {
			continue
		}
		select {
		case t.ch <- e:
		default:
			t.dropped++
		}
	}
}
