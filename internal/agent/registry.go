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

	a *Agent
}

// Subscribe returns a bounded stream of every event the agent's modules emit
// (after their rate limit, before the spool, so spool shedding cannot blind a
// consumer). A full channel drops events rather than blocking the emitter.
// Call the returned function to unsubscribe.
func (e Env) Subscribe(buf int) (<-chan event.Event, func()) { return e.a.subscribe(buf) }

// Keep stores a value that survives the module being replaced by a
// reconfiguration (for example learned detection baselines).
func (e Env) Keep(key string, v any) { e.a.kept.Store(key, v) }

// Kept returns a value stored with Keep.
func (e Env) Kept(key string) any { v, _ := e.a.kept.Load(key); return v }

// Factory builds one kind of module from the signed agent config. Packages
// register their factory from init (platform build tags decide which exist).
type Factory struct {
	Name string
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
	factories[f.Name] = f
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
	dropped uint64
}

func (a *Agent) subscribe(buf int) (<-chan event.Event, func()) {
	if buf <= 0 {
		buf = 1024
	}
	t := &tap{ch: make(chan event.Event, buf)}
	a.tapMu.Lock()
	a.taps = append(a.taps, t)
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

// publish hands e to every subscriber without blocking.
func (a *Agent) publish(e event.Event) {
	a.tapMu.Lock()
	defer a.tapMu.Unlock()
	if len(a.taps) == 0 {
		return
	}
	if e.Agent == "" {
		e.Agent = a.bundle.Host
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	for _, t := range a.taps {
		select {
		case t.ch <- e:
		default:
			t.dropped++
		}
	}
}
