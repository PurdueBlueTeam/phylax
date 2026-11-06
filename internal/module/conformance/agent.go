package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// errLinkDown is what the harness emit returns while check 6 runs.
var errLinkDown = errors.New("conformance: link down")

// AgentCase is one agent module under test.
type AgentCase struct {
	Factory  agent.Factory
	Default  *plan.AgentConfig // the module's default block on a fixture host
	Reconfig *plan.AgentConfig // a changed block (check 8)
	KeepKey  string            // key the module stores with Env.Keep; "" when it keeps nothing
	Load     []event.Event     // consumed events fed on the bus (checks 6 and 7)
	Block    any               // pointer to a zero settings struct (check 8); nil: plan.BlockFor(Default, Factory.Name)
}

// Agent runs the agent-side conformance checks.
func Agent(t *testing.T, c AgentCase) {
	t.Helper()
	errs := runAgentChecks(c)
	names := make([]string, 0, len(errs))
	for name := range errs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		err := errs[name]
		t.Run(name, func(t *testing.T) {
			if err != nil {
				t.Error(err)
			}
		})
	}
}

// runAgentChecks returns one error per named check. A check panicking is a
// failure of that check, not of the suite.
func runAgentChecks(c AgentCase) map[string]error {
	checks := []struct {
		name string
		fn   func(AgentCase) error
	}{
		{"no_config", checkNoConfig},
		{"default_config", checkDefaultConfig},
		{"stops_cleanly", checkStopsCleanly},
		{"health", checkHealth},
		{"declared_kinds", checkDeclaredKinds},
		{"link_loss", checkLinkLoss},
		{"reconfig", checkReconfig},
		{"config_decode", checkConfigDecode},
	}
	errs := make(map[string]error, len(checks))
	for _, ch := range checks {
		errs[ch.name] = safeCheck(ch.name, c, ch.fn)
	}
	return errs
}

// safeCheck turns a panic out of a check into that check's error.
func safeCheck(name string, c AgentCase, fn func(AgentCase) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%s: panic: %v", c.Factory.Name, r)
		}
	}()
	return fn(c)
}

// newHarness builds a real harness for one check, with a fresh state dir. The
// returned cleanup removes the state dir.
func newHarness(c AgentCase, emitErr func() error) (*agent.Harness, func(), error) {
	return newHarnessFor(c.Factory, c.Default, emitErr)
}

func newHarnessFor(f agent.Factory, def *plan.AgentConfig, emitErr func() error) (*agent.Harness, func(), error) {
	host := "h1"
	if def != nil && def.Host != "" {
		host = def.Host
	}
	dir, err := os.MkdirTemp("", "phylax-conformance-*")
	if err != nil {
		return nil, nil, err
	}
	h, err := agent.NewHarness(agent.HarnessOptions{
		Host:      host,
		StateDir:  dir,
		Factories: []agent.Factory{f},
		EmitErr:   emitErr,
	})
	if err != nil {
		os.RemoveAll(dir)
		return nil, nil, err
	}
	return h, func() { os.RemoveAll(dir) }, nil
}

// waitFor polls a module's health until ok reports true or d elapses.
func waitFor(h *agent.Harness, name string, d time.Duration, ok func(module.Health, bool) bool) (module.Health, bool) {
	deadline := time.Now().Add(d)
	for {
		hl, present := h.Health(name)
		if ok(hl, present) {
			return hl, true
		}
		if time.Now().After(deadline) {
			return hl, false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func running(hl module.Health, present bool) bool { return present && hl.State == module.StateOK }

// checkNoConfig is check 1: a module without its config block is disabled or
// refuses to build; it never panics and never runs.
func checkNoConfig(c AgentCase) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%s: panic with an empty config: %v", c.Factory.Name, r)
		}
	}()
	if _, on := c.Factory.Section(&plan.AgentConfig{}); !on {
		return nil
	}
	h, cleanup, herr := newHarness(c, nil)
	if herr != nil {
		return herr
	}
	defer cleanup()
	h.Apply(&plan.AgentConfig{})
	hl, present := h.Health(c.Factory.Name)
	if present && hl.State == module.StateUnavailable {
		return nil
	}
	return fmt.Errorf("%s: runs with no config block (health %+v, present %v); Section must report disabled or Build must return agent.ErrUnavailable",
		c.Factory.Name, hl, present)
}

// checkDefaultConfig is check 2: with the module's default block, health
// reaches ok (or unavailable when the host cannot run it) within 10 s.
func checkDefaultConfig(c AgentCase) error {
	h, cleanup, err := newHarness(c, nil)
	if err != nil {
		return err
	}
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	h.Apply(c.Default)
	hl, ok := waitFor(h, c.Factory.Name, 10*time.Second, func(hl module.Health, present bool) bool {
		return present && (hl.State == module.StateOK || hl.State == module.StateUnavailable)
	})
	if !ok {
		return fmt.Errorf("%s: health did not reach ok or unavailable within 10s: %+v", c.Factory.Name, hl)
	}
	return nil
}

// agentSettle lets a just-started module reach its first statement before a
// check cancels its context; a module reporting ok while still starting would
// otherwise race the stop check.
const agentSettle = 100 * time.Millisecond

// settled reports health that has left the start-up window.
func settled(hl module.Health, present bool) bool {
	if !present {
		return false
	}
	return !(hl.State == module.StateDegraded && hl.Detail == "starting")
}

// gapReported reports the state a module must show for a platform or privilege
// it cannot serve here: unavailable or degraded, naming the gap.
func gapReported(hl module.Health) bool {
	return (hl.State == module.StateUnavailable || hl.State == module.StateDegraded) && len(hl.Gaps) > 0
}

// runningAsRoot reports whether this process can serve a root-privilege module.
func runningAsRoot() bool {
	return runtime.GOOS != "windows" && os.Geteuid() == 0
}

// checkHealth is check 4: a health block appears within 5 s, and an OS the
// manifest does not run here, or root privilege without root, is a reported gap.
func checkHealth(c AgentCase) error {
	h, cleanup, err := newHarness(c, nil)
	if err != nil {
		return err
	}
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	h.Apply(c.Default)
	hl, ok := waitFor(h, c.Factory.Name, 5*time.Second, settled)
	if !ok {
		return fmt.Errorf("%s: no health block within 5s", c.Factory.Name)
	}
	for _, goos := range c.Factory.Manifest.OS {
		if goos == runtime.GOOS {
			continue
		}
		if !gapReported(hl) {
			return fmt.Errorf("%s: manifest runs on %s, this host is %s, but health is %q with gaps %v",
				c.Factory.Name, goos, runtime.GOOS, hl.State, hl.Gaps)
		}
	}
	if c.Factory.Manifest.Privilege == "root" && !runningAsRoot() && !gapReported(hl) {
		return fmt.Errorf("%s: needs root, this process is not root, but health is %q with gaps %v",
			c.Factory.Name, hl.State, hl.Gaps)
	}
	return nil
}

// checkDeclaredKinds is checks 5 and 11: a consumed kind is declared, and
// every emitted kind is in the manifest and validates against its declaration
// (so a non-canonical field such as conn.src_ip is refused).
func checkDeclaredKinds(c AgentCase) error {
	for _, k := range c.Factory.Manifest.Consumes {
		if _, ok := event.Lookup(k); !ok {
			return fmt.Errorf("%s: consumes undeclared kind %q", c.Factory.Name, k)
		}
	}
	h, cleanup, err := newHarness(c, nil)
	if err != nil {
		return err
	}
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	h.Apply(c.Default)
	waitFor(h, c.Factory.Name, 2*time.Second, running)
	time.Sleep(agentSettle)
	emits := make(map[string]bool, len(c.Factory.Manifest.Emits))
	for _, t := range c.Factory.Manifest.Emits {
		emits[t.Kind] = true
	}
	for _, e := range h.Emitted() {
		if e.Kind == "agent.module_crash" {
			continue // the supervisor's own event, not the module's
		}
		if !emits[e.Kind] {
			return fmt.Errorf("%s: emits %q, which its manifest does not declare", c.Factory.Name, e.Kind)
		}
		if err := event.Validate(e); err != nil {
			return fmt.Errorf("%s: emitted %s does not validate: %v", c.Factory.Name, e.Kind, err)
		}
	}
	return nil
}

// crashCount counts the supervisor's crash events for one module.
func crashCount(h *agent.Harness, name string) int {
	n := 0
	for _, e := range h.Emitted() {
		if e.Kind == "agent.module_crash" && e.Fields["module"] == name {
			n++
		}
	}
	return n
}

// checkLinkLoss is check 6: while every emit fails, a module that consumes
// input stays ok and is never restarted. The full window runs when the case
// supplies input; without input a short smoke window still catches a module
// that crashes on its first emit.
func checkLinkLoss(c AgentCase) error {
	window := agentSettle
	if len(c.Load) > 0 {
		window = LinkLoss
		if testing.Short() {
			window = 2 * time.Second
		}
	}
	h, cleanup, err := newHarness(c, func() error { return errLinkDown })
	if err != nil {
		return err
	}
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	h.Apply(c.Default)
	for _, e := range c.Load {
		h.Publish(e)
	}
	deadline := time.Now().Add(window)
	for {
		hl, present := h.Health(c.Factory.Name)
		if !present {
			return fmt.Errorf("%s: no health block under link loss", c.Factory.Name)
		}
		if n := crashCount(h, c.Factory.Name); n > 0 {
			return fmt.Errorf("%s: restarted %d times while emits fail", c.Factory.Name, n)
		}
		if hl.State != module.StateOK {
			return fmt.Errorf("%s: state %q under link loss: %s", c.Factory.Name, hl.State, hl.Detail)
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// checkStopsCleanly is check 3: after cancel, Run returns within 5 s and the
// goroutine set returns to the pre-start set within 1 s.
func checkStopsCleanly(c AgentCase) error {
	h, cleanup, err := newHarness(c, nil)
	if err != nil {
		return err
	}
	defer cleanup()
	before := goroutineKeys()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.Run(ctx)
		close(done)
	}()
	h.Apply(c.Default)
	waitFor(h, c.Factory.Name, 5*time.Second, running)
	time.Sleep(agentSettle)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("%s: Run did not return within 5s of cancel", c.Factory.Name)
	}
	deadline := time.Now().Add(time.Second)
	for {
		extra := extraGoroutines(before, goroutineKeys())
		if len(extra) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s: goroutines still running after stop: %v", c.Factory.Name, extra)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// checkReconfig is check 7: applying a changed block replaces the module, and
// state kept with Env.Keep survives the replacement.
func checkReconfig(c AgentCase) error {
	if c.Reconfig == nil {
		return nil
	}
	builds := new(atomic.Int32)
	f := c.Factory
	build := f.Build
	f.Build = func(env agent.Env, cfg *plan.AgentConfig) (agent.ModuleSpec, error) {
		builds.Add(1)
		return build(env, cfg)
	}
	h, cleanup, err := newHarnessFor(f, c.Default, nil)
	if err != nil {
		return err
	}
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	h.Apply(c.Default)
	waitFor(h, c.Factory.Name, 5*time.Second, running)
	time.Sleep(agentSettle)
	h.Apply(c.Reconfig)
	deadline := time.Now().Add(5 * time.Second)
	for builds.Load() < 2 {
		if time.Now().After(deadline) {
			return fmt.Errorf("%s: reconfiguration did not replace the module (built %d times)", c.Factory.Name, builds.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok := waitFor(h, c.Factory.Name, 5*time.Second, running); !ok {
		return fmt.Errorf("%s: replaced module did not reach ok", c.Factory.Name)
	}
	if c.KeepKey != "" && h.Kept(c.KeepKey) == nil {
		return fmt.Errorf("%s: Keep(%q) is gone after reconfiguration", c.Factory.Name, c.KeepKey)
	}
	return nil
}

// checkConfigDecode is check 8: the module's agent-side block decodes the
// generic enablement fields strictly and refuses an unknown key.
func checkConfigDecode(c AgentCase) error {
	var block any
	if c.Block != nil {
		block = c.Block
	} else if b, ok := plan.BlockFor(c.Default, c.Factory.Name); ok {
		block = b
	}
	if block == nil {
		return nil // the module has no agent-side config block to check
	}
	t := reflect.TypeOf(block)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return fmt.Errorf("%s: block %T is not a struct", c.Factory.Name, block)
	}
	v := reflect.New(t)
	if err := decodeStrict(v.Interface(), `{"enabled":true,"act_enabled":true}`); err != nil {
		return fmt.Errorf("%s: block rejects the generic fields: %v", c.Factory.Name, err)
	}
	el := v.Elem()
	enabled, act := el.FieldByName("Enabled"), el.FieldByName("ActEnabled")
	if !enabled.IsValid() || !act.IsValid() || enabled.Kind() != reflect.Bool || act.Kind() != reflect.Bool {
		return fmt.Errorf("%s: block %s carries no enabled and act_enabled fields", c.Factory.Name, t)
	}
	if !enabled.Bool() || !act.Bool() {
		return fmt.Errorf("%s: block did not read enabled and act_enabled", c.Factory.Name)
	}
	if err := decodeStrict(reflect.New(t).Interface(), `{"x_unknown":1}`); err == nil {
		return fmt.Errorf("%s: block accepts an unknown field", c.Factory.Name)
	}
	return nil
}

// decodeStrict decodes one JSON object into dst, refusing unknown fields. A
// type with its own UnmarshalJSON (which DisallowUnknownFields cannot police)
// is caught by checkConfigDecode's unknown-key probe.
func decodeStrict(dst any, in string) error {
	dec := json.NewDecoder(strings.NewReader(in))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
