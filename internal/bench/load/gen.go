// Package load is the comms bench's lab load generator: a cut-able TCP proxy
// (proxy.go), a synthetic module and the real-agent runner (gen.go), and the
// scenario that cuts the link for a partition and checks the transport envelope
// against the controller's own bench file (run.go). It is lab-only: the load
// run writes synthetic events into the target controller's store, so
// phylax bench load requires -lab. It imports only internal/bench, internal/agent,
// internal/link, internal/spool and internal/event (plan: docs/impl/14-bench.md).
package load

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/bench"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/spool"
)

// Gen is the synthetic module: it emits Rates[class] events per second of kind
// "bench.load" at that priority.
type Gen struct {
	Rates   [bench.NumClasses]float64 // events/s per class (critical, high, normal, bulk)
	Size    int                       // payload bytes of the "pad" field
	emitted atomic.Uint64
	stop    atomic.Bool
}

// Name is the module name in heartbeats.
func (g *Gen) Name() string { return "benchload" }

// Start ticks every 100 ms and emits floor(rate*elapsed) catch-up events per
// class. It returns nil at ctx.Done or after Stop.
func (g *Gen) Start(ctx context.Context, emit agent.Emit) error {
	start := time.Now()
	var sent [bench.NumClasses]int64
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		if g.stop.Load() {
			return nil
		}
		elapsed := time.Since(start).Seconds()
		for class, rate := range g.Rates {
			want := int64(rate * elapsed)
			n := want - sent[class]
			if n <= 0 {
				continue
			}
			// shortcut: bounded burst, upgrade if a generator must model a stall
			if n > 5000 {
				n = 5000
			}
			sent[class] += n
			for i := int64(0); i < n; i++ {
				if g.stop.Load() || ctx.Err() != nil {
					return nil
				}
				seq := g.emitted.Add(1)
				// A shed event is the spool's loss to report, not a generator
				// crash: the supervisor counts it and the run keeps its rate.
				_ = emit(event.Event{
					Kind:     "bench.load",
					Priority: event.Priority(class),
					Fields:   map[string]any{"n": seq, "pad": strings.Repeat("x", g.Size)},
				})
			}
		}
	}
}

// Stop makes Start return.
func (g *Gen) Stop() { g.stop.Store(true) }

// Emitted is the number of events this generator handed to its agent.
func (g *Gen) Emitted() uint64 { return g.emitted.Load() }

// Agents is the running set of synthetic agents.
type Agents struct {
	hosts  []string
	gens   []*Gen
	runs   []*agent.Agent
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
}

// StartAgents loads every bundle <dir>/<prefix>*.json (sorted; at most n),
// rewrites its controller to proxyAddr, lays each out under work/<host>, and
// runs a real agent with one shared Gen configuration (one Gen per agent).
func StartAgents(ctx context.Context, bundleDir, prefix string, n int, proxyAddr, work string,
	rates [bench.NumClasses]float64, size int, bo link.Backoff, spoolMax int64) (*Agents, error) {
	if n < 1 {
		return nil, fmt.Errorf("load: need at least 1 agent, got %d", n)
	}
	entries, err := os.ReadDir(bundleDir)
	if err != nil {
		return nil, fmt.Errorf("load: bundles in %s: %w", bundleDir, err)
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		paths = append(paths, filepath.Join(bundleDir, e.Name()))
	}
	sort.Strings(paths)
	if len(paths) < n {
		return nil, fmt.Errorf("load: need %d, found %d bundles in %s", n, len(paths), bundleDir)
	}

	runCtx, cancel := context.WithCancel(ctx)
	a := &Agents{cancel: cancel}
	fail := func(err error) (*Agents, error) {
		cancel()
		a.wg.Wait()
		return nil, err
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, path := range paths[:n] {
		data, err := os.ReadFile(path)
		if err != nil {
			return fail(fmt.Errorf("load: bundle %s: %w", path, err))
		}
		b, err := agent.ParseBundle(data)
		if err != nil {
			return fail(fmt.Errorf("load: bundle %s: %w", path, err))
		}
		b.Controllers = []string{proxyAddr}
		layout := agent.Layout{Root: filepath.Join(work, b.Host)}
		if err := layout.SaveBundle(b); err != nil {
			return fail(fmt.Errorf("load: bundle %s: %w", path, err))
		}
		g := &Gen{Rates: rates, Size: size}
		ag, err := agent.New(agent.Config{
			Layout:            layout,
			Version:           "bench-load",
			Logger:            logger,
			Modules:           []agent.ModuleSpec{{Module: g, Rate: 0}},
			HeartbeatInterval: 5 * time.Second,
			HealthInterval:    time.Hour,
			Backoff:           bo,
			Spool:             spool.Options{MaxBytes: spoolMax},
		})
		if err != nil {
			return fail(fmt.Errorf("load: agent %s: %w", b.Host, err))
		}
		a.hosts = append(a.hosts, b.Host)
		a.gens = append(a.gens, g)
		a.runs = append(a.runs, ag)
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			_ = ag.Run(runCtx)
		}()
	}
	return a, nil
}

// Hosts are the synthetic agent host names, in bundle order.
func (a *Agents) Hosts() []string { return append([]string(nil), a.hosts...) }

// Connected is the number of agents whose link is up.
func (a *Agents) Connected() int {
	n := 0
	for _, ag := range a.runs {
		if ag.Link().Connected {
			n++
		}
	}
	return n
}

// StopGen stops every generator.
func (a *Agents) StopGen() {
	for _, g := range a.gens {
		g.Stop()
	}
}

// Depth is the largest spool depth (head - ack) over the agents.
func (a *Agents) Depth() (max uint64) {
	for _, ag := range a.runs {
		st := ag.SpoolStats()
		if st.HeadSeq > st.AckSeq {
			max = maxOf(max, st.HeadSeq-st.AckSeq)
		}
	}
	return max
}

// Emitted is the number of events all generators emitted.
func (a *Agents) Emitted() uint64 {
	var n uint64
	for _, g := range a.gens {
		n += g.Emitted()
	}
	return n
}

// Stop cancels and waits for every Run to return.
func (a *Agents) Stop() {
	a.once.Do(func() {
		a.cancel()
		a.wg.Wait()
	})
}

func maxOf(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
