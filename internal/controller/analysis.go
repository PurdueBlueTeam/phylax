package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
)

const (
	analysisDefaultDeadline = 10 * time.Second
	analysisDebounce        = time.Second
	analysisMaxWait         = 10 * time.Second
	analysisBusBuf          = 1024
)

// runAnalyzers drives a module's analysers from its committed input events
// and their Every periods until ctx ends. One subscription feeds every
// analyser; a trigger is debounced so a burst runs the analyser once.
func (c *Controller) runAnalyzers(ctx context.Context, m module.ControllerModule, st *moduleRunState, as []module.Analyzer) {
	h := c.hostFor(m)
	inputs := map[string]bool{}
	for _, a := range as {
		for _, k := range a.Inputs {
			inputs[k] = true
		}
	}
	var ch <-chan event.Event
	stop := func() {}
	if len(inputs) > 0 {
		kinds := make([]string, 0, len(inputs))
		for k := range inputs {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		ch, stop = h.Subscribe(kinds, analysisBusBuf)
	}
	defer stop()

	type worker struct {
		a    module.Analyzer
		trig chan struct{}
	}
	ws := make([]*worker, 0, len(as))
	for _, a := range as {
		ws = append(ws, &worker{a: a, trig: make(chan struct{}, 1)})
	}
	var wg sync.WaitGroup
	for _, w := range ws {
		wg.Add(1)
		go func(w *worker) {
			defer wg.Done()
			c.runAnalyzer(ctx, h, st, w.a, w.trig)
		}(w)
	}
	// An input stored before the subscription was ready still analyses once.
	for _, w := range ws {
		if len(w.a.Inputs) > 0 {
			select {
			case w.trig <- struct{}{}:
			default:
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case e := <-ch:
			for _, w := range ws {
				for _, k := range w.a.Inputs {
					if k == e.Kind {
						select {
						case w.trig <- struct{}{}:
						default:
						}
						break
					}
				}
			}
		}
	}
}

// runAnalyzer runs one analyser's trigger and Every timers, one run at a time.
// A trigger is debounced, but never postponed beyond analysisMaxWait from the
// first pending trigger, so a stream of inputs cannot starve the analyser.
func (c *Controller) runAnalyzer(ctx context.Context, h *moduleHost, st *moduleRunState, a module.Analyzer, trig <-chan struct{}) {
	clk := c.clk
	if clk == nil {
		clk = realClock{}
	}
	var tick <-chan time.Time
	if a.Every > 0 {
		t := clk.NewTicker(a.Every)
		defer t.Stop()
		tick = t.C()
	}
	var debounce, maxWait timer
	var debounceC, maxWaitC <-chan time.Time
	pending := false
	stopPending := func() {
		if debounce != nil {
			debounce.Stop()
		}
		if maxWait != nil {
			maxWait.Stop()
		}
		debounceC, maxWaitC = nil, nil
		pending = false
	}
	defer stopPending()
	run := func() {
		stopPending()
		c.runAnalyzerOnce(ctx, h, st, a)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-trig:
			if debounce == nil {
				debounce = clk.NewTimer(analysisDebounce)
			} else {
				debounce.Reset(analysisDebounce)
			}
			debounceC = debounce.C()
			if !pending {
				pending = true
				if maxWait == nil {
					maxWait = clk.NewTimer(analysisMaxWait)
				} else {
					maxWait.Reset(analysisMaxWait)
				}
				maxWaitC = maxWait.C()
			}
		case <-debounceC:
			run()
		case <-maxWaitC:
			run()
		case <-tick:
			run()
		}
	}
}

func (c *Controller) runAnalyzerOnce(ctx context.Context, h *moduleHost, st *moduleRunState, a module.Analyzer) {
	defer func() {
		if r := recover(); r != nil {
			c.setAnalysisGap(st, a.Name, module.Gap{What: "analyser " + a.Name, Why: fmt.Sprintf("panic: %v", r)})
		}
	}()
	deadline := c.analysisDeadline
	if deadline <= 0 {
		deadline = analysisDefaultDeadline
	}
	rctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	evs, err := a.Run(rctx, h.Query(), c.now().UTC())
	if err == nil && rctx.Err() != nil {
		err = rctx.Err()
	}
	if err == nil {
		for _, e := range evs {
			if err = h.Emit(e); err != nil {
				break
			}
		}
	}
	if err != nil {
		why := err.Error()
		if errors.Is(err, context.DeadlineExceeded) {
			why = fmt.Sprintf("run exceeded %s", deadline)
		}
		c.setAnalysisGap(st, a.Name, module.Gap{What: "analyser " + a.Name, Why: why})
		return
	}
	c.clearAnalysisGap(st, a.Name)
}

func (c *Controller) setAnalysisGap(st *moduleRunState, name string, gap module.Gap) {
	st.mu.Lock()
	if st.aGaps == nil {
		st.aGaps = map[string]module.Gap{}
	}
	st.aGaps[name] = gap
	st.mu.Unlock()
}

func (c *Controller) clearAnalysisGap(st *moduleRunState, name string) {
	st.mu.Lock()
	delete(st.aGaps, name)
	st.mu.Unlock()
}
