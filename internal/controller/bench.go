package controller

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/bench"
	"github.com/PurdueBlueTeam/phylax/internal/chains"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// benchQueryTimeout bounds one UI or store query the recorder times: a slow
// query is omitted from the sample, never waited on.
const benchQueryTimeout = 5 * time.Second

// benchSource is the recorder's view of the controller: the counters the
// ingest drain keeps, one sample per known agent, the store size and the time
// the operator queries take.
type benchSource struct {
	c   *Controller
	ops *WebOps
}

func newBenchSource(c *Controller) *benchSource {
	return &benchSource{c: c, ops: NewWebOps(c, c.cfg.PlansPath, chains.Config{})}
}

// Counters is the controller's cumulative figures; the recorder turns them into
// per-interval deltas. Commit comes from the store, which counts it.
func (s *benchSource) Counters() bench.Counters {
	c := s.c.bs.counters()
	c.Commit = s.c.st.CommitHist()
	return c
}

// Agents is one sample per known host, sorted by host (AgentHosts sorts).
func (s *benchSource) Agents() []bench.AgentSample {
	hosts := s.c.AgentHosts()
	out := make([]bench.AgentSample, 0, len(hosts))
	for _, h := range hosts {
		st, ok := s.c.AgentStatus(h)
		if !ok {
			continue
		}
		a := bench.AgentSample{
			Host:        h,
			Connected:   st.Connected,
			ConnectedAt: st.ConnectedAt,
			Connects:    st.Connects,
			RTTMs:       float64(st.RTT) / float64(time.Millisecond),
			Head:        st.HeadSeq,
			Acked:       st.Acked,
			SpoolDepth:  st.SpoolDepth,
			Congestion:  st.Congestion,
			Shed:        st.Drops,
			SkewMS:      float64(st.ClockSkew) / float64(time.Millisecond),
		}
		if st.HeadSeq > st.Acked {
			a.LagEvents = st.HeadSeq - st.Acked
		}
		if hs := s.c.AgentHealth(h); len(hs) > 0 {
			a.Modules = make(map[string]bench.ModuleUse, len(hs))
			for name, mh := range hs {
				a.Modules[name] = bench.ModuleUse{
					State:     string(mh.State),
					CPUMs:     mh.Usage.CPUMillis,
					HeldBytes: mh.Usage.HeldBytes,
					Events:    mh.Usage.Events,
					BytesOut:  mh.Usage.BytesOut,
					Dropped:   mh.Usage.Dropped,
				}
			}
		}
		out = append(out, a)
	}
	return out
}

// StoreBytes is the database file plus its WAL.
func (s *benchSource) StoreBytes() int64 { return s.c.st.Size() }

// QueryTimes times the operator queries the UI makes: the dashboard overview,
// the health page and one page of stored events. A query that fails is omitted
// from the sample.
func (s *benchSource) QueryTimes(ctx context.Context) map[string]float64 {
	out := map[string]float64{}
	timeQuery := func(name string, f func(context.Context) error) {
		qctx, cancel := context.WithTimeout(ctx, benchQueryTimeout)
		defer cancel()
		t0 := time.Now()
		if err := f(qctx); err != nil {
			return
		}
		out[name] = float64(time.Since(t0)) / float64(time.Millisecond)
	}
	timeQuery("overview", func(ctx context.Context) error { _, err := s.ops.Overview(ctx); return err })
	timeQuery("health", func(ctx context.Context) error { _, err := s.ops.Health(ctx); return err })
	timeQuery("events", func(ctx context.Context) error {
		_, err := s.c.st.Events(ctx, store.Query{Limit: 100, Desc: true})
		return err
	})
	return out
}

// BenchPath is the bench file: <data_dir>/bench.jsonl (plus its .1 rotation).
func (c *Controller) BenchPath() string { return filepath.Join(c.cfg.DataDir, "bench.jsonl") }

// startBench starts the bench recorder on wg when the config enables it. A log
// that cannot be opened is returned: the caller warns and serves without a
// recorder, because the controller must start even when the disk is odd.
func (c *Controller) startBench(ctx context.Context, wg *sync.WaitGroup) error {
	if c.cfg.BenchOff {
		return nil
	}
	l, err := bench.OpenLog(c.BenchPath(), int64(c.cfg.BenchMaxMB)<<20)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.benchLog = l
	c.mu.Unlock()
	rec := bench.NewRecorder(newBenchSource(c), l, time.Duration(c.cfg.BenchInterval))
	wg.Add(1)
	go func() {
		defer wg.Done()
		rec.Run(ctx)
	}()
	return nil
}

// closeBench closes the bench file. The recorder has stopped by the time Close
// is called (Serve waits for it), so no record can arrive afterwards.
func (c *Controller) closeBench() error {
	c.mu.Lock()
	l := c.benchLog
	c.benchLog = nil
	c.mu.Unlock()
	if l == nil {
		return nil
	}
	return l.Close()
}
