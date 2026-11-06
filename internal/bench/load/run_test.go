package load_test

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/bench"
	"github.com/PurdueBlueTeam/phylax/internal/bench/load"
	"github.com/PurdueBlueTeam/phylax/internal/enroll"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/spool"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

func TestRunEndToEndPartition(t *testing.T) {
	c, addr, _ := startController(t)
	dir := t.TempDir()
	hosts := []string{"bench-001", "bench-002", "bench-003"}
	if err := c.Enroller().WriteBundles(dir, hosts, enroll.BundleOptions{
		Controllers: []string{addr}, TTL: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var out bytes.Buffer
	res, err := load.Run(ctx, load.Config{
		BundleDir: dir, Prefix: "bench-", N: 3,
		Rates: [bench.NumClasses]float64{1, 5, 10, 0}, Size: 80,
		Duration: 12 * time.Second, PartitionAt: 3 * time.Second, PartitionFor: 3 * time.Second,
		CtlBench: c.BenchPath(), CtlInterval: 500 * time.Millisecond, Out: t.TempDir(),
		Backoff:  link.Backoff{Min: 50 * time.Millisecond, Max: 500 * time.Millisecond},
		Criteria: bench.Criteria{LatencyP99Ms: 10000, MaxReconnectS: 5},
	}, &out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !res.Pass {
		t.Fatalf("checks: %+v\n%s", res.Checks, out.String())
	}
	if res.Summary.ReconnectN != 3 || res.Summary.NoReconnect != 0 || res.Summary.Reconnect.Max >= 5 {
		t.Fatalf("reconnect = %+v", res.Summary)
	}
	for host, n := range res.Summary.ReconnectsPerAgent {
		if n != 1 {
			t.Fatalf("%s reconnected %d times, want 1", host, n)
		}
	}
	if res.Summary.GapEvents != 0 {
		t.Fatalf("gap events = %d", res.Summary.GapEvents)
	}
	if res.Summary.Class[2].EventsPerS <= 20 {
		t.Fatalf("normal events/s = %.1f, want > 20", res.Summary.Class[2].EventsPerS)
	}
	if !strings.Contains(out.String(), "reconnect after partition") || !strings.Contains(out.String(), "PASS no_loss") {
		t.Fatalf("output lacks the report or the no_loss check:\n%s", out.String())
	}

	// The store holds each agent's chain with no gap: sequence numbers run
	// 1..n and no spool gap record was needed.
	for _, host := range hosts {
		evs, err := c.Store().Events(ctx, store.Query{Agent: host, Limit: store.MaxQueryLimit})
		if err != nil {
			t.Fatal(err)
		}
		if len(evs) < 100 {
			t.Fatalf("%s stored %d events, want the run's load", host, len(evs))
		}
		for i, e := range evs {
			if e.Seq != uint64(i+1) {
				t.Fatalf("%s seq %d at position %d", host, e.Seq, i)
			}
			if e.Kind == spool.GapKind {
				t.Fatalf("%s has a gap record at seq %d", host, e.Seq)
			}
		}
		n, err := c.Store().Count(ctx, host)
		if err != nil {
			t.Fatal(err)
		}
		if n != int64(len(evs)) {
			t.Fatalf("%s count %d, queried %d", host, n, len(evs))
		}
	}
}

func TestRunFailsWhenSpoolTooSmall(t *testing.T) {
	c, addr, _ := startController(t)
	dir := t.TempDir()
	if err := c.Enroller().WriteBundles(dir, []string{"bench-001", "bench-002", "bench-003"}, enroll.BundleOptions{
		Controllers: []string{addr}, TTL: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var out bytes.Buffer
	res, err := load.Run(ctx, load.Config{
		BundleDir: dir, Prefix: "bench-", N: 3,
		Rates: [bench.NumClasses]float64{0, 0, 200, 200}, Size: 500,
		Duration: 10 * time.Second, PartitionAt: 2 * time.Second, PartitionFor: 4 * time.Second,
		CtlBench: c.BenchPath(), CtlInterval: 500 * time.Millisecond, Out: t.TempDir(),
		Backoff:  link.Backoff{Min: 50 * time.Millisecond, Max: 500 * time.Millisecond},
		SpoolMax: 200 << 10,
		Criteria: bench.Criteria{LatencyP99Ms: 10000, MaxReconnectS: 5},
	}, &out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if res.Pass {
		t.Fatalf("run passed with a 200 KB spool:\n%s", out.String())
	}
	failed := false
	for _, chk := range res.Checks {
		if chk.Name == "no_loss" && !chk.Pass {
			failed = true
		}
	}
	if !failed {
		t.Fatalf("no_loss did not fail: %+v", res.Checks)
	}
}

func TestRunValidatesConfig(t *testing.T) {
	base := func() load.Config {
		return load.Config{BundleDir: t.TempDir(), Prefix: "bench-", N: 1,
			Duration: time.Minute, PartitionAt: 10 * time.Second, PartitionFor: 10 * time.Second,
			CtlBench: filepath.Join(t.TempDir(), "bench.jsonl"), CtlInterval: 500 * time.Millisecond,
			Out: t.TempDir()}
	}
	c := base()
	c.PartitionAt, c.PartitionFor, c.Duration = 30*time.Second, 30*time.Second, time.Minute
	if _, err := load.Run(context.Background(), c, io.Discard); err == nil || !strings.Contains(err.Error(), "partition") {
		t.Fatalf("partition at/for that fill the run: err = %v", err)
	}
	c = base()
	c.N = 0
	if _, err := load.Run(context.Background(), c, io.Discard); err == nil {
		t.Fatal("N = 0 accepted")
	}
	c = base()
	if _, err := load.Run(context.Background(), c, io.Discard); err == nil || !strings.Contains(err.Error(), c.BundleDir) {
		t.Fatalf("missing bundles: err = %v, want the dir %s", err, c.BundleDir)
	}
}
