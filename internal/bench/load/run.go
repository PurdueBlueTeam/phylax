package load

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/bench"
	"github.com/PurdueBlueTeam/phylax/internal/link"
)

// Config is one load run.
type Config struct {
	BundleDir, Prefix string
	N                 int
	Rates             [bench.NumClasses]float64
	Size              int
	Duration          time.Duration // total run, including the partition
	PartitionAt       time.Duration // from load start
	PartitionFor      time.Duration
	CtlBench          string        // the controller's bench.jsonl (read at the end)
	CtlInterval       time.Duration // the controller's bench_interval; the runner waits two of them before reading
	Out               string        // directory: agents/<host> state, load.jsonl marks
	Backoff           link.Backoff
	SpoolMax          int64
	Criteria          bench.Criteria
	CatchUpTimeout    time.Duration // default 120 s
}

// Result is what one load run measured and checked.
type Result struct {
	Checks  []bench.Result
	Summary bench.Summary // whole run, synthetic hosts only
	Pass    bool
}

// Run drives N synthetic agents against a real controller, cuts the link for
// the partition, then reads the controller's bench file and checks the
// transport envelope. It stops the agents and the proxy on every path.
func Run(ctx context.Context, c Config, w io.Writer) (Result, error) {
	var res Result
	if c.N < 1 {
		return res, fmt.Errorf("bench load: N must be at least 1")
	}
	if c.Duration <= 0 {
		return res, fmt.Errorf("bench load: duration must be positive")
	}
	if c.PartitionAt < 0 || c.PartitionFor < 0 || c.PartitionAt+c.PartitionFor >= c.Duration {
		return res, fmt.Errorf("bench load: partition at %s for %s must end before the %s run",
			c.PartitionAt, c.PartitionFor, c.Duration)
	}
	if c.CatchUpTimeout <= 0 {
		c.CatchUpTimeout = 120 * time.Second
	}
	paths, err := matchingBundles(c.BundleDir, c.Prefix)
	if err != nil {
		return res, err
	}
	if len(paths) < c.N {
		return res, fmt.Errorf("load: need %d, found %d bundles in %s", c.N, len(paths), c.BundleDir)
	}
	target, err := firstBundleController(paths[0])
	if err != nil {
		return res, err
	}
	if err := os.MkdirAll(c.Out, 0o700); err != nil {
		return res, fmt.Errorf("bench load: out dir: %w", err)
	}
	markPath := filepath.Join(c.Out, "load.jsonl")
	mark := func(name string) error { return bench.AppendMark(markPath, name, time.Now()) }

	proxy, err := NewProxy("127.0.0.1:0", target, 2*c.N+8)
	if err != nil {
		return res, fmt.Errorf("bench load: proxy: %w", err)
	}
	defer proxy.Close()
	agents, err := StartAgents(ctx, c.BundleDir, c.Prefix, c.N, proxy.Addr(), filepath.Join(c.Out, "agents"),
		c.Rates, c.Size, c.Backoff, c.SpoolMax)
	if err != nil {
		return res, err
	}
	defer agents.Stop()

	if err := waitCond(ctx, 60*time.Second, func() bool { return agents.Connected() == c.N }); err != nil {
		return res, fmt.Errorf("bench load: agents did not connect: %w", err)
	}
	if err := mark("load_start"); err != nil {
		return res, err
	}
	start := time.Now()
	deadline := start.Add(c.Duration)

	if err := sleepCtx(ctx, c.PartitionAt); err != nil {
		return res, err
	}
	if err := mark("partition_start"); err != nil {
		return res, err
	}
	proxy.Cut()
	if err := sleepCtx(ctx, c.PartitionFor); err != nil {
		return res, err
	}
	proxy.Restore()
	if err := mark("partition_end"); err != nil {
		return res, err
	}

	threshold := uint64(max(10, 2*sumRates(c.Rates)))
	caughtUp := false
	for time.Now().Before(deadline) {
		if agents.Depth() <= threshold {
			if err := mark("caught_up"); err != nil {
				return res, err
			}
			caughtUp = true
			break
		}
		if err := sleepCtx(ctx, 250*time.Millisecond); err != nil {
			return res, err
		}
	}
	notCaughtUp := false
	if !caughtUp {
		if err := mark("not_caught_up"); err != nil {
			return res, err
		}
		notCaughtUp = true
	}
	if err := sleepUntil(ctx, deadline); err != nil {
		return res, err
	}
	if err := mark("load_end"); err != nil {
		return res, err
	}

	agents.StopGen()
	if err := waitCond(ctx, c.CatchUpTimeout, func() bool { return agents.Depth() == 0 }); err != nil {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if !notCaughtUp {
			if err := mark("not_caught_up"); err != nil {
				return res, err
			}
		}
	}
	agents.Stop()
	if err := sleepCtx(ctx, 2*c.CtlInterval); err != nil {
		return res, err
	}

	recs, err := bench.ReadFiles(c.CtlBench, markPath)
	if err != nil {
		return res, err
	}
	res.Summary = bench.Summarize(recs, bench.Filter{HostPrefix: c.Prefix})
	res.Checks = bench.Check(recs, c.Prefix, c.Criteria)
	res.Pass = true
	res.Summary.Write(w)
	for _, chk := range res.Checks {
		verdict := "PASS"
		if !chk.Pass {
			verdict = "FAIL"
			res.Pass = false
		}
		fmt.Fprintf(w, "%s %s %s %s\n", verdict, chk.Name, chk.Got, chk.Want)
	}
	return res, nil
}

// matchingBundles lists <dir>/<prefix>*.json in name order.
func matchingBundles(dir, prefix string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("load: bundles in %s: %w", dir, err)
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		paths = append(paths, filepath.Join(dir, e.Name()))
	}
	sort.Strings(paths)
	return paths, nil
}

// firstBundleController is the controller address the first bundle names.
func firstBundleController(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("load: bundle %s: %w", path, err)
	}
	b, err := agent.ParseBundle(data)
	if err != nil {
		return "", fmt.Errorf("load: bundle %s: %w", path, err)
	}
	return b.Controllers[0], nil
}

// sumRates is the configured events per second across classes.
func sumRates(r [bench.NumClasses]float64) int {
	var n float64
	for _, v := range r {
		n += v
	}
	return int(n)
}

// waitCond polls f every 100 ms until it is true or d elapses.
func waitCond(ctx context.Context, d time.Duration, f func() bool) error {
	deadline := time.Now().Add(d)
	for {
		if f() {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s", d)
		}
		if err := sleepCtx(ctx, 100*time.Millisecond); err != nil {
			return err
		}
	}
}

// sleepCtx sleeps for d, or until ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// sleepUntil sleeps until t, or returns at once when t has passed.
func sleepUntil(ctx context.Context, t time.Time) error {
	return sleepCtx(ctx, time.Until(t))
}
