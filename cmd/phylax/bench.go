package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/bench"
)

func init() {
	register(command{name: "bench", summary: "communications bench: report, mark, load", run: runBench})
}

const benchUsage = `usage: phylax bench <subcommand>

  report [-from RFC3339] [-to RFC3339] [-host-prefix P] [-check] FILE...
        print the summary of one or more bench files; -check also evaluates
        the transport envelope's pass criteria
  mark FILE NAME
        append a mark with the current time (partition_start, partition_end,
        caught_up, ...)
  load  (lab only; see phylax bench load -h)
`

// defaultCriteria are the transport envelope's pass figures (design: "Volume
// and envelope"): p99 event-to-controller latency at most 10 s, every agent
// reconnects once within 35 s of the link coming back.
var defaultCriteria = bench.Criteria{LatencyP99Ms: 10000, MaxReconnectS: 35}

func runBench(ctx context.Context, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, benchUsage)
		return errors.New("missing subcommand")
	}
	switch args[0] {
	case "report":
		return runBenchReport(args[1:])
	case "mark":
		return runBenchMark(args[1:])
	}
	fmt.Fprint(os.Stderr, benchUsage)
	return fmt.Errorf("unknown bench subcommand %q", args[0])
}

func runBenchReport(args []string) error {
	fs := flag.NewFlagSet("bench report", flag.ContinueOnError)
	from := fs.String("from", "", "start of the window (RFC3339)")
	to := fs.String("to", "", "end of the window (RFC3339)")
	prefix := fs.String("host-prefix", "", "only agent samples whose host starts with this")
	check := fs.Bool("check", false, "also evaluate the envelope pass criteria (exit 1 on a failure)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("bench report needs at least one FILE")
	}
	f := bench.Filter{HostPrefix: *prefix}
	var err error
	if f.From, err = parseRFC3339("-from", *from); err != nil {
		return err
	}
	if f.To, err = parseRFC3339("-to", *to); err != nil {
		return err
	}
	recs, err := bench.ReadFiles(fs.Args()...)
	if err != nil {
		return err
	}

	bench.Summarize(recs, f).Write(os.Stdout)
	if ps, ok := phases(recs, f); ok {
		for _, p := range ps {
			fmt.Fprintf(os.Stdout, "== %s\n", p.name)
			bench.Summarize(recs, p.filter).Write(os.Stdout)
		}
	}
	if !*check {
		return nil
	}
	failed := 0
	for _, r := range bench.Check(recs, *prefix, defaultCriteria) {
		verdict := "PASS"
		if !r.Pass {
			verdict = "FAIL"
			failed++
		}
		fmt.Fprintf(os.Stdout, "%s %s %s %s\n", verdict, r.Name, r.Got, r.Want)
	}
	if failed > 0 {
		return fmt.Errorf("%d bench check(s) failed", failed)
	}
	return nil
}

// phase is one named window of a load run.
type phase struct {
	name   string
	filter bench.Filter
}

// phases splits a load run at its partition marks: before the partition, the
// partition and the recovery up to caught_up, and after. The samples on a
// boundary belong to both neighbouring phases. ok is false unless the records
// hold both a partition_start and a caught_up mark.
func phases(recs []bench.Record, f bench.Filter) ([]phase, bool) {
	var start, up time.Time
	for _, r := range recs {
		if r.Kind != bench.KindMark {
			continue
		}
		switch r.Mark {
		case "partition_start":
			if start.IsZero() {
				start = r.T
			}
		case "caught_up":
			if up.IsZero() {
				up = r.T
			}
		}
	}
	if start.IsZero() || up.IsZero() {
		return nil, false
	}
	return []phase{
		{"before partition", bench.Filter{From: f.From, To: earlier(f.To, start), HostPrefix: f.HostPrefix}},
		{"partition and recovery", bench.Filter{From: later(f.From, start), To: earlier(f.To, up), HostPrefix: f.HostPrefix}},
		{"after", bench.Filter{From: later(f.From, up), To: f.To, HostPrefix: f.HostPrefix}},
	}, true
}

// later is the later of a and b; a zero time is unbounded (the other wins).
func later(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() {
		return a
	}
	if a.After(b) {
		return a
	}
	return b
}

// earlier is the earlier of a and b; a zero time is unbounded (the other wins).
func earlier(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() {
		return a
	}
	if a.Before(b) {
		return a
	}
	return b
}

func runBenchMark(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: phylax bench mark FILE NAME")
	}
	now := time.Now()
	if err := bench.AppendMark(args[0], args[1], now); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "mark %s %s\n", args[1], now.UTC().Format(time.RFC3339))
	return nil
}

func parseRFC3339(name, v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", name, err)
	}
	return t.UTC(), nil
}
