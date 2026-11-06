package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/bench"
)

// capture swaps f's standard stream for a pipe and returns what was written.
func capture(t *testing.T, stream **os.File, f func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := *stream
	*stream = w
	done := make(chan string, 1)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	ferr := f()
	w.Close()
	*stream = old
	return <-done, ferr
}

// benchFile writes records to a fresh bench file and returns its path.
func benchFile(t *testing.T, recs ...bench.Record) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bench.jsonl")
	l, err := bench.OpenLog(p, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if err := l.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBenchReportPrintsSummary(t *testing.T) {
	t0 := time.Now().Add(-20 * time.Second).UTC()
	ctl := func(at time.Time) bench.Record {
		return bench.Record{T: at, Kind: bench.KindCtl, Ctl: &bench.Ctl{IntervalMS: 10000, Events: [bench.NumClasses]uint64{0, 50, 0, 0}}}
	}
	p := benchFile(t,
		ctl(t0),
		ctl(t0.Add(10*time.Second)),
		bench.Record{T: t0.Add(10 * time.Second), Kind: bench.KindAgent,
			Agent: &bench.AgentSample{Host: "h1", Connected: true, Connects: 1, Head: 100, Acked: 100}},
	)
	out, err := capture(t, &os.Stdout, func() error {
		return commands["bench"].run(context.Background(), []string{"report", p})
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"window ", "high ", "5.0", "agents "} {
		if !strings.Contains(out, want) {
			t.Fatalf("report lacks %q:\n%s", want, out)
		}
	}
}

func TestBenchMarkAppends(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bench.jsonl")
	before := time.Now()
	for i := 0; i < 2; i++ {
		if _, err := capture(t, &os.Stdout, func() error {
			return commands["bench"].run(context.Background(), []string{"mark", p, "partition_start"})
		}); err != nil {
			t.Fatal(err)
		}
	}
	recs, err := bench.ReadFiles(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("%d records, want 2 marks", len(recs))
	}
	for i, r := range recs {
		if r.Kind != bench.KindMark || r.Mark != "partition_start" {
			t.Fatalf("record %d = %+v", i, r)
		}
		if d := r.T.Sub(before); d < -time.Second || d > 2*time.Second {
			t.Fatalf("mark %d time %s is not now (%s)", i, r.T, before)
		}
	}
}

func TestBenchReportCheckFailsWithoutMarks(t *testing.T) {
	p := benchFile(t, bench.Record{T: time.Now().UTC(), Kind: bench.KindCtl, Ctl: &bench.Ctl{IntervalMS: 10000}})
	out, err := capture(t, &os.Stdout, func() error {
		return commands["bench"].run(context.Background(), []string{"report", "-check", p})
	})
	if err == nil {
		t.Fatal("report -check passed without partition marks")
	}
	if !strings.Contains(out, "FAIL partition_marks") {
		t.Fatalf("output lacks the failing check:\n%s", out)
	}
}

func TestBenchUnknownSubcommand(t *testing.T) {
	errOut, err := capture(t, &os.Stderr, func() error {
		return commands["bench"].run(context.Background(), []string{"nope"})
	})
	if err == nil {
		t.Fatal("unknown subcommand accepted")
	}
	if !strings.Contains(errOut, "usage") {
		t.Fatalf("stderr lacks usage: %q", errOut)
	}
}
