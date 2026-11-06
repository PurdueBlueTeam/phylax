package controller

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/bench"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/module"
)

func TestBenchSourceSamplesRealAgent(t *testing.T) {
	x := newCtlWith(t, Config{
		AgentListen:      "127.0.0.1:0",
		DataDir:          filepath.Join(t.TempDir(), "data"),
		SilenceThreshold: Duration(300 * time.Millisecond),
		BenchInterval:    Duration(200 * time.Millisecond),
	}, Options{})
	tok, err := x.c.Enroller().MintToken("h1", 0)
	if err != nil {
		t.Fatal(err)
	}
	a := newAgent(t, x, "h1", tok)
	a.hbEvery = 0 // this test sends the one heartbeat whose figures it checks
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.run(ctx)
	waitFor(t, 20*time.Second, "the agent to connect", func() bool {
		st, ok := x.c.AgentStatus("h1")
		return ok && st.Connected
	})
	for i := 0; i < 30; i++ {
		if _, err := a.sp.Append(event.Event{Kind: "test.ev", Priority: event.PriorityNormal, Fields: map[string]any{"i": i}}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, 30*time.Second, "30 events acked", func() bool {
		st, ok := x.c.AgentStatus("h1")
		return ok && st.Acked == 30
	})
	head, _ := a.sp.Head()
	sess := a.session()
	if sess == nil {
		t.Fatal("no live session")
	}
	// RTTUs stays 800: the agent sends no further heartbeat, so the session
	// never stamps a measured round trip over it.
	if err := sess.Send(ctx, link.PrioCritical, &link.Heartbeat{
		Seq: head, HostClock: time.Now(), SpoolDepth: 2, Congestion: "ok",
		RTTUs:   800,
		Modules: map[string]string{"net": "ok"},
		Health: map[string]module.Health{"net": {State: module.StateOK, Usage: module.Usage{
			CPUMillis: 90, HeldBytes: 1 << 20, Events: 30, BytesOut: 5000,
		}}},
	}); err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Second)
	recs, err := bench.ReadFiles(x.c.BenchPath())
	if err != nil {
		t.Fatal(err)
	}
	var (
		ctls           []bench.Ctl
		h1             *bench.AgentSample
		events, lat    uint64
		commits        uint64
		storeBytes     int64
		queries        map[string]float64
		queryNamesSeen int
	)
	for _, r := range recs {
		switch r.Kind {
		case bench.KindCtl:
			if r.Ctl == nil {
				continue
			}
			ctls = append(ctls, *r.Ctl)
			events += r.Ctl.Events[2]
			lat += r.Ctl.Latency[2].Count()
			commits += r.Ctl.Commit.Count()
			if r.Ctl.StoreBytes > storeBytes {
				storeBytes = r.Ctl.StoreBytes
			}
			if len(r.Ctl.QueryMS) > queryNamesSeen {
				queries, queryNamesSeen = r.Ctl.QueryMS, len(r.Ctl.QueryMS)
			}
		case bench.KindAgent:
			if r.Agent != nil && r.Agent.Host == "h1" {
				s := *r.Agent
				h1 = &s
			}
		}
	}
	if len(ctls) < 3 {
		t.Fatalf("ctl records = %d, want at least 3", len(ctls))
	}
	if events != 30 || lat != 30 {
		t.Fatalf("normal events %d and latencies %d, want 30 and 30", events, lat)
	}
	if commits < 1 {
		t.Fatalf("commit observations = %d, want at least 1", commits)
	}
	if storeBytes <= 0 {
		t.Fatalf("store bytes = %d, want positive", storeBytes)
	}
	if runtime.GOOS == "linux" {
		var rss uint64
		for _, c := range ctls {
			rss = max(rss, c.RSSBytes)
		}
		if rss == 0 {
			t.Fatal("rss bytes = 0 on Linux")
		}
	}
	for _, name := range []string{"overview", "health", "events"} {
		if _, ok := queries[name]; !ok {
			t.Fatalf("query timings %v missing %q", queries, name)
		}
	}
	if h1 == nil {
		t.Fatal("no agent record for h1")
	}
	if h1.RTTMs != 0.8 || !h1.Connected || h1.Connects != 1 {
		t.Fatalf("agent sample rtt/connected/connects: %v %v %v", h1.RTTMs, h1.Connected, h1.Connects)
	}
	net := h1.Modules["net"]
	if net.CPUMs != 90 || net.HeldBytes != 1<<20 {
		t.Fatalf("module net = %+v", net)
	}
}

func TestBenchOffWritesNothing(t *testing.T) {
	x := newCtlWith(t, Config{
		AgentListen: "127.0.0.1:0",
		DataDir:     filepath.Join(t.TempDir(), "data"),
		BenchOff:    true,
	}, Options{})
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(x.c.BenchPath()); !os.IsNotExist(err) {
		t.Fatalf("bench file exists with bench_off, stat err = %v", err)
	}
}

func TestBenchDefaultsOn(t *testing.T) {
	cfg := Config{DataDir: t.TempDir()}
	if err := cfg.Validate(); err != nil || cfg.BenchOff || time.Duration(cfg.BenchInterval) != 10*time.Second || cfg.BenchMaxMB != 64 {
		t.Fatalf("%+v %v", cfg, err)
	}
}

func TestBenchConfigRejectsUnknownKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, p, `{"data_dir":"x","bench_of":true}`)
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("unknown key bench_of accepted")
	}
}
