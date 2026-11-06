package controller

import (
	"context"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

func TestBenchStatsClassesAndLatency(t *testing.T) {
	var b benchStats
	now := time.Unix(1700000100, 0)
	b.stored(event.Event{Priority: event.PriorityHigh, Time: now.Add(-3 * time.Second), Kind: "k", Fields: map[string]any{"a": 1}}, now, 0)
	b.stored(event.Event{Priority: event.PriorityHigh, Time: now.Add(-3 * time.Second), Kind: "k"}, now, 2*time.Second) // agent clock 2 s ahead: true age 1 s
	b.stored(event.Event{Priority: event.PriorityBulk, Time: now.Add(time.Hour)}, now, 0)                               // future: clamped to 0
	c := b.counters()
	if c.Events[1] != 2 || c.Events[3] != 1 || c.Bytes[1] == 0 {
		t.Fatalf("%+v", c)
	}
	if c.Latency[1][11] != 1 /* 3 s <= 5000 */ || c.Latency[1][9] != 1 /* 1 s <= 1000 */ || c.Latency[3][0] != 1 {
		t.Fatalf("%v", c.Latency)
	}
}

func TestBenchStatsGap(t *testing.T) {
	var b benchStats
	b.gap(event.Event{Kind: store.KindGap, Seq: 20, Fields: map[string]any{"from": float64(11), "to": float64(19), "count": float64(9)}})
	if c := b.counters(); c.GapRecords != 1 || c.GapEvents != 9 || c.Events[0] != 0 {
		t.Fatalf("%+v", c)
	}
}

func TestControllerCountsIngestAndConnects(t *testing.T) {
	x := newCtl(t)
	tok, err := x.c.Enroller().MintToken("h1", 0)
	if err != nil {
		t.Fatal(err)
	}
	a := newAgent(t, x, "h1", tok)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.run(ctx)
	waitFor(t, 20*time.Second, "the agent to connect", func() bool {
		st, ok := x.c.AgentStatus("h1")
		return ok && st.Connected
	})
	for i := 0; i < 20; i++ {
		p := event.PriorityNormal
		if i >= 10 {
			p = event.PriorityHigh
		}
		if _, err := a.sp.Append(event.Event{Kind: "test.ev", Priority: p, Fields: map[string]any{"i": i}}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, 30*time.Second, "20 events acked", func() bool {
		st, ok := x.c.AgentStatus("h1")
		return ok && st.Acked == 20
	})
	c := x.c.bs.counters()
	if c.Events[1] != 10 || c.Events[2] != 10 {
		t.Fatalf("events by class: %v, want high 10 normal 10", c.Events)
	}
	if c.Latency[1].Count() != 10 {
		t.Fatalf("high latency observations = %d, want 10", c.Latency[1].Count())
	}
	if c.Connects != 1 {
		t.Fatalf("connects = %d, want 1", c.Connects)
	}

	a.kill()
	waitFor(t, 30*time.Second, "the reconnect", func() bool { return x.c.bs.counters().Connects == 2 })
	if c := x.c.bs.counters(); c.Down.Count() != 1 {
		t.Fatalf("down observations = %d, want 1", c.Down.Count())
	}
	st, ok := x.c.AgentStatus("h1")
	if !ok || st.Connects != 2 || st.ConnectedAt.IsZero() {
		t.Fatalf("status after reconnect: %+v", st)
	}
}

func TestHeartbeatCarriesHeadAndRTT(t *testing.T) {
	x := newCtl(t)
	tok, err := x.c.Enroller().MintToken("h1", 0)
	if err != nil {
		t.Fatal(err)
	}
	id, err := link.GenerateIdentity("h1")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := link.Dial(ctx, x.addr, link.DialOptions{Identity: id, ServerPin: x.c.Pin(), ALPN: link.ALPNAgent})
	if err != nil {
		t.Fatal(err)
	}
	welcomed := make(chan struct{})
	sess := link.NewSession(conn, link.Options{Role: link.RoleAgent, Handler: func(_ context.Context, m link.Message) error {
		if _, ok := m.(*link.Welcome); ok {
			close(welcomed)
		}
		return nil
	}})
	defer sess.Close()
	go sess.Run(ctx)
	if err := sess.Send(ctx, link.PrioCritical, &link.Hello{Proto: 1, Minor: link.ProtoMinor, Host: "h1", Version: "test", Token: tok}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-welcomed:
	case <-ctx.Done():
		t.Fatal("no welcome")
	}
	if err := sess.Send(ctx, link.PrioCritical, &link.Heartbeat{Seq: 7, HostClock: time.Now(), RTTUs: 1500}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "the heartbeat's head and rtt", func() bool {
		st, ok := x.c.AgentStatus("h1")
		return ok && st.HeadSeq == 7 && st.RTT == 1500*time.Microsecond
	})
}
