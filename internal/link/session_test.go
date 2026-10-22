package link

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// tcpPair returns both ends of a real loopback TCP connection.
func tcpPair(t *testing.T) (a, b net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	a, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b = <-ch
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func evMsg(seq uint64, p event.Priority) *Events {
	return &Events{Events: []event.Event{{Agent: "h", Seq: seq, Kind: "k", Priority: p, Time: time.Unix(1, 0)}}}
}

func readTypes(t *testing.T, c net.Conn, n int) []Message {
	t.Helper()
	fr := NewFrameReader(c)
	var out []Message
	for len(out) < n {
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		typ, body, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read after %d frames: %v", len(out), err)
		}
		m, err := Unmarshal(typ, body)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func TestStrictPriorityOrder(t *testing.T) {
	a, b := tcpPair(t)
	s := NewSession(a, Options{Role: RoleAgent})
	digest := strings.Repeat("00", 32)
	// Queue lowest priority first, before the writer runs.
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.TrySend(PrioBulk, &Chunk{SHA256: digest, Total: 1, Data: []byte("x")}))
	must(s.TrySend(PrioTelemetry, evMsg(5, event.PriorityNormal)))
	must(s.TrySend(PrioFlow, evMsg(4, event.PriorityHigh)))
	must(s.TrySend(PrioEvidence, evMsg(3, event.PriorityHigh)))
	must(s.TrySend(PrioStep, &StepResult{Plan: "p", Node: "n", Phase: "apply", Status: "ok"}))
	must(s.TrySend(PrioCritical, &Heartbeat{Seq: 1, HostClock: time.Now()}))
	must(s.TrySend(PrioTelemetry, evMsg(6, event.PriorityNormal)))
	must(s.TrySend(PrioCritical, &Ack{Seq: 1}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	got := readTypes(t, b, 8)
	var order []string
	for _, m := range got {
		switch v := m.(type) {
		case *Events:
			order = append(order, "e"+string(rune('0'+v.Events[0].Seq)))
		default:
			order = append(order, m.MsgType().String())
		}
	}
	want := "heartbeat ack step_result e3 e4 e5 e6 chunk"
	if strings.Join(order, " ") != want {
		t.Fatalf("send order\n got %v\nwant %s", order, want)
	}
}

func TestBoundedQueuesAndBackpressure(t *testing.T) {
	a, b := tcpPair(t)
	var o Options
	o.Role = RoleAgent
	o.Queues[PrioTelemetry] = QueueLimit{Msgs: 3}
	s := NewSession(a, o)
	for i := 1; i <= 3; i++ {
		if err := s.TrySend(PrioTelemetry, evMsg(uint64(i), event.PriorityNormal)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.TrySend(PrioTelemetry, evMsg(4, event.PriorityNormal)); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("want ErrQueueFull, got %v", err)
	}
	// A full telemetry queue must not affect critical traffic.
	if err := s.TrySend(PrioCritical, &Ack{Seq: 1}); err != nil {
		t.Fatalf("critical blocked by full telemetry queue: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := s.Send(ctx, PrioTelemetry, evMsg(4, event.PriorityNormal)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocking send should time out, got %v", err)
	}
	// Blocked Send completes once the writer drains.
	done := make(chan error, 1)
	go func() { done <- s.Send(context.Background(), PrioTelemetry, evMsg(4, event.PriorityNormal)) }()
	time.Sleep(30 * time.Millisecond)
	rctx, rcancel := context.WithCancel(context.Background())
	defer rcancel()
	go s.Run(rctx)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	readTypes(t, b, 5)
}

func TestHeartbeatCoalescing(t *testing.T) {
	a, b := tcpPair(t)
	s := NewSession(a, Options{Role: RoleAgent})
	for i := 1; i <= 5; i++ {
		s.TrySend(PrioCritical, &Heartbeat{Seq: uint64(i), HostClock: time.Now()})
	}
	s.TrySend(PrioCritical, &Ack{Seq: 9})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	got := readTypes(t, b, 2)
	hb, ok := got[0].(*Heartbeat)
	if !ok || hb.Seq != 5 {
		t.Fatalf("expected only the newest heartbeat first, got %#v", got[0])
	}
	if _, ok := got[1].(*Ack); !ok {
		t.Fatalf("expected ack second, got %#v", got[1])
	}
}

func TestRoleEnforcedAndUnknownTypeFatal(t *testing.T) {
	for _, tc := range []struct {
		name string
		send func(w net.Conn)
		want error
	}{
		{"wrong-direction", func(w net.Conn) {
			fw := NewFrameWriter(w)
			_, body, _ := Marshal(&Step{Plan: "p", Node: "n", Host: "h", Action: "a", Sig: "s"})
			fw.WriteFrame(TypeStep, body, false)
		}, ErrUnexpected},
		{"unknown-type", func(w net.Conn) { NewFrameWriter(w).WriteFrame(Type(0x3e), []byte(`{}`), false) }, ErrUnknownType},
		{"bad-body", func(w net.Conn) { NewFrameWriter(w).WriteFrame(TypeHello, []byte(`{"proto":1}`), false) }, ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := tcpPair(t)
			s := NewSession(a, Options{Role: RoleController}) // controller must not accept a step
			errc := make(chan error, 1)
			go func() { errc <- s.Run(context.Background()) }()
			tc.send(b)
			select {
			case err := <-errc:
				if !errors.Is(err, tc.want) {
					t.Fatalf("want %v, got %v", tc.want, err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("session survived a protocol violation")
			}
		})
	}
}

func TestReadIdleEndsSession(t *testing.T) {
	a, _ := tcpPair(t)
	s := NewSession(a, Options{Role: RoleController, ReadIdle: 150 * time.Millisecond})
	errc := make(chan error, 1)
	go func() { errc <- s.Run(context.Background()) }()
	select {
	case err := <-errc:
		if !isTimeoutErr(err) {
			t.Fatalf("want timeout, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("silent peer never timed out")
	}
}

func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func TestSlowHandlerDoesNotStallControlOrAcks(t *testing.T) {
	a, b := tcpPair(t)
	release := make(chan struct{})
	var seenHB, seenCtl atomic.Bool
	ctrl := NewSession(a, Options{Role: RoleController, AckFunc: func() uint64 { return 77 },
		Handler: func(ctx context.Context, m Message) error {
			switch m.(type) {
			case *Events:
				<-release // a handler stuck on slow storage
			case *Heartbeat:
				seenHB.Store(true)
			}
			return nil
		}})
	gotAck := make(chan uint64, 1)
	agent := NewSession(b, Options{Role: RoleAgent, Handler: func(ctx context.Context, m Message) error {
		if c, ok := m.(*Control); ok && c.Kind == "x" {
			seenCtl.Store(true)
		}
		return nil
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ctrl.Run(ctx)
	go agent.Run(ctx)
	agent.TrySend(PrioTelemetry, evMsg(1, event.PriorityNormal))
	agent.TrySend(PrioCritical, &Heartbeat{Seq: 1, HostClock: time.Now()})
	eventually(t, 2*time.Second, "heartbeat handled and acked while events handler is stuck", func() bool {
		seq, seen := agent.Acked()
		if seen {
			select {
			case gotAck <- seq:
			default:
			}
		}
		return seenHB.Load() && seen
	})
	if seq := <-gotAck; seq != 77 {
		t.Fatalf("ack = %d", seq)
	}
	ctrl.TrySend(PrioCritical, &Control{Kind: "x", On: true})
	eventually(t, 2*time.Second, "control delivered", seenCtl.Load)
	close(release)
}

func TestHandlerOverflowEndsSession(t *testing.T) {
	a, b := tcpPair(t)
	block := make(chan struct{})
	defer close(block)
	ctrl := NewSession(a, Options{Role: RoleController, InboundQueue: 4,
		Handler: func(ctx context.Context, m Message) error { <-block; return nil }})
	errc := make(chan error, 1)
	go func() { errc <- ctrl.Run(context.Background()) }()
	fw := NewFrameWriter(b)
	_, body, _ := Marshal(evMsg(1, event.PriorityNormal))
	go func() {
		for i := 0; i < 50; i++ {
			if fw.WriteFrame(TypeEvents, body, false) != nil {
				return
			}
		}
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, ErrOverload) {
			t.Fatalf("want ErrOverload, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("unbounded inbound queue")
	}
}

func TestBulkRateLimitNeverDelaysCritical(t *testing.T) {
	a, b := tcpPair(t)
	s := NewSession(a, Options{Role: RoleAgent, BulkRate: 2 << 20})
	digest := strings.Repeat("11", 32)
	for i := 0; i < 8; i++ {
		data := make([]byte, ChunkSize)
		rand.Read(data)
		if err := s.TrySend(PrioBulk, &Chunk{SHA256: digest, Offset: uint64(i) * ChunkSize, Total: 8 * ChunkSize, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	go s.Run(ctx)
	frames := make(chan time.Duration, 16)
	go func() {
		fr := NewFrameReader(b)
		for {
			typ, _, err := fr.ReadFrame()
			if err != nil {
				return
			}
			if typ == TypeHeartbeat {
				frames <- time.Since(start)
			}
		}
	}()
	// Wait until the bucket is exhausted, then inject a heartbeat.
	time.Sleep(150 * time.Millisecond)
	s.TrySend(PrioCritical, &Heartbeat{Seq: 1, HostClock: time.Now()})
	select {
	case d := <-frames:
		if d > 400*time.Millisecond {
			t.Fatalf("heartbeat delayed %v behind throttled bulk", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("heartbeat starved by bulk")
	}
	eventually(t, 5*time.Second, "bulk to drain", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.q[PrioBulk]) == 0
	})
	if since := time.Since(start); since < 250*time.Millisecond {
		t.Fatalf("bulk was not rate limited (drained in %v)", since)
	}
}
