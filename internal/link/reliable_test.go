package link

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func TestReceiverDedupAndOutOfOrder(t *testing.T) {
	mk := func(seqs ...uint64) []event.Event {
		var out []event.Event
		for _, s := range seqs {
			out = append(out, event.Event{Seq: s})
		}
		return out
	}
	r := NewReceiver(0, 100)
	f, _ := r.Fresh(mk(3, 3, 1))
	if len(f) != 2 {
		t.Fatalf("in-batch duplicate not removed: %d", len(f))
	}
	if ack := r.Commit(f); ack != 1 {
		t.Fatalf("ack with a gap at 2 = %d, want 1", ack)
	}
	f, _ = r.Fresh(mk(1, 2, 3, 4))
	if len(f) != 2 || f[0].Seq != 2 || f[1].Seq != 4 {
		t.Fatalf("already-stored events not filtered: %+v", f)
	}
	if ack := r.Commit(f); ack != 4 {
		t.Fatalf("ack after filling gap = %d, want 4", ack)
	}
	if _, err := r.Fresh(mk(4 + 101)); !errors.Is(err, ErrWindow) {
		t.Fatalf("want ErrWindow, got %v", err)
	}
	// Fresh alone changes nothing: a failed store can be retried.
	r2 := NewReceiver(0, 100)
	r2.Fresh(mk(1))
	if f, _ := r2.Fresh(mk(1)); len(f) != 1 {
		t.Fatal("Fresh must not mutate state")
	}
}

func TestBackoffBounds(t *testing.T) {
	b := Backoff{Min: time.Second, Max: 30 * time.Second}
	var last time.Duration
	for i := 0; i < 12; i++ {
		d := b.Next()
		if d < 500*time.Millisecond || d > 30*time.Second {
			t.Fatalf("delay %v out of bounds", d)
		}
		last = d
	}
	if last < 15*time.Second {
		t.Fatalf("backoff did not grow to the cap: %v", last)
	}
	b.Reset()
	if d := b.Next(); d > time.Second {
		t.Fatalf("reset ineffective: %v", d)
	}
}

// controllerStore plays the controller: a persistent Receiver and store per
// host, kept across connections, with a hook to sever the link mid-stream.
type controllerStore struct {
	mu       sync.Mutex
	rx       *Receiver
	stored   map[uint64]int
	order    []event.Event
	hellos   int
	killAt   []int // sever the connection each time stored count reaches the next value
	severed  int
	lastHost string
}

func (cs *controllerStore) handler(ctx context.Context, c *Conn) {
	var sess *Session
	sess = NewSession(c, Options{
		Role:    RoleController,
		AckFunc: cs.rx.Acked,
		Handler: func(ctx context.Context, m Message) error {
			switch v := m.(type) {
			case *Hello:
				cs.mu.Lock()
				cs.hellos++
				cs.lastHost = v.Host
				cs.mu.Unlock()
				sess.TrySend(PrioCritical, &Welcome{Proto: ProtoVersion})
				sess.TrySend(PrioCritical, &Ack{Seq: cs.rx.Acked()})
			case *Events:
				fresh, err := cs.rx.Fresh(v.Events)
				if err != nil {
					return err
				}
				cs.mu.Lock()
				for _, e := range fresh {
					cs.stored[e.Seq]++
					cs.order = append(cs.order, e)
				}
				n := len(cs.stored)
				kill := len(cs.killAt) > 0 && n >= cs.killAt[0]
				if kill {
					cs.killAt = cs.killAt[1:]
					cs.severed++
				}
				cs.mu.Unlock()
				if kill {
					// Die after storing but before acking: the agent will resend
					// events the controller already holds.
					cs.rx.Commit(fresh)
					c.Close()
					return errors.New("severed")
				}
				sess.TrySend(PrioCritical, &Ack{Seq: cs.rx.Commit(fresh)})
			}
			return nil
		}})
	sess.Run(ctx)
}

func TestAckAndResendAcrossForcedDisconnects(t *testing.T) {
	const total = 3000
	cs := &controllerStore{rx: NewReceiver(0, 1<<16), stored: map[uint64]int{}, killAt: []int{400, 1300, 2200}}
	e := startServer(t, ServerOptions{Handlers: map[string]Handler{ALPNAgent: cs.handler}})

	src := &memSource{}
	// Mixed priorities and small batches so higher-priority batches overtake
	// queued lower ones, exercising out-of-order delivery as well as resend.
	for i := 0; i < total/2; i++ {
		p := event.PriorityBulk
		if i%5 == 0 {
			p = event.PriorityCritical
		}
		src.add(1, p)
	}
	notify := make(chan struct{}, 1)
	go func() { // events keep arriving while the link flaps
		for i := total / 2; i < total; i++ {
			src.add(1, event.PriorityNormal)
			select {
			case notify <- struct{}{}:
			default:
			}
			if i%100 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connects := 0
	bo := Backoff{Min: 5 * time.Millisecond, Max: 20 * time.Millisecond}
	for cs.rx.Acked() < total {
		if ctx.Err() != nil {
			t.Fatalf("timed out at ack %d", cs.rx.Acked())
		}
		c, err := Dial(ctx, e.addr, DialOptions{Identity: e.cliID, ServerPin: e.srvID.Pin, ALPN: ALPNAgent})
		if err != nil {
			time.Sleep(bo.Next())
			continue
		}
		connects++
		sess := NewSession(c, Options{Role: RoleAgent, ReadIdle: 5 * time.Second})
		runCtx, runCancel := context.WithCancel(ctx)
		go sess.Run(runCtx)
		sess.TrySend(PrioCritical, &Hello{Proto: ProtoVersion, Host: "h1", Version: "t"})
		up := &Uplink{Session: sess, Source: src, BatchMax: 7, Window: 200, Notify: notify, Poll: 5 * time.Millisecond}
		upErr := make(chan error, 1)
		go func() { upErr <- up.Run(runCtx) }()
		select {
		case <-sess.Done():
		case <-upErr:
		case <-func() chan struct{} {
			ch := make(chan struct{})
			go func() {
				for cs.rx.Acked() < total && runCtx.Err() == nil {
					time.Sleep(5 * time.Millisecond)
				}
				close(ch)
			}()
			return ch
		}():
		}
		runCancel()
		sess.Close()
		time.Sleep(bo.Next())
	}

	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.severed != 3 {
		t.Fatalf("expected 3 forced disconnects, got %d (test did not exercise resend)", cs.severed)
	}
	if connects < 4 || cs.hellos < 4 {
		t.Fatalf("expected reconnects, connects=%d hellos=%d", connects, cs.hellos)
	}
	for seq := uint64(1); seq <= total; seq++ {
		if n := cs.stored[seq]; n != 1 {
			t.Fatalf("seq %d stored %d times (loss or duplication)", seq, n)
		}
	}
	if len(cs.order) != total {
		t.Fatalf("stored %d events, want %d", len(cs.order), total)
	}
	// The hash chain verifies when events are ordered by sequence.
	bySeq := make(map[uint64]event.Event, total)
	for _, ev := range cs.order {
		bySeq[ev.Seq] = ev
	}
	prevSeq, prevHash := uint64(0), event.GenesisHash
	for seq := uint64(1); seq <= total; seq++ {
		ev := bySeq[seq]
		if err := ev.Verify(prevSeq, prevHash); err != nil {
			t.Fatal(err)
		}
		prevSeq, prevHash = ev.Seq, ev.Hash
	}
}

func TestUplinkWindowBoundsInflight(t *testing.T) {
	a, b := tcpPair(t)
	src := &memSource{}
	src.add(500, event.PriorityNormal)
	agent := NewSession(a, Options{Role: RoleAgent})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go agent.Run(ctx)
	var mu sync.Mutex
	maxSeq := uint64(0)
	ctrl := NewSession(b, Options{Role: RoleController, Handler: func(ctx context.Context, m Message) error {
		if ev, ok := m.(*Events); ok {
			mu.Lock()
			for _, e := range ev.Events {
				maxSeq = max(maxSeq, e.Seq)
			}
			mu.Unlock()
		}
		return nil
	}})
	go ctrl.Run(ctx)
	ctrl.TrySend(PrioCritical, &Ack{Seq: 0})
	up := &Uplink{Session: agent, Source: src, BatchMax: 10, Window: 50, Poll: 5 * time.Millisecond}
	go up.Run(ctx)
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	got := maxSeq
	mu.Unlock()
	if got != 50 {
		t.Fatalf("without acks the uplink should stall at the window (50), sent up to %d", got)
	}
	ctrl.TrySend(PrioCritical, &Ack{Seq: 50})
	eventually(t, 2*time.Second, "window to advance after ack", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return maxSeq == 100
	})
}
