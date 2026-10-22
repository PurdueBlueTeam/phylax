package agent

import (
	"context"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// A producer that emits the instant it starts must not lose its event to a
// subscriber module that subscribes late.
func TestEventsPublishedBeforeSubscribeAreReplayed(t *testing.T) {
	ctl := newFakeController(t, "ubuntu-ecom", "tok-1", 0)
	l := Layout{Root: t.TempDir()}
	writeBundle(t, l, ctl, "tok-1")
	ready := make(chan *Agent)
	got := make(chan event.Event, 16)
	consumer := funcModule{"consumer", func(ctx context.Context, _ Emit) error {
		a := <-ready
		time.Sleep(300 * time.Millisecond) // subscribe well after the producer emitted
		ch, unsub := Env{a: a}.Subscribe(64)
		defer unsub()
		for {
			select {
			case e := <-ch:
				if e.Kind == "test.early" {
					got <- e
				}
			case <-ctx.Done():
				return nil
			}
		}
	}}
	producer := funcModule{"producer", func(ctx context.Context, emit Emit) error {
		emit(event.Event{Kind: "test.early", Priority: event.PriorityHigh})
		<-ctx.Done()
		return nil
	}}
	r := startAgent(t, Config{Layout: l, Version: "1", HeartbeatInterval: 50 * time.Millisecond,
		Modules: []ModuleSpec{{Module: consumer, Subscriber: true}, {Module: producer}}})
	ready <- r.a
	select {
	case e := <-got:
		if e.Agent != "ubuntu-ecom" {
			t.Fatalf("replayed event lost its agent: %+v", e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("event published before the subscriber started was lost")
	}
	eventually(t, 5*time.Second, "buffer released after subscribe", func() bool { return r.a.Held() == 0 })
}

func TestHoldIsBoundedAndTimesOut(t *testing.T) {
	a := &Agent{}
	a.expectSubscriber(ModuleSpec{Subscriber: true})
	for i := 0; i < heldMax+100; i++ {
		a.publish(event.Event{Agent: "h", Kind: "k", Time: time.Now(), Fields: map[string]any{"i": i}})
	}
	if n := a.Held(); n != heldMax {
		t.Fatalf("held %d, want bound %d", n, heldMax)
	}
	ch, unsub := a.subscribe(10)
	defer unsub()
	if len(ch) != 10 {
		t.Fatalf("replay should be capped by the tap size, got %d", len(ch))
	}
	if first := (<-ch).Fields["i"]; first != heldMax+100-10 {
		t.Fatalf("replay should keep the newest events, first i=%v", first)
	}
	if a.Held() != 0 {
		t.Fatal("buffer not released after the awaited subscriber arrived")
	}
	// A subscriber that never arrives: the hold gives up after its deadline.
	b := &Agent{}
	b.expectSubscriber(ModuleSpec{Subscriber: true})
	b.holdUntil = time.Now().Add(-time.Second)
	b.publish(event.Event{Agent: "h", Kind: "k"})
	if b.Held() != 0 || b.subWait != 0 {
		t.Fatalf("expired hold not abandoned: held=%d wait=%d", b.Held(), b.subWait)
	}
}
