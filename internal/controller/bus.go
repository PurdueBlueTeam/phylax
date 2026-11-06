package controller

import (
	"sync"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

const (
	busDefaultBuf = 1024
	busMaxBuf     = 65536
)

// eventBus fans committed events out to controller modules. A subscriber that
// cannot keep up loses events (counted per module) rather than blocking ingest.
type eventBus struct {
	mu   sync.Mutex
	subs map[*busSub]struct{}
}

type busSub struct {
	module  string
	kinds   map[string]bool
	ch      chan event.Event
	dropped uint64
}

func newEventBus() *eventBus {
	return &eventBus{subs: map[*busSub]struct{}{}}
}

// subscribe registers a filtered subscriber. The returned stop removes it
// under the lock and then closes the channel, so the publisher can never send
// on a closed channel.
func (b *eventBus) subscribe(module string, kinds []string, buf int) (<-chan event.Event, func()) {
	if buf <= 0 {
		buf = busDefaultBuf
	}
	if buf > busMaxBuf {
		buf = busMaxBuf
	}
	s := &busSub{module: module, kinds: make(map[string]bool, len(kinds)), ch: make(chan event.Event, buf)}
	for _, k := range kinds {
		s.kinds[k] = true
	}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, s)
			b.mu.Unlock()
			close(s.ch)
		})
	}
	return s.ch, stop
}

// publish delivers a committed batch. It never blocks: a full subscriber
// channel drops the event and increments that module's drop counter.
func (b *eventBus) publish(evs []event.Event) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for s := range b.subs {
		for _, e := range evs {
			if !s.kinds[e.Kind] {
				continue
			}
			select {
			case s.ch <- e:
			default:
				s.dropped++
			}
		}
	}
}

// dropped returns the number of events dropped for a module since subscribe.
func (b *eventBus) dropped(module string) uint64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var n uint64
	for s := range b.subs {
		if s.module == module {
			n += s.dropped
		}
	}
	return n
}
