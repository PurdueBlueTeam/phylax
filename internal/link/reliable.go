package link

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// EventSource is the agent-side spool as the link sees it: events with
// sequence numbers above `after`, in ascending order, at most max of them.
// The spool keeps events until the peer acks them, so a resend after a
// reconnect is just a read from the acked position.
type EventSource interface {
	Events(after uint64, max int) ([]event.Event, error)
}

// DefaultWindow is the Uplink in-flight window when Window is unset: the most
// events sent but not yet acked (5000).
const DefaultWindow uint64 = 5000

// Uplink streams events from a source over a session with a bounded
// in-flight window. It starts from the peer's first ack, so after a reconnect
// everything not acknowledged is sent again and nothing acknowledged is.
type Uplink struct {
	Session *Session
	Source  EventSource
	// BatchMax is the most events per message (default 500).
	BatchMax int
	// Window is the most events sent but not yet acked (default 5000).
	Window uint64
	// Poll is how often an idle uplink re-reads the source (default 250 ms).
	Poll time.Duration
	// Notify, if set, wakes the uplink when the source has new events.
	Notify <-chan struct{}
}

// Run blocks until ctx is cancelled, the session ends or the source fails.
func (u *Uplink) Run(ctx context.Context) error {
	if u.BatchMax <= 0 {
		u.BatchMax = 500
	}
	if u.Window == 0 {
		u.Window = DefaultWindow
	}
	if u.Poll <= 0 {
		u.Poll = 250 * time.Millisecond
	}
	cursor, err := u.Session.WaitFirstAck(ctx)
	if err != nil {
		return err
	}
	for {
		acked, _ := u.Session.Acked()
		if cursor < acked {
			cursor = acked
		}
		inflight := cursor - acked
		if inflight >= u.Window {
			select {
			case <-u.Session.AckChanged():
			case <-ctx.Done():
				return ctx.Err()
			case <-u.Session.Done():
				return u.Session.Err()
			}
			continue
		}
		room := min(uint64(u.BatchMax), u.Window-inflight)
		evs, err := u.Source.Events(cursor, int(room))
		if err != nil {
			return fmt.Errorf("link: event source: %w", err)
		}
		if len(evs) == 0 {
			t := time.NewTimer(u.Poll)
			select {
			case <-u.Notify:
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-u.Session.Done():
				t.Stop()
				return u.Session.Err()
			}
			t.Stop()
			continue
		}
		for len(evs) > 0 {
			n, err := u.sendBatch(ctx, evs)
			if err != nil {
				return err
			}
			cursor = evs[n-1].Seq
			evs = evs[n:]
		}
	}
}

// sendBatch sends a prefix of evs that fits in one frame and returns its length.
func (u *Uplink) sendBatch(ctx context.Context, evs []event.Event) (int, error) {
	for n := len(evs); n > 0; n /= 2 {
		batch := evs[:n]
		_, body, err := Marshal(&Events{Events: batch})
		if err != nil {
			return 0, err
		}
		if len(body) >= MaxDecompressed/2 && n > 1 {
			continue
		}
		prio := PrioBulk
		for _, e := range batch {
			prio = min(prio, EventPriority(e.Priority))
		}
		if err := u.Session.Send(ctx, prio, &Events{Events: batch}); err != nil {
			return 0, err
		}
		return n, nil
	}
	return 0, errors.New("link: single event too large")
}

// ErrWindow means an event's sequence is too far beyond the contiguous
// acknowledged position to track.
var ErrWindow = errors.New("link: event sequence beyond receive window")

// Receiver is the controller-side duplicate filter and ack tracker for one
// agent. It survives reconnects (keep one per host). Acks cover the highest
// contiguous sequence; events arriving out of order (a higher-priority batch
// overtaking a lower one) are remembered in a bounded set, so a resend after
// reconnect never delivers an event twice and never skips one.
type Receiver struct {
	mu         sync.Mutex
	contiguous uint64
	pending    map[uint64]struct{}
	maxAhead   uint64
}

// NewReceiver resumes from the highest contiguous sequence already stored
// (0 for a new agent). maxAhead bounds the out-of-order window (default 65536).
func NewReceiver(contiguous, maxAhead uint64) *Receiver {
	if maxAhead == 0 {
		maxAhead = 1 << 16
	}
	return &Receiver{contiguous: contiguous, pending: map[uint64]struct{}{}, maxAhead: maxAhead}
}

// Acked is the highest contiguous sequence committed.
func (r *Receiver) Acked() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.contiguous
}

// Fresh returns the events not yet committed (deduplicated, input order). It
// changes nothing; store them, then call Commit.
func (r *Receiver) Fresh(evs []event.Event) ([]event.Event, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []event.Event
	seen := map[uint64]struct{}{}
	for _, e := range evs {
		if e.Seq <= r.contiguous {
			continue
		}
		if e.Seq-r.contiguous > r.maxAhead {
			return nil, fmt.Errorf("%w: %d (acked %d)", ErrWindow, e.Seq, r.contiguous)
		}
		if _, ok := r.pending[e.Seq]; ok {
			continue
		}
		if _, ok := seen[e.Seq]; ok {
			continue
		}
		seen[e.Seq] = struct{}{}
		out = append(out, e)
	}
	return out, nil
}

// Commit records evs as durably stored and returns the new cumulative ack.
func (r *Receiver) Commit(evs []event.Event) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range evs {
		if e.Seq > r.contiguous {
			r.pending[e.Seq] = struct{}{}
		}
	}
	for {
		next := r.contiguous + 1
		if _, ok := r.pending[next]; !ok {
			return r.contiguous
		}
		delete(r.pending, next)
		r.contiguous = next
	}
}

// Backoff produces reconnect delays: exponential from Min to Max with jitter.
type Backoff struct {
	Min, Max time.Duration
	n        int
}

// Next returns the next delay (half to full of the exponential step).
func (b *Backoff) Next() time.Duration {
	lo, hi := b.Min, b.Max
	if lo <= 0 {
		lo = time.Second
	}
	if hi <= 0 {
		hi = 30 * time.Second
	}
	d := lo << min(b.n, 20)
	if d > hi || d <= 0 {
		d = hi
	} else {
		b.n++
	}
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

// Reset is called after a connection has been healthy.
func (b *Backoff) Reset() { b.n = 0 }
