package enroll

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

type eventRecorder struct {
	mu  sync.Mutex
	evs []event.Event
}

func (r *eventRecorder) emit(_ context.Context, e event.Event) (event.Event, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, e)
	return e, nil
}

func (r *eventRecorder) kinds() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.evs))
	for i := range r.evs {
		out[i] = r.evs[i].Kind
	}
	return out
}

type alertRecorder struct {
	mu  sync.Mutex
	got []Alert
}

type Alert struct {
	Host, Kind, Detail string
}

func (r *alertRecorder) alert(host, kind, detail string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, Alert{Host: host, Kind: kind, Detail: detail})
}

func (r *alertRecorder) kinds() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.got))
	for i := range r.got {
		out[i] = r.got[i].Kind
	}
	return out
}

func newAuthorizeFixture(t *testing.T) (*enrFixture, *eventRecorder, *alertRecorder) {
	evs, alerts := &eventRecorder{}, &alertRecorder{}
	f := newEnrollerWith(t, func(o *Options) {
		o.Emit = evs.emit
		o.Alert = alerts.alert
	})
	return f, evs, alerts
}

func authorize(t *testing.T, f *enrFixture, host, tok string, pin link.Pin) (Result, error) {
	t.Helper()
	return f.e.Authorize(context.Background(), &link.Hello{Proto: 1, Host: host, Token: tok}, pin)
}

func TestAuthorizeFirstEnrollment(t *testing.T) {
	f, evs, _ := newAuthorizeFixture(t)
	tok, err := f.e.MintToken("h1", 0)
	if err != nil {
		t.Fatal(err)
	}
	pin := link.Pin{1}
	res, err := authorize(t, f, "h1", tok, pin)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Enrolled || res.Reenrolled {
		t.Fatalf("Result = %+v, want Enrolled only", res)
	}
	ag, err := f.st.Agent(context.Background(), "h1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ag.PubKey, pin[:]) {
		t.Fatalf("stored key = %x, want %x", ag.PubKey, pin[:])
	}
	if err := f.e.Announce(context.Background(), "h1", pin, res); err != nil {
		t.Fatal(err)
	}
	if got := evs.kinds(); len(got) != 1 || got[0] != "agent.enrolled" {
		t.Fatalf("emitted %v, want one agent.enrolled", got)
	}
	e := evs.evs[0]
	if e.Fields["host"] != "h1" || e.Fields["key_hash"] != pin.String() || e.Fields["manifest"] != "h1" {
		t.Fatalf("agent.enrolled fields = %#v", e.Fields)
	}
}

func TestAuthorizeRefusals(t *testing.T) {
	t.Run("unknown host without token", func(t *testing.T) {
		f, _, alerts := newAuthorizeFixture(t)
		if _, err := authorize(t, f, "h1", "", link.Pin{1}); err == nil {
			t.Fatal("unknown host without a token was admitted")
		}
		if got := alerts.kinds(); len(got) != 1 || got[0] != "enroll.refused" {
			t.Fatalf("alerts = %v, want one enroll.refused", got)
		}
	})

	t.Run("wrong host token is not burned", func(t *testing.T) {
		f, _, alerts := newAuthorizeFixture(t)
		tok, err := f.e.MintToken("h2", 0)
		if err != nil {
			t.Fatal(err)
		}
		pin := link.Pin{2}
		if _, err := authorize(t, f, "h1", tok, pin); !errors.Is(err, ErrTokenHost) {
			t.Fatalf("wrong-host token err = %v, want ErrTokenHost", err)
		}
		if got := alerts.kinds(); len(got) != 1 || got[0] != "enroll.refused" {
			t.Fatalf("alerts = %v, want one enroll.refused", got)
		}
		if _, err := authorize(t, f, "h2", tok, pin); err != nil {
			t.Fatalf("the token was burned by the wrong-host claim: %v", err)
		}
	})

	t.Run("known host with a different key", func(t *testing.T) {
		f, _, alerts := newAuthorizeFixture(t)
		tok, _ := f.e.MintToken("h1", 0)
		if _, err := authorize(t, f, "h1", tok, link.Pin{3}); err != nil {
			t.Fatal(err)
		}
		if _, err := authorize(t, f, "h1", "", link.Pin{4}); !errors.Is(err, store.ErrKeyMismatch) {
			t.Fatalf("different key err = %v, want store.ErrKeyMismatch", err)
		}
		if got := alerts.kinds(); len(got) != 1 || got[0] != "enroll.key_mismatch" {
			t.Fatalf("alerts = %v, want one enroll.key_mismatch", got)
		}
	})

	t.Run("key reuse across hosts", func(t *testing.T) {
		f, _, alerts := newAuthorizeFixture(t)
		tok, _ := f.e.MintToken("h1", 0)
		pin := link.Pin{5}
		if _, err := authorize(t, f, "h1", tok, pin); err != nil {
			t.Fatal(err)
		}
		tok2, _ := f.e.MintToken("h2", 0)
		if _, err := authorize(t, f, "h2", tok2, pin); err == nil {
			t.Fatal("a key enrolled as h1 was admitted as h2")
		}
		if got := alerts.kinds(); len(got) != 1 || got[0] != "enroll.key_reuse" {
			t.Fatalf("alerts = %v, want one enroll.key_reuse", got)
		}
	})
}

func TestRevokeThenReenroll(t *testing.T) {
	ctx := context.Background()
	f, evs, _ := newAuthorizeFixture(t)
	keyA, keyB := link.Pin{0xA}, link.Pin{0xB}
	tok, _ := f.e.MintToken("h1", 0)
	first, err := authorize(t, f, "h1", tok, keyA)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.e.Announce(ctx, "h1", keyA, first); err != nil {
		t.Fatal(err)
	}

	prevSeq, prevHash := uint64(0), ""
	for i := 0; i < 5; i++ {
		e := event.Event{Agent: "h1", Time: time.Now().UTC(), Kind: "test.ev", Priority: event.PriorityNormal,
			Fields: map[string]any{"i": i}}
		if err := e.Seal(prevSeq, prevHash); err != nil {
			t.Fatal(err)
		}
		if _, err := f.st.Ingest(ctx, "h1", []event.Event{e}); err != nil {
			t.Fatal(err)
		}
		prevSeq, prevHash = e.Seq, e.Hash
	}

	if err := f.e.Revoke(ctx, "h1"); err != nil {
		t.Fatal(err)
	}
	if !f.e.Revoked("h1") {
		t.Fatal("Revoked(h1) is false after Revoke")
	}
	if _, err := authorize(t, f, "h1", "", keyA); !errors.Is(err, ErrRevoked) {
		t.Fatalf("old key after revoke: %v, want ErrRevoked", err)
	}

	tok2, _ := f.e.MintToken("h1", 0)
	res, err := authorize(t, f, "h1", tok2, keyB)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reenrolled || res.Enrolled {
		t.Fatalf("Result = %+v, want Reenrolled only", res)
	}
	if err := f.e.Announce(ctx, "h1", keyB, res); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, k := range evs.kinds() {
		if k == "agent.reenrolled" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("agent.reenrolled emitted %d times, want 1 (%v)", n, evs.kinds())
	}
	if f.e.Revoked("h1") {
		t.Fatal("Revoked(h1) is still true after re-enrollment")
	}
	ag, err := f.st.Agent(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ag.PubKey, keyB[:]) || ag.LastSeq != 0 {
		t.Fatalf("new agent row = key %x last_seq %d, want key %x last_seq 0", ag.PubKey, ag.LastSeq, keyB[:])
	}
	old, err := f.st.Agent(ctx, "h1~1")
	if err != nil {
		t.Fatal(err)
	}
	if old.LastSeq != 5 {
		t.Fatalf("archived last_seq = %d, want 5", old.LastSeq)
	}
	if c, err := f.st.Count(ctx, "h1~1"); err != nil || c != 5 {
		t.Fatalf("archived count = %d, %v; want 5, nil", c, err)
	}
}

