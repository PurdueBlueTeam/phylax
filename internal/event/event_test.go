package event

import (
	"errors"
	"testing"
	"time"
)

func chain(t *testing.T, n int) []Event {
	t.Helper()
	var out []Event
	var seq uint64
	prev := GenesisHash
	for i := 0; i < n; i++ {
		e := Event{Agent: "a1", Time: time.Unix(1700000000, int64(i)), Kind: "proc.exec", Fields: map[string]any{"pid": i, "b": "x", "a": []any{1, "two"}}}
		if err := e.Seal(seq, prev); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
		seq, prev = e.Seq, e.Hash
	}
	return out
}

func TestChainVerifies(t *testing.T) {
	evs := chain(t, 5)
	var seq uint64
	prev := GenesisHash
	for _, e := range evs {
		if err := e.Verify(seq, prev); err != nil {
			t.Fatalf("seq %d: %v", e.Seq, err)
		}
		seq, prev = e.Seq, e.Hash
	}
}

func TestTamperDetected(t *testing.T) {
	evs := chain(t, 3)
	cases := map[string]func(e *Event){
		"field":    func(e *Event) { e.Fields["pid"] = 999 },
		"kind":     func(e *Event) { e.Kind = "other" },
		"time":     func(e *Event) { e.Time = e.Time.Add(time.Second) },
		"priority": func(e *Event) { e.Priority = PriorityBulk },
	}
	for name, mut := range cases {
		e := evs[1]
		e.Fields = map[string]any{"pid": 1, "b": "x", "a": []any{1, "two"}}
		mut(&e)
		if err := e.Verify(evs[0].Seq, evs[0].Hash); !errors.Is(err, ErrChain) {
			t.Errorf("%s: tamper not detected: %v", name, err)
		}
	}
}

func TestGapAndReorderDetected(t *testing.T) {
	evs := chain(t, 3)
	if err := evs[2].Verify(evs[0].Seq, evs[0].Hash); !errors.Is(err, ErrChain) {
		t.Fatalf("gap not detected: %v", err)
	}
}

func TestCanonicalStableAcrossMapOrderAndZone(t *testing.T) {
	loc := time.FixedZone("X", 3600)
	t0 := time.Unix(1700000000, 5)
	a := Event{Agent: "a", Time: t0, Kind: "k", Fields: map[string]any{"z": 1, "a": 2}}
	b := Event{Agent: "a", Time: t0.In(loc), Kind: "k", Fields: map[string]any{"a": 2, "z": 1}}
	ha, _ := a.ComputeHash()
	hb, _ := b.ComputeHash()
	if ha != hb {
		t.Fatalf("canonical hash differs: %s vs %s", ha, hb)
	}
}
