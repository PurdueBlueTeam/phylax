package spool

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestChainAndReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		if _, _, err := s.Append(Event{TS: time.Unix(int64(i), 0), Type: "heartbeat", Data: []byte(fmt.Sprint(i))}); err != nil {
			t.Fatal(err)
		}
	}
	if bad, n := s.Verify(); bad != 0 {
		t.Fatalf("chain bad at seq %d of %d", bad, n)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: chain must still verify and state must match.
	s2, err := Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.MaxSeq() != 5 || s2.Count() != 5 {
		t.Fatalf("reopen state = seq %d count %d", s2.MaxSeq(), s2.Count())
	}
	if bad, _ := s2.Verify(); bad != 0 {
		t.Fatalf("reopen chain bad at %d", bad)
	}
	recs, err := s2.Range(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 5 || recs[0].Seq != 1 || recs[4].Seq != 5 {
		t.Fatalf("range = %d records", len(recs))
	}
	if recs[2].Prev != recs[1].Hash || recs[2].Seq != 3 {
		t.Fatal("linking broken after reopen")
	}
}

func TestTamperDetected(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 4; i++ {
		s.Append(Event{TS: time.Unix(int64(i), 0), Type: "event", Data: []byte{byte(i)}})
	}
	s.Close()

	p := filepath.Join(dir, "spool.jsonl")
	b, _ := os.ReadFile(p)
	// Flip a byte in the second line (seq 2 payload).
	line1 := b
	idx := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			idx = i + 1
			break
		}
	}
	b[idx+10] ^= 0xFF
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = line1

	_, err = Open(dir, 0)
	if err == nil {
		t.Fatal("tampered spool opened without error")
	}
}

func TestShedOrder(t *testing.T) {
	dir := t.TempDir()
	// Tiny cap: ~40 bytes per record; cap at 3 records worth.
	s, err := Open(dir, 120)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// seq 1,2: protected; 3: log; 4: churn; 5: flow; 6: log
	s.Append(Event{TS: time.Now(), Type: "alert", Data: []byte("a"), Class: ClassProtected})
	s.Append(Event{TS: time.Now(), Type: "heartbeat", Data: []byte("b"), Class: ClassProtected})
	s.Append(Event{TS: time.Now(), Type: "log", Data: []byte("c"), Class: ClassLog})
	s.Append(Event{TS: time.Now(), Type: "churn", Data: []byte("d"), Class: ClassChurn})
	s.Append(Event{TS: time.Now(), Type: "flow", Data: []byte("e"), Class: ClassFlow})
	s.Append(Event{TS: time.Now(), Type: "log", Data: []byte("f"), Class: ClassLog})

	// No acks yet: shedding must drop unacked by class (log first), keeping
	// all protected records.
	if _, err := s.Shed(); err != nil {
		t.Fatal(err)
	}
	if !s.Full() && s.Count() == 6 {
		t.Fatal("shed did nothing")
	}
	recs, _ := s.Range(0, 0)
	bySeq := map[uint64]int{}
	for _, r := range recs {
		bySeq[r.Seq] = r.Class
	}
	if _, ok := bySeq[1]; !ok {
		t.Fatal("protected seq 1 was shed")
	}
	if _, ok := bySeq[2]; !ok {
		t.Fatal("protected seq 2 was shed")
	}
	if bad, _ := s.Verify(); bad != 0 {
		t.Fatalf("chain broken after shed at %d", bad)
	}

	// Ack everything, shed again: everything acked drops oldest first.
	s.Ack(s.MaxSeq())
	before := s.Count()
	if _, err := s.Shed(); err != nil {
		t.Fatal(err)
	}
	after := s.Count()
	if after >= before {
		t.Fatalf("acked records not shed: before=%d after=%d", before, after)
	}
}
