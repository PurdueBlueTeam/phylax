package spool

import (
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// SetAck is the first ack of a session after a restore: the controller really
// has less than the agent believes, so the ack (and the send cursor) move
// backwards and everything above it is sent again.
func TestSetAckLowersAndResends(t *testing.T) {
	s := open(t, t.TempDir(), Options{})
	defer s.Close()
	for i := 0; i < 20; i++ {
		mustAppend(t, s, ev(event.PriorityNormal, i, 10))
	}
	if err := s.Ack(20); err != nil {
		t.Fatal(err)
	}
	if got := s.Stats().AckSeq; got != 20 {
		t.Fatalf("ack after Ack(20) = %d", got)
	}
	// Drain the send cursor to the head, as a finished session would.
	if _, err := s.ReadBatch(100, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAck(12); err != nil {
		t.Fatal(err)
	}
	if got := s.Stats().AckSeq; got != 12 {
		t.Fatalf("ack after SetAck(12) = %d, want 12", got)
	}
	batch, err := s.ReadBatch(100, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != 8 || batch[0].Seq != 13 || batch[len(batch)-1].Seq != 20 {
		t.Fatalf("resend got %d events, seq %d..%d; want 8 events, 13..20", len(batch), batch[0].Seq, batch[len(batch)-1].Seq)
	}
	// Above the head clamps to the head, not past it.
	if err := s.SetAck(99); err != nil {
		t.Fatal(err)
	}
	if got := s.Stats().AckSeq; got != 20 {
		t.Fatalf("ack after SetAck(99) = %d, want the head 20", got)
	}
}
