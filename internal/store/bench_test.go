package store

import (
	"context"
	"testing"
)

func TestCommitHistAndSize(t *testing.T) {
	s, _ := open(t)
	enroll(t, s, "a")
	size0 := s.Size()
	if size0 <= 0 {
		t.Fatalf("Size() = %d on a fresh store", size0)
	}
	c := &chain{agent: "a"}
	for i := 0; i < 3; i++ {
		if _, err := s.Ingest(context.Background(), "a", c.many(50, "k")); err != nil {
			t.Fatal(err)
		}
	}
	if n := s.CommitHist().Count(); n != 3 {
		t.Fatalf("CommitHist count = %d, want 3 (one per successful Ingest)", n)
	}
	if got := s.Size(); got <= size0 {
		t.Fatalf("Size() did not grow: %d -> %d", size0, got)
	}

	// A failure before the commit adds no observation.
	if _, err := s.Ingest(context.Background(), "nobody", (&chain{agent: "nobody"}).many(1, "k")); err == nil {
		t.Fatal("ingest of an unknown agent was accepted")
	}
	if n := s.CommitHist().Count(); n != 3 {
		t.Fatalf("CommitHist count = %d after a failed ingest, want 3", n)
	}
}
