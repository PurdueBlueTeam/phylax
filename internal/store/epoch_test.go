package store

import (
	"context"
	"testing"
)

// RaiseEpoch only moves forward, appends a history row when it does, and
// returns the epoch in force.
func TestRaiseEpoch(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	if ep, err := s.RaiseEpoch(ctx, 3, "setup"); err != nil || ep != 3 {
		t.Fatalf("RaiseEpoch(3) = %d, %v", ep, err)
	}
	eps, err := s.Epochs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n := len(eps)
	if ep, err := s.RaiseEpoch(ctx, 2, "lower"); err != nil || ep != 3 {
		t.Fatalf("RaiseEpoch(2) = %d, %v; want the epoch in force 3", ep, err)
	}
	if eps, _ := s.Epochs(ctx); len(eps) != n {
		t.Fatalf("a lower raise added a history row: %+v", eps)
	}
	if ep, err := s.RaiseEpoch(ctx, 7, "r"); err != nil || ep != 7 {
		t.Fatalf("RaiseEpoch(7) = %d, %v", ep, err)
	}
	if ep, _ := s.Epoch(ctx); ep != 7 {
		t.Fatalf("Epoch() = %d, want 7", ep)
	}
	eps, _ = s.Epochs(ctx)
	if last := eps[len(eps)-1]; last.Epoch != 7 || last.Reason != "r" {
		t.Fatalf("history ends with %+v", last)
	}
	// An agent enrolled now belongs to the epoch in force.
	enroll(t, s, "a")
	if a, err := s.Agent(ctx, "a"); err != nil || a.Epoch != 7 {
		t.Fatalf("agent %+v, %v", a, err)
	}
}
