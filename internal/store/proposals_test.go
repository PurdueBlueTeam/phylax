package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestProposalsRoundTrip(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	want := ProposalRow{Module: "ctltest", Title: "hash hosts", Template: "fix",
		Params:   map[string]string{"host": "h1"},
		Evidence: []string{"h1:7", "h1:8"},
		Reason:   "tier 1",
		Created:  t0,
		State:    "open"}
	id, err := st.InsertProposal(ctx, want)
	if err != nil || id == 0 {
		t.Fatalf("insert: %d %v", id, err)
	}
	got, err := st.Proposal(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	want.ID = id
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	open, err := st.OpenProposals(ctx)
	if err != nil || len(open) != 1 || open[0].ID != id {
		t.Fatalf("open %+v %v", open, err)
	}
	if err := st.CloseProposal(ctx, id, "accepted", "plan-1", "driver"); err != nil {
		t.Fatal(err)
	}
	got, err = st.Proposal(ctx, id)
	if err != nil || got.State != "accepted" || got.PlanID != "plan-1" || got.By != "driver" {
		t.Fatalf("closed %+v %v", got, err)
	}
	if open, _ := st.OpenProposals(ctx); len(open) != 0 {
		t.Fatalf("open after close: %+v", open)
	}
	if _, err := st.Proposal(ctx, id+1); !errors.Is(err, ErrNoProposal) {
		t.Fatalf("unknown proposal: %v", err)
	}
}

func TestProposalTimesUTC(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	local := time.Date(2027, 3, 1, 12, 0, 0, 0, time.FixedZone("x", 3600))
	id, err := st.InsertProposal(ctx, ProposalRow{Module: "m", Title: "t", Template: "x", Created: local, State: "open"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Proposal(ctx, id)
	if err != nil || got.Created.Location() != time.UTC || !got.Created.Equal(local) {
		t.Fatalf("%+v %v", got, err)
	}
}
