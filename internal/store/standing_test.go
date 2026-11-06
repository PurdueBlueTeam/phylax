package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestStandingApprovalsRoundTrip(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	want := StandingApproval{ID: "s1", Module: "ctltest", Template: "dump", Targets: "linux && server",
		Actions:  []string{"file.hash", "file.write"},
		Expires:  t0.Add(time.Hour),
		Approver: "Captain",
		Created:  "admin"}
	if err := st.InsertStanding(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := st.Standing(ctx, want.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	list, err := st.ListStanding(ctx)
	if err != nil || len(list) != 1 || !reflect.DeepEqual(list[0], want) {
		t.Fatalf("list %+v %v", list, err)
	}
	if err := st.SetStandingRevoked(ctx, want.ID); err != nil {
		t.Fatal(err)
	}
	got, err = st.Standing(ctx, want.ID)
	if err != nil || !got.Revoked {
		t.Fatalf("revoked %+v %v", got, err)
	}
	if err := st.SetStandingRevoked(ctx, "nope"); !errors.Is(err, ErrNoStanding) {
		t.Fatalf("unknown standing approval: %v", err)
	}
	if _, err := st.Standing(ctx, "nope"); !errors.Is(err, ErrNoStanding) {
		t.Fatalf("unknown standing approval: %v", err)
	}
}
