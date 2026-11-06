package store

import (
	"context"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func TestStoreRoundTripsSchemaAndTag(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	enroll(t, st, "h1")
	e := event.Event{Agent: "h1", Time: time.Unix(5, 0).UTC(), Kind: "k", Schema: 1, Tag: "plan:p9", Priority: event.PriorityHigh}
	if err := e.Seal(0, event.GenesisHash); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Ingest(ctx, "h1", []event.Event{e}); err != nil {
		t.Fatal(err)
	}
	got, err := st.Events(ctx, Query{Agent: "h1"})
	if err != nil || len(got) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	if got[0].Schema != 1 || got[0].Tag != "plan:p9" || got[0].Verify(0, event.GenesisHash) != nil {
		t.Fatalf("%+v", got[0])
	}
}
