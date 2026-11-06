package storetest

import (
	"context"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

func init() {
	event.Declare(event.Type{Kind: "ttest.seed", Schema: 1, Priority: event.PriorityNormal, Fields: struct {
		N int `json:"n"`
	}{}})
}

func TestNewSeedsReadableChain(t *testing.T) {
	t.Skip("unimplemented: W1 Task 8a")
	a, _ := event.New("ttest.seed", struct {
		N int `json:"n"`
	}{1})
	a.Agent = "h1"
	b := a
	b.Agent = "h1"
	c := a
	c.Agent = "db1"
	st := New(t, a, b, c)
	got, err := st.Events(context.Background(), store.Query{Agent: "h1"})
	if err != nil || len(got) != 2 || got[0].Seq != 1 || got[1].Seq != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	if e, err := st.Latest(context.Background(), "db1", "ttest.seed"); err != nil || e.Seq != 1 {
		t.Fatalf("%+v %v", e, err)
	}
}

func TestNewKeepsGivenTimes(t *testing.T) {
	t.Skip("unimplemented: W1 Task 8a")
	// an event with Time set keeps it; one without gets a strictly increasing default; Events returns them in that order
}
