package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

type seed struct {
	N int `json:"n"`
}

func init() {
	event.Declare(event.Type{Kind: "ttest.seed", Schema: 1, Priority: event.PriorityNormal, Fields: seed{}})
}

func TestNewSeedsReadableChain(t *testing.T) {
	a, _ := event.New("ttest.seed", seed{1})
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
	ctx := context.Background()
	fixed := defaultTime.Add(10 * time.Second)
	a, _ := event.New("ttest.seed", seed{1})
	a.Agent = "h1"
	b, _ := event.New("ttest.seed", seed{2})
	b.Agent = "h1"
	c, _ := event.New("ttest.seed", seed{3})
	c.Agent, c.Time = "h1", fixed
	st := New(t, a, b, c)
	got, err := st.Events(ctx, store.Query{Agent: "h1"})
	if err != nil || len(got) != 3 {
		t.Fatalf("%+v %v", got, err)
	}
	want := []time.Time{defaultTime, defaultTime.Add(time.Second), fixed}
	for i, w := range want {
		if !got[i].Time.Equal(w) {
			t.Errorf("seq %d: time %v, want %v", got[i].Seq, got[i].Time, w)
		}
		if i > 0 && !got[i-1].Time.Before(got[i].Time) {
			t.Errorf("seq %d: %v not before %v", got[i].Seq, got[i-1].Time, got[i].Time)
		}
	}
}
