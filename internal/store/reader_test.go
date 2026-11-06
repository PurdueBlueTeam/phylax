package store

import (
	"context"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func TestQueryFieldEquality(t *testing.T) {
	t.Skip("unimplemented: W1 Task 8")
	st, _ := open(t)
	ctx := context.Background()
	enroll(t, st, "h1")
	var evs []event.Event
	for i, f := range []map[string]any{{"host": "a", "n": 5}, {"host": "b", "n": 6}} {
		e := event.Event{Agent: "h1", Time: time.Unix(int64(i), 0).UTC(), Kind: "k", Priority: event.PriorityNormal, Fields: f}
		if err := e.Seal(uint64(i), func() string {
			if i == 0 {
				return event.GenesisHash
			}
			return evs[i-1].Hash
		}()); err != nil {
			t.Fatal(err)
		}
		evs = append(evs, e)
	}
	if _, err := st.Ingest(ctx, "h1", evs); err != nil {
		t.Fatal(err)
	}
	got, err := st.Events(ctx, Query{Kind: "k", Fields: map[string]string{"host": "a"}})
	if err != nil || len(got) != 1 || got[0].Fields["host"] != "a" {
		t.Fatalf("%+v %v", got, err)
	}
	got, err = st.Events(ctx, Query{Kind: "k", Fields: map[string]string{"n": "6"}})
	if err != nil || len(got) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestQueryFieldKeyValidated(t *testing.T) {
	t.Skip("unimplemented: W1 Task 8")
	st, _ := open(t)
	if _, err := st.Events(context.Background(), Query{Fields: map[string]string{"a') OR 1=1 --": "x"}}); err == nil {
		t.Fatal("bad key accepted")
	}
}

func TestModuleDBMigrateOwnPrefix(t *testing.T) {
	t.Skip("unimplemented: W1 Task 8")
	st, _ := open(t)
	ctx := context.Background()
	db := st.ModuleDB("deps")
	if err := db.Migrate(ctx, []string{"CREATE TABLE deps_edge(a TEXT)"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, []string{"CREATE TABLE deps_edge(a TEXT)"}); err != nil {
		t.Fatalf("second run must be a no-op: %v", err)
	}
	if err := st.ModuleDB("deps").Migrate(ctx, []string{"CREATE TABLE deps_edge(a TEXT)", "CREATE TABLE edge(a TEXT)"}); err == nil {
		t.Fatal("foreign table name accepted")
	}
}

func TestModuleDBExecOwnTables(t *testing.T) {
	t.Skip("unimplemented: W1 Task 8")
	st, _ := open(t)
	ctx := context.Background()
	db := st.ModuleDB("deps")
	_ = db.Migrate(ctx, []string{"CREATE TABLE deps_edge(a TEXT)"})
	if _, err := db.Exec(ctx, "INSERT INTO deps_edge(a) VALUES (?)", "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, "DELETE FROM events"); err == nil {
		t.Fatal("write to a core table accepted")
	}
	rows, err := db.Query(ctx, "SELECT a FROM deps_edge")
	if err != nil {
		t.Fatal(err)
	}
	rows.Close()
}
