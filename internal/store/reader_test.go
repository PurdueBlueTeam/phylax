package store

import (
	"context"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func TestQueryFieldEquality(t *testing.T) {
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
	st, _ := open(t)
	if _, err := st.Events(context.Background(), Query{Fields: map[string]string{"a') OR 1=1 --": "x"}}); err == nil {
		t.Fatal("bad key accepted")
	}
}

func TestModuleDBMigrateOwnPrefix(t *testing.T) {
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

func TestModuleDBUpsertAllowed(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	db := st.ModuleDB("deps")
	if err := db.Migrate(ctx, []string{"CREATE TABLE deps_edge(a TEXT PRIMARY KEY, n INTEGER)"}); err != nil {
		t.Fatal(err)
	}
	up := `INSERT INTO deps_edge(a, n) VALUES (?, ?) ON CONFLICT(a) DO UPDATE SET n=n+1`
	for i := 0; i < 2; i++ {
		if _, err := db.Exec(ctx, up, "x", 1); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
	}
	var n int
	rows, err := db.Query(ctx, `SELECT n FROM deps_edge WHERE a=?`, "x")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("no row")
	}
	if err := rows.Scan(&n); err != nil || n != 2 {
		t.Fatalf("n %d %v", n, err)
	}
}

func TestModuleDBRejectsBypasses(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	db := st.ModuleDB("deps")
	if err := db.Migrate(ctx, []string{"CREATE TABLE deps_edge(a TEXT PRIMARY KEY)"}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"UPDATE /**/ events SET envelope='x'",
		"UPDATE events -- comment\nSET envelope='x'",
		"UPDATE events /* comment */ SET envelope='x'",
		"ATTACH DATABASE 'other.db' AS other",
		"DETACH DATABASE other",
		"PRAGMA writable_schema=ON",
		"CREATE TRIGGER deps_t AFTER INSERT ON deps_edge BEGIN DELETE FROM events; END",
		"CREATE VIEW deps_v AS SELECT * FROM events",
		"CREATE INDEX deps_i ON events(seq)",
		"CREATE UNIQUE INDEX IF NOT EXISTS deps_i ON events(seq)",
		`CREATE INDEX deps_i ON "events"(seq)`,
	} {
		t.Run(q, func(t *testing.T) {
			if _, err := db.Exec(ctx, q); err == nil {
				t.Fatalf("Exec accepted bypass %q", q)
			}
			if err := db.Migrate(ctx, []string{q}); err == nil {
				t.Fatalf("Migrate accepted bypass %q", q)
			}
		})
	}
	// An index on the module's own table is still allowed.
	if _, err := db.Exec(ctx, "CREATE INDEX IF NOT EXISTS deps_edge_a ON deps_edge(a)"); err != nil {
		t.Fatalf("index on the module's own table refused: %v", err)
	}
}

func TestModuleDBNamedModuleRefused(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	db := st.ModuleDB("module")
	if _, err := db.Exec(ctx, "CREATE TABLE module_x(a TEXT)"); err == nil {
		t.Fatal(`module named "module" accepted`)
	}
	if err := db.Migrate(ctx, nil); err == nil {
		t.Fatal(`empty migration for module named "module" accepted`)
	}
}
