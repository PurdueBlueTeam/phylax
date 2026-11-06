package conformance

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

func TestControllerCheck10CatchesNondeterminism(t *testing.T) {
	c := ControllerCase{Module: randomAnalyserModule(), Config: "enabled: true\n", Now: time.Unix(1e9, 0)}
	if errs := runControllerChecks(c); errs["analysers"] == nil {
		t.Fatal("nondeterministic analyser not detected")
	}
}

func TestControllerCheck8CatchesLooseConfig(t *testing.T) {
	// a Configurable module whose Start ignores Host.Config errors and reports ok
	c := ControllerCase{Module: ignoresConfigErrorModule(), Config: "enabled: true\n", Now: time.Unix(1e9, 0)}
	if errs := runControllerChecks(c); errs["config_decode"] == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestControllerCheck10CatchesUnreplayableTable(t *testing.T) {
	// a module whose writer also inserts a row from a UI handler without emitting an event (table ctltest_notes)
	c := ControllerCase{Module: sideWriterModule(), Config: "enabled: true\n", Now: time.Unix(1e9, 0)}
	if errs := runControllerChecks(c); errs["tables_replay"] == nil || !strings.Contains(errs["tables_replay"].Error(), "ctltest_notes") {
		t.Fatalf("table that cannot be rebuilt from events not detected: %v", errs["tables_replay"])
	}
}

func TestControllerCheck10PassesCommandEvents(t *testing.T) {
	// the same table written only from a command event kind ctltest.note (in Emits, passed in ControllerCase.Commands) rebuilds identically
	c := ControllerCase{Module: commandWriterModule(), Config: "enabled: true\n", Now: time.Unix(1e9, 0),
		Commands: []event.Event{noteEvent(t, "operator note one"), noteEvent(t, "operator note two")}}
	if errs := runControllerChecks(c); errs["tables_replay"] != nil {
		t.Fatalf("a table built from command events must replay: %v", errs["tables_replay"])
	}
}

func TestControllerChecksPass(t *testing.T) {
	Controller(t, ControllerCase{Module: goodControllerModule(), Config: "enabled: true\n", Now: time.Unix(1e9, 0)})
}

// ---- fixtures for the table replay check ----

// notePayload is the ctltest.note payload: an operator command event that a
// module's writer projects into its own table.
type notePayload struct {
	Note string `json:"note"`
}

func init() {
	event.Declare(event.Type{Kind: "ctltest.note", Schema: 1, Priority: event.PriorityNormal, Fields: notePayload{}})
}

func noteEvent(t *testing.T, note string) event.Event {
	t.Helper()
	e, err := event.New("ctltest.note", notePayload{Note: note})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// notesModule is a controller module whose one writer keeps ctltest_notes as a
// projection of its own ctltest.note events. side makes it also write one row
// per start from outside the event stream, the way a UI handler that forgot to
// emit a command event would; the row changes on every run, so a rebuild from
// events cannot reproduce it.
type notesModule struct {
	side   bool
	starts atomic.Int32
}

func (m *notesModule) Manifest() module.Manifest {
	return module.Manifest{Name: "ctltest", Sides: []module.Side{module.SideController}, Privilege: "none",
		Emits:  []event.Type{{Kind: "ctltest.note", Schema: 1}},
		Tables: []string{"ctltest_notes"}}
}
func (m *notesModule) Health() module.Health { return module.Health{State: module.StateOK} }

func (m *notesModule) Start(ctx context.Context, h module.Host) error {
	db, err := h.Tables()
	if err != nil {
		return err
	}
	if err := db.Migrate(ctx, []string{
		"CREATE TABLE IF NOT EXISTS ctltest_notes (id INTEGER PRIMARY KEY, note TEXT NOT NULL)",
	}); err != nil {
		return err
	}
	if m.side {
		note := fmt.Sprintf("written by a UI handler, run %d", m.starts.Add(1))
		if _, err := db.Exec(ctx, "INSERT INTO ctltest_notes(note) VALUES (?)", note); err != nil {
			return err
		}
	}
	// Rebuild from the committed events first (the persistence rule: a table is
	// a projection of the module's own events, command events included).
	evs, err := h.Query().Events(ctx, store.Query{Kind: "ctltest.note", Limit: store.MaxQueryLimit})
	if err != nil {
		return err
	}
	insert := func(e event.Event) error {
		note, _ := e.Fields["note"].(string)
		_, err := db.Exec(ctx, "INSERT INTO ctltest_notes(note) VALUES (?)", note)
		return err
	}
	for _, e := range evs {
		if err := insert(e); err != nil {
			return err
		}
	}
	ch, unsub := h.Subscribe([]string{"ctltest.note"}, 64)
	defer unsub()
	for {
		select {
		case e := <-ch:
			if err := insert(e); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func sideWriterModule() module.ControllerModule    { return &notesModule{side: true} }
func commandWriterModule() module.ControllerModule { return &notesModule{} }
