package store

import (
	"context"
	"database/sql"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// Reader is the read-only query interface modules and analysers use.
type Reader interface {
	Events(ctx context.Context, q Query) ([]event.Event, error)
	Event(ctx context.Context, agent string, seq uint64) (event.Event, error)
	Latest(ctx context.Context, agent, kind string) (event.Event, error)
}

var _ Reader = (*Store)(nil)

// ModuleDB is a module's own set of tables.
type ModuleDB interface {
	Migrate(ctx context.Context, migrations []string) error // ordered; applied once; may only create or alter tables named <module>_*
	Exec(ctx context.Context, query string, args ...any) (sql.Result, error)
	Query(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// ModuleDB returns the module's table handle.
func (s *Store) ModuleDB(module string) ModuleDB { panic("unimplemented: W1 Task 8") }
