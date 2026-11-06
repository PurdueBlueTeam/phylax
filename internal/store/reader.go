package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"

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

// MaxModuleMigrations bounds one module's migration list.
const MaxModuleMigrations = 256

var (
	moduleNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	// a table name after CREATE/ALTER/DROP TABLE, or a write target after
	// INSERT INTO, REPLACE INTO, UPDATE or DELETE FROM.
	tableRefRe = regexp.MustCompile(`(?i)\b(?:CREATE\s+(?:TEMP\s+|TEMPORARY\s+)?(?:UNIQUE\s+)?TABLE|ALTER\s+TABLE|DROP\s+TABLE|INSERT\s+(?:OR\s+[A-Z]+\s+)?INTO|REPLACE\s+INTO|UPDATE\s+(?:OR\s+[A-Z]+\s+)?|DELETE\s+FROM)\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(['"` + "`" + `\[]?)([A-Za-z_][A-Za-z0-9_]*)(['"` + "`" + `\]]?)`)
)

// ErrForeignTable reports a module statement that names a table the module
// does not own.
var ErrForeignTable = errors.New("store: statement names a table outside the module's prefix")

// ModuleDB returns the module's table handle.
func (s *Store) ModuleDB(module string) ModuleDB {
	return moduleDB{module: module, s: s}
}

type moduleDB struct {
	module string
	s      *Store
}

// owns reports whether name is one of the module's tables.
func (d moduleDB) owns(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), d.module+"_")
}

// checkOwnership refuses a statement that creates, alters, drops or writes a
// table the module does not own. The prefix rule is a shortcut for a SQLite
// authorizer: a module that needs dynamic SQL upgrades it.
func (d moduleDB) checkOwnership(q string) error {
	if !moduleNameRe.MatchString(d.module) {
		return fmt.Errorf("store: bad module name %q", d.module)
	}
	for _, m := range tableRefRe.FindAllStringSubmatch(q, -1) {
		open, name, close := m[1], m[2], m[3]
		// A quoted name is not a table reference we can attribute: refuse it
		// rather than guess (no module needs one).
		if open != "" || close != "" {
			return fmt.Errorf("%w: quoted table name in module statement", ErrForeignTable)
		}
		if !d.owns(name) {
			return fmt.Errorf("%w: %s (module %s)", ErrForeignTable, name, d.module)
		}
	}
	return nil
}

// Migrate applies the module's migrations once, in order, in one transaction.
func (d moduleDB) Migrate(ctx context.Context, ms []string) error {
	if len(ms) > MaxModuleMigrations {
		return fmt.Errorf("store: %d module migrations > %d", len(ms), MaxModuleMigrations)
	}
	for _, m := range ms {
		if err := d.checkOwnership(m); err != nil {
			return err
		}
	}
	tx, err := d.s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	applied := 0
	err = tx.QueryRowContext(ctx, `SELECT applied FROM module_migrations WHERE module=?`, d.module).Scan(&applied)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		applied = 0
		if _, err := tx.ExecContext(ctx, `INSERT INTO module_migrations(module, applied) VALUES (?, 0)`, d.module); err != nil {
			return err
		}
	case err != nil:
		return err
	}
	if applied > len(ms) {
		return fmt.Errorf("store: module %s has %d migrations applied, %d offered", d.module, applied, len(ms))
	}
	for _, m := range ms[applied:] {
		if _, err := tx.ExecContext(ctx, m); err != nil {
			return fmt.Errorf("store: module %s migration: %w", d.module, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE module_migrations SET applied=? WHERE module=?`, len(ms), d.module); err != nil {
		return err
	}
	return tx.Commit()
}

// Exec runs a write against the module's own tables.
func (d moduleDB) Exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	if err := d.checkOwnership(q); err != nil {
		return nil, err
	}
	return d.s.w.ExecContext(ctx, q, args...)
}

// Query runs a read.
func (d moduleDB) Query(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return d.s.r.QueryContext(ctx, q, args...)
}
