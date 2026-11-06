// Package store is the controller's event store: one SQLite database (WAL,
// pure Go) holding agents, their hash-chained events, and the tables later
// milestones fill in (design: "Controller" -> Storage, Data model, Backing up
// the controller; "Controller recovery"; "Reliability").
//
// Trust property: once an event is acknowledged it cannot be rewritten. A
// resent event must match the stored hash exactly, and the chain is verified
// per agent on every ingest.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver
)

// Bounds.
const (
	MaxBatch        = 1000  // events per Ingest call
	DefaultQueryMax = 1000  // default Query limit
	MaxQueryLimit   = 10000 // hard cap on Query limit
)

var (
	ErrClosed       = errors.New("store: closed")
	ErrUnknownAgent = errors.New("store: unknown agent")
	ErrKeyMismatch  = errors.New("store: agent already enrolled with a different key")
	ErrBatchTooBig  = errors.New("store: batch too large")
	ErrNewerSchema  = errors.New("store: database schema is newer than this binary")
)

// Store is safe for concurrent use.
type Store struct {
	path  string
	w     *sql.DB // single writer connection
	r     *sql.DB // read pool
	hook  atomic.Pointer[IngestHook]
	quota atomic.Pointer[Quota]
}

func fileSize(p string) int64 {
	fi, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// Open opens (creating if needed) the database at path and applies migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	s := &Store{path: path}
	var err error
	s.w, err = openDB(path, false)
	if err != nil {
		return nil, err
	}
	s.w.SetMaxOpenConns(1)
	if err := s.migrate(ctx); err != nil {
		s.w.Close()
		return nil, err
	}
	s.r, err = openDB(path, true)
	if err != nil {
		s.w.Close()
		return nil, err
	}
	s.r.SetMaxOpenConns(8)
	return s, nil
}

func openDB(path string, readOnly bool) (*sql.DB, error) {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(NORMAL)")
	if readOnly {
		q.Add("_pragma", "query_only(1)")
	} else {
		q.Add("_pragma", "journal_mode(WAL)")
		q.Set("_txlock", "immediate")
	}
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: path}).EscapedPath()+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	return db, nil
}

func (s *Store) migrate(ctx context.Context) error {
	var v int
	if err := s.w.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}
	if v > len(migrations) {
		return fmt.Errorf("%w: %d > %d", ErrNewerSchema, v, len(migrations))
	}
	for i := v; i < len(migrations); i++ {
		tx, err := s.w.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: migration %d version: %w", i+1, err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// SchemaVersion returns the applied migration count.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := s.r.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v)
	return v, err
}

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

// Close checkpoints the WAL and closes the database.
func (s *Store) Close() error {
	if s.w == nil {
		return nil
	}
	_, _ = s.w.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	e1 := s.r.Close()
	e2 := s.w.Close()
	s.w, s.r = nil, nil
	return errors.Join(e1, e2)
}

// Epoch returns the current controller epoch.
func (s *Store) Epoch(ctx context.Context) (uint64, error) {
	var e uint64
	err := s.r.QueryRowContext(ctx, `SELECT CAST(value AS INTEGER) FROM meta WHERE key='epoch'`).Scan(&e)
	return e, err
}

// Agent is an enrolled agent's row.
type Agent struct {
	ID           string
	PubKey       []byte
	EnrolledAt   time.Time
	LastSeq      uint64 // ack point
	LastHash     string
	Epoch        uint64
	RestoredSeq  uint64 // head recorded at the last restore (0 if none)
	RestoredHash string
}

// EnrollAgent registers an agent's identity key. Re-enrolling with the same
// key is a no-op; a different key is ErrKeyMismatch (use ReplaceAgentKey for
// a deliberate re-enrollment).
func (s *Store) EnrollAgent(ctx context.Context, id string, pubkey []byte) error {
	if id == "" || len(pubkey) == 0 {
		return errors.New("store: enroll needs an id and a key")
	}
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var have []byte
	err = tx.QueryRowContext(ctx, `SELECT pubkey FROM agents WHERE id=?`, id).Scan(&have)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		var ep uint64
		if err := tx.QueryRowContext(ctx, `SELECT CAST(value AS INTEGER) FROM meta WHERE key='epoch'`).Scan(&ep); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO agents(id, pubkey, enrolled_at, epoch) VALUES (?,?,?,?)`,
			id, pubkey, time.Now().UnixNano(), ep); err != nil {
			return err
		}
	case err != nil:
		return err
	case string(have) != string(pubkey):
		return ErrKeyMismatch
	}
	return tx.Commit()
}

// ReplaceAgentKey swaps an agent's key (operator-approved re-enrollment). The
// chain state is kept.
func (s *Store) ReplaceAgentKey(ctx context.Context, id string, pubkey []byte) error {
	res, err := s.w.ExecContext(ctx, `UPDATE agents SET pubkey=? WHERE id=?`, pubkey, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUnknownAgent
	}
	return nil
}

const agentCols = `id, pubkey, enrolled_at, last_seq, last_hash, epoch, restored_seq, restored_hash`

type scanner interface{ Scan(...any) error }

func scanAgent(r scanner) (Agent, error) {
	var a Agent
	var ns int64
	err := r.Scan(&a.ID, &a.PubKey, &ns, &a.LastSeq, &a.LastHash, &a.Epoch, &a.RestoredSeq, &a.RestoredHash)
	a.EnrolledAt = time.Unix(0, ns).UTC()
	return a, err
}

// Agent returns one agent.
func (s *Store) Agent(ctx context.Context, id string) (Agent, error) {
	a, err := scanAgent(s.r.QueryRowContext(ctx, `SELECT `+agentCols+` FROM agents WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Agent{}, ErrUnknownAgent
	}
	return a, err
}

// Agents lists all agents ordered by id.
func (s *Store) Agents(ctx context.Context) ([]Agent, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+agentCols+` FROM agents ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
