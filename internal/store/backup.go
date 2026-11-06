package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// BackupOptions control Backup.
type BackupOptions struct {
	// StateOnly drops event rows from the snapshot, keeping agents (with their
	// ack seq and chain hash), gaps and all other tables. This matches the
	// design's "state, not event data" snapshot. After a restore, resent
	// events at or below the recorded seq are verified and backfilled.
	StateOnly bool
}

// Backup writes a consistent snapshot of the live database to dest using
// VACUUM INTO (an online, transactionally consistent copy). dest must not
// exist; it is written to a temp name, synced and renamed into place.
// Encryption of the snapshot is the caller's job (age).
func (s *Store) Backup(ctx context.Context, dest string, opts BackupOptions) error {
	if _, err := os.Lstat(dest); err == nil {
		return fmt.Errorf("store: backup destination %s exists", dest)
	}
	tmp := dest + ".tmp"
	os.Remove(tmp)
	if _, err := s.w.ExecContext(ctx, `VACUUM INTO ?`, tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("store: backup: %w", err)
	}
	if opts.StateOnly {
		if err := stripEvents(ctx, tmp); err != nil {
			os.Remove(tmp)
			return err
		}
	}
	if err := syncFile(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(dest)
}

func stripEvents(ctx context.Context, path string) error {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(DELETE)")
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `DELETE FROM events`); err != nil {
		return fmt.Errorf("store: strip events: %w", err)
	}
	if _, err := db.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("store: vacuum snapshot: %w", err)
	}
	return nil
}

// Restore installs the snapshot at dbPath (replacing any database there,
// atomically), opens it and starts a new epoch. Every agent's current ack
// point is recorded as its restore point: a later resend must pass through
// that seq and hash (ErrRestoreMismatch otherwise).
func Restore(ctx context.Context, snapshot, dbPath, reason string) (*Store, error) {
	if reason == "" {
		reason = "restore"
	}
	// Validate the snapshot before touching dbPath.
	if err := checkSnapshot(ctx, snapshot); err != nil {
		return nil, err
	}
	tmp := dbPath + ".restore.tmp"
	if err := copyFile(snapshot, tmp); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	os.Remove(dbPath + "-wal")
	os.Remove(dbPath + "-shm")
	if err := os.Rename(tmp, dbPath); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	if err := syncDir(dbPath); err != nil {
		return nil, err
	}
	s, err := Open(ctx, dbPath)
	if err != nil {
		return nil, err
	}
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		s.Close()
		return nil, err
	}
	defer tx.Rollback()
	var ep uint64
	if err := tx.QueryRowContext(ctx, `SELECT CAST(value AS INTEGER) FROM meta WHERE key='epoch'`).Scan(&ep); err != nil {
		s.Close()
		return nil, err
	}
	ep++
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE meta SET value=? WHERE key='epoch'`, []any{fmt.Sprint(ep)}},
		{`INSERT INTO epochs(epoch, started, reason) VALUES (?,?,?)`, []any{ep, time.Now().UnixNano(), reason}},
		{`UPDATE agents SET restored_seq=last_seq, restored_hash=last_hash, epoch=?`, []any{ep}},
	} {
		if _, err := tx.ExecContext(ctx, q.sql, q.args...); err != nil {
			s.Close()
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func checkSnapshot(ctx context.Context, path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if err != nil {
		return err
	}
	defer db.Close()
	var res string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&res); err != nil {
		return fmt.Errorf("store: snapshot unreadable: %w", err)
	}
	if res != "ok" {
		return fmt.Errorf("store: snapshot corrupt: %s", res)
	}
	var v int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	if v == 0 {
		return errors.New("store: not a phylax snapshot")
	}
	if v > len(migrations) {
		return ErrNewerSchema
	}
	return nil
}

// RaiseEpoch sets the epoch to max(current, atLeast), appending an epochs row
// with reason when it rose. It returns the epoch in force.
func (s *Store) RaiseEpoch(ctx context.Context, atLeast uint64, reason string) (uint64, error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var cur uint64
	if err := tx.QueryRowContext(ctx, `SELECT CAST(value AS INTEGER) FROM meta WHERE key='epoch'`).Scan(&cur); err != nil {
		return 0, err
	}
	if atLeast <= cur {
		return cur, nil
	}
	if reason == "" {
		reason = "raise"
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE meta SET value=? WHERE key='epoch'`, []any{fmt.Sprint(atLeast)}},
		{`INSERT INTO epochs(epoch, started, reason) VALUES (?,?,?)`, []any{atLeast, time.Now().UnixNano(), reason}},
	} {
		if _, err := tx.ExecContext(ctx, q.sql, q.args...); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return atLeast, nil
}

// EpochRecord is one entry of the epoch history.
type EpochRecord struct {
	Epoch   uint64
	Started time.Time
	Reason  string
}

// Epochs lists the epoch history.
func (s *Store) Epochs(ctx context.Context) ([]EpochRecord, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT epoch, started, reason FROM epochs ORDER BY epoch`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EpochRecord
	for rows.Next() {
		var e EpochRecord
		var ns int64
		if err := rows.Scan(&e.Epoch, &ns, &e.Reason); err != nil {
			return nil, err
		}
		e.Started = time.Unix(0, ns).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
