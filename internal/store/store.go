// Package store is the controller's persistent state (SQLite): enrolled
// hosts and their pinned keys, one-time enrollment tokens, the event
// mirror used for chain verification and resend dedupe, and per-host ack
// watermarks. See docs/protocol.md.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, registered as "sqlite"
)

// Host is one enrolled (or pending) agent host.
type Host struct {
	Name          string    `json:"name"`
	Pin           string    `json:"pin"` // base64 sha256 of cert SPKI
	KeyB64        string    `json:"key"` // base64 ed25519 public key
	Roles         []string  `json:"roles"`
	EnrolledAt    time.Time `json:"enrolled_at"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	ChainSeq      uint64    `json:"chain_seq"`
	ChainHash     string    `json:"chain_hash"`
	Status        string    `json:"status"` // pending | enrolled | dark
}

// Event is one mirrored agent event.
type Event struct {
	Seq  uint64
	TS   string
	Type string
	Data []byte
	Hash string
}

// Store wraps the controller's SQLite database.
type Store struct {
	db  *sql.DB
	dir string
}

// Dir returns the state directory holding the database.
func (s *Store) Dir() string { return s.dir }

const schema = `
CREATE TABLE IF NOT EXISTS hosts (
	name           TEXT PRIMARY KEY,
	pin            TEXT NOT NULL,
	key_b64        TEXT NOT NULL,
	roles          TEXT NOT NULL,
	enrolled_at    TEXT,
	last_heartbeat TEXT,
	chain_seq      INTEGER NOT NULL DEFAULT 0,
	chain_hash     TEXT NOT NULL DEFAULT '',
	status         TEXT NOT NULL DEFAULT 'pending'
);
CREATE TABLE IF NOT EXISTS tokens (
	token      TEXT PRIMARY KEY,
	host       TEXT NOT NULL,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	used       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS events (
	host TEXT NOT NULL,
	seq  INTEGER NOT NULL,
	ts   TEXT NOT NULL,
	type TEXT NOT NULL,
	data BLOB NOT NULL,
	hash TEXT NOT NULL,
	PRIMARY KEY (host, seq)
);
CREATE TABLE IF NOT EXISTS acks (
	host TEXT PRIMARY KEY,
	seq  INTEGER NOT NULL
);
`

// Open opens (or creates) the controller database under dir.
func Open(dir string) (*Store, error) {
	path := filepath.Join(dir, "phylax.db")
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, dir: dir}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// EnrollHost records a host's pinned identity. Re-enrollment (new key for
// an existing name) must go through AlertAndReenroll, not this.
func (s *Store) EnrollHost(name, pin, keyB64 string, roles []string) error {
	rolesJSON, err := json.Marshal(roles)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.db.Exec(`INSERT INTO hosts (name, pin, key_b64, roles, enrolled_at, status)
		VALUES (?, ?, ?, ?, ?, 'enrolled')`, name, pin, keyB64, string(rolesJSON), now)
	if err != nil {
		return fmt.Errorf("store: enroll %s: %w", name, err)
	}
	return nil
}

// GetHost returns one host by name.
func (s *Store) GetHost(name string) (Host, error) {
	var h Host
	var rolesJSON, enrolledAt, lastHB string
	err := s.db.QueryRow(`SELECT pin, key_b64, roles, COALESCE(enrolled_at, ''),
		COALESCE(last_heartbeat, ''),
		chain_seq, chain_hash, status FROM hosts WHERE name = ?`, name).
		Scan(&h.Pin, &h.KeyB64, &rolesJSON, &enrolledAt, &lastHB,
			&h.ChainSeq, &h.ChainHash, &h.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return h, sql.ErrNoRows
	}
	if err != nil {
		return h, err
	}
	h.Name = name
	_ = json.Unmarshal([]byte(rolesJSON), &h.Roles)
	if enrolledAt != "" {
		h.EnrolledAt, _ = time.Parse(time.RFC3339Nano, enrolledAt)
	}
	if lastHB != "" {
		h.LastHeartbeat, _ = time.Parse(time.RFC3339Nano, lastHB)
	}
	return h, nil
}

// ListHosts returns all hosts.
func (s *Store) ListHosts() ([]Host, error) {
	rows, err := s.db.Query(`SELECT name, pin, key_b64, roles, COALESCE(enrolled_at, ''),
		COALESCE(last_heartbeat, ''), chain_seq, chain_hash, status FROM hosts ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		var h Host
		var rolesJSON, enrolledAt, lastHB string
		if err := rows.Scan(&h.Name, &h.Pin, &h.KeyB64, &rolesJSON, &enrolledAt,
			&lastHB, &h.ChainSeq, &h.ChainHash, &h.Status); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(rolesJSON), &h.Roles)
		if enrolledAt != "" {
			h.EnrolledAt, _ = time.Parse(time.RFC3339Nano, enrolledAt)
		}
		if lastHB != "" {
			h.LastHeartbeat, _ = time.Parse(time.RFC3339Nano, lastHB)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// TouchHeartbeat records a heartbeat and the spool tip the agent reports.
// The chain hash is recorded only when it advances chain_seq, so a
// re-enrolled or restored agent cannot overwrite history it shouldn't hold.
func (s *Store) TouchHeartbeat(name string, at time.Time, spoolSeq uint64, spoolHash string) error {
	res, err := s.db.Exec(`UPDATE hosts SET last_heartbeat = ? WHERE name = ?`,
		at.UTC().Format(time.RFC3339Nano), name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	if spoolSeq > 0 && spoolHash != "" {
		_, _ = s.db.Exec(`UPDATE hosts SET chain_seq = ?, chain_hash = ?
			WHERE name = ? AND chain_seq < ?`, spoolSeq, spoolHash, name, spoolSeq)
	}
	return nil
}

// RecordEvent stores one mirrored event; duplicates (same host+seq) are
// ignored. It returns true when the event was new.
func (s *Store) RecordEvent(host string, ev Event) (bool, error) {
	res, err := s.db.Exec(`INSERT OR IGNORE INTO events (host, seq, ts, type, data, hash)
		VALUES (?, ?, ?, ?, ?, ?)`, host, ev.Seq, ev.TS, ev.Type, ev.Data, ev.Hash)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// EventCount returns how many events are mirrored for a host.
func (s *Store) EventCount(host string) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE host = ?`, host).Scan(&n)
	return n, err
}

// QueryEvents returns recent events of one type for a host, newest first.
func (s *Store) QueryEvents(host, typ string, limit int) ([]Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT seq, ts, type, data, hash FROM events
		WHERE host = ? AND type = ? ORDER BY seq DESC LIMIT ?`, host, typ, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var ev Event
		if err := rows.Scan(&ev.Seq, &ev.TS, &ev.Type, &ev.Data, &ev.Hash); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}
// ChainAt returns the recorded chain hash at a host's seq, if mirrored.
func (s *Store) ChainAt(host string, seq uint64) (string, bool) {
	var h string
	err := s.db.QueryRow(`SELECT hash FROM events WHERE host = ? AND seq = ?`, host, seq).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false
	}
	if err != nil {
		return "", false
	}
	return h, true
}

// MaxEventSeq returns the highest mirrored seq for a host (0 if none).
func (s *Store) MaxEventSeq(host string) (uint64, error) {
	var n uint64
	err := s.db.QueryRow(`SELECT COALESCE(MAX(seq), 0) FROM events WHERE host = ?`, host).Scan(&n)
	return n, err
}

// Acked returns the highest contiguous acknowledged seq for a host.
func (s *Store) Acked(host string) (uint64, error) {
	var n uint64
	err := s.db.QueryRow(`SELECT seq FROM acks WHERE host = ?`, host).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return n, nil
}

// SetAcked advances a host's ack watermark (monotonic).
func (s *Store) SetAcked(host string, seq uint64) error {
	_, err := s.db.Exec(`INSERT INTO acks (host, seq) VALUES (?, ?)
		ON CONFLICT(host) DO UPDATE SET seq = MAX(seq, excluded.seq)`, host, seq)
	return err
}

// IssueToken creates a one-time enrollment token for a host.
func (s *Store) IssueToken(host string, ttl time.Duration) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := "phylax_" + hex.EncodeToString(b)
	now := time.Now().UTC()
	_, err := s.db.Exec(`INSERT INTO tokens (token, host, created_at, expires_at)
		VALUES (?, ?, ?, ?)`, tok, host,
		now.Format(time.RFC3339Nano), now.Add(ttl).Format(time.RFC3339Nano))
	if err != nil {
		return "", err
	}
	return tok, nil
}

// ConsumeToken validates and burns a token, returning the host it was
// issued for.
func (s *Store) ConsumeToken(token string) (string, error) {
	host, expires, used, err := func() (string, time.Time, int, error) {
		var h string
		var exp string
		var u int
		err := s.db.QueryRow(`SELECT host, expires_at, used FROM tokens WHERE token = ?`, token).
			Scan(&h, &exp, &u)
		if err != nil {
			return "", time.Time{}, 0, err
		}
		e, err := time.Parse(time.RFC3339Nano, exp)
		return h, e, u, err
	}()
	if errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("store: unknown token")
	}
	if err != nil {
		return "", err
	}
	if used != 0 {
		return "", errors.New("store: token already used")
	}
	if time.Now().UTC().After(expires) {
		return "", errors.New("store: token expired")
	}
	if _, err := s.db.Exec(`UPDATE tokens SET used = 1 WHERE token = ? AND used = 0`, token); err != nil {
		return "", err
	}
	return host, nil
}

// TokenInfo returns a token's host, expiry and use state without burning
// it (bootstrap downloads validate repeatedly; enrollment consumes once).
func (s *Store) TokenInfo(token string) (host string, expires time.Time, used int, err error) {
	var exp string
	err = s.db.QueryRow(`SELECT host, expires_at, used FROM tokens WHERE token = ?`, token).
		Scan(&host, &exp, &used)
	if err != nil {
		return "", time.Time{}, 0, err
	}
	expires, err = time.Parse(time.RFC3339Nano, exp)
	return host, expires, used, err
}

// MarkDark flips a host's status to dark (or back to enrolled when it
// returns).
func (s *Store) MarkDark(name string, dark bool) error {
	status := "enrolled"
	if dark {
		status = "dark"
	}
	_, err := s.db.Exec(`UPDATE hosts SET status = ? WHERE name = ?`, status, name)
	return err
}

// HostsDarkAfter returns all enrolled hosts whose last heartbeat is older
// than cutoff (a host never seen is dark from the start).
func (s *Store) HostsDarkAfter(cutoff time.Time) ([]string, error) {
	rows, err := s.db.Query(`SELECT name FROM hosts
		WHERE status = 'enrolled' AND (last_heartbeat IS NULL OR last_heartbeat = '' OR last_heartbeat < ?)`,
		cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

