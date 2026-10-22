package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// IngestHook runs inside the ingest transaction with the events that were
// newly stored by that transaction (appended or backfilled; not duplicates).
// Whatever it writes through tx commits or rolls back together with the
// events, so derived rows (the alert queue, check results) can never be lost
// to a crash between "events stored" and "derived rows written". Returning an
// error rolls the whole batch back; the agent resends it. A hook must skip
// events it cannot use instead of failing on them, or one bad event would
// block the agent forever.
type IngestHook func(ctx context.Context, tx *IngestTx, evs []event.Event) error

// SetIngestHook installs the hook (nil removes it). Call before ingesting.
func (s *Store) SetIngestHook(h IngestHook) {
	if h == nil {
		s.hook.Store(nil)
		return
	}
	s.hook.Store(&h)
}

// IngestTx is the slice of the ingest transaction a hook may use.
type IngestTx struct {
	ctx context.Context
	tx  *sql.Tx
}

// FindEventAt returns the stored event of the agent and kind with exactly
// this timestamp (the lowest seq when several), including events written
// earlier in the same transaction.
func (t *IngestTx) FindEventAt(agent, kind string, at time.Time) (seq uint64, ok bool, err error) {
	var n int64
	err = t.tx.QueryRowContext(t.ctx, `SELECT seq FROM events WHERE agent=? AND kind=? AND time_ns=? ORDER BY seq LIMIT 1`,
		agent, kind, at.UnixNano()).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return uint64(n), err == nil, err
}

// InsertAlertOnce adds an alert unless one with the same source event
// (agent, seq) and rule is already queued. It reports whether a row was added.
func (t *IngestTx) InsertAlertOnce(a AlertRow) (inserted bool, err error) {
	return insertAlertOnce(t.ctx, t.tx, a)
}

// RecordCheck stores one check result (see Store.RecordCheck).
func (t *IngestTx) RecordCheck(c CheckResult) error { return recordCheck(t.ctx, t.tx, c) }

type execer interface {
	ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error)
}

func insertAlertOnce(ctx context.Context, x execer, a AlertRow) (bool, error) {
	if a.State == "" {
		a.State = "open"
	}
	if a.Keys == "" {
		a.Keys = "{}"
	}
	var seq any
	if a.Seq != 0 {
		seq = int64(a.Seq)
	}
	res, err := x.ExecContext(ctx, `INSERT INTO alerts(rule, host, severity, state, time_ns, keys, agent, seq)
SELECT ?,?,?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM alerts WHERE agent=? AND seq=? AND rule=?)`,
		a.Rule, a.Host, a.Severity, a.State, a.Time.UnixNano(), a.Keys, nullStr(a.Agent), seq, a.Agent, seq, a.Rule)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// InsertAlertOnce is the idempotent form of InsertAlert for alerts derived
// from a stored event: a second call for the same (agent, seq, rule) is a
// no-op.
func (s *Store) InsertAlertOnce(ctx context.Context, a AlertRow) (bool, error) {
	return insertAlertOnce(ctx, s.w, a)
}

// UnqueuedEvents returns stored events of a kind that no alert row refers to
// (by agent and seq), oldest first, up to limit. The controller replays them
// on start so a crash can never leave a stored detect.alert without a queue
// row.
func (s *Store) UnqueuedEvents(ctx context.Context, kind string, limit int) ([]event.Event, error) {
	if limit <= 0 || limit > MaxQueryLimit {
		limit = DefaultQueryMax
	}
	return s.collect(ctx, `SELECT `+eventCols+` FROM events e WHERE e.kind=? AND NOT EXISTS
(SELECT 1 FROM alerts a WHERE a.agent=e.agent AND a.seq=e.seq) ORDER BY e.time_ns, e.agent, e.seq LIMIT ?`, kind, limit)
}

// ---------------------------------------------------------------- check results

// CheckResult is one probe result. Detail is a JSON document the producer
// owns (class, error text, timing, mode, item); it never holds credentials.
type CheckResult struct {
	CheckID string
	Service string
	Kind    string // probe type: http, ssh, ...
	Vantage string // "controller" or the agent that ran it
	Time    time.Time
	OK      bool
	Detail  string
}

const checkKeep = 2000 // results kept per check

func recordCheck(ctx context.Context, x interface {
	execer
}, c CheckResult) error {
	if c.Detail == "" {
		c.Detail = "{}"
	}
	if _, err := x.ExecContext(ctx, `INSERT INTO checks(id, service, kind, updated_ns) VALUES (?,?,?,?)
ON CONFLICT(id) DO UPDATE SET service=excluded.service, kind=excluded.kind, updated_ns=excluded.updated_ns`,
		c.CheckID, c.Service, c.Kind, c.Time.UnixNano()); err != nil {
		return err
	}
	ok := 0
	if c.OK {
		ok = 1
	}
	if _, err := x.ExecContext(ctx, `INSERT OR IGNORE INTO check_results(check_id, time_ns, vantage, ok, detail) VALUES (?,?,?,?,?)`,
		c.CheckID, c.Time.UnixNano(), c.Vantage, ok, c.Detail); err != nil {
		return err
	}
	_, err := x.ExecContext(ctx, `DELETE FROM check_results WHERE check_id=? AND time_ns < COALESCE((SELECT time_ns FROM check_results WHERE check_id=? ORDER BY time_ns DESC LIMIT 1 OFFSET ?), 0)`,
		c.CheckID, c.CheckID, checkKeep)
	return err
}

// RecordCheck stores one result, creating the check row on first sight and
// keeping the newest 2000 results per check.
func (s *Store) RecordCheck(ctx context.Context, c CheckResult) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := recordCheck(ctx, tx, c); err != nil {
		return err
	}
	return tx.Commit()
}

// CheckRow is a known check.
type CheckRow struct {
	ID, Service, Kind string
	Updated           time.Time
}

// Checks lists known checks by service then id.
func (s *Store) Checks(ctx context.Context) ([]CheckRow, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, service, kind, updated_ns FROM checks ORDER BY service, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CheckRow
	for rows.Next() {
		var c CheckRow
		var ns int64
		if err := rows.Scan(&c.ID, &c.Service, &c.Kind, &ns); err != nil {
			return nil, err
		}
		c.Updated = time.Unix(0, ns).UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}

// CheckHistory returns a check's results, newest first (limit <= 0: 100).
func (s *Store) CheckHistory(ctx context.Context, id string, limit int) ([]CheckResult, error) {
	if limit <= 0 || limit > checkKeep {
		limit = 100
	}
	rows, err := s.r.QueryContext(ctx, `SELECT r.check_id, c.service, c.kind, r.vantage, r.time_ns, r.ok, r.detail
FROM check_results r JOIN checks c ON c.id=r.check_id WHERE r.check_id=? ORDER BY r.time_ns DESC LIMIT ?`, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CheckResult
	for rows.Next() {
		var r CheckResult
		var ns int64
		var ok int
		if err := rows.Scan(&r.CheckID, &r.Service, &r.Kind, &r.Vantage, &ns, &ok, &r.Detail); err != nil {
			return nil, err
		}
		r.Time, r.OK = time.Unix(0, ns).UTC(), ok != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- report drafts

// ErrNoDraft is returned for an unknown draft id.
var ErrNoDraft = errors.New("store: no such draft")

// Draft is a stored report or inject draft; Spec is the controller's JSON.
type Draft struct {
	ID        int64
	Kind      string
	Number    int
	Team      int
	Title     string
	Spec      json.RawMessage
	CreatedBy string
	Created   time.Time
	Updated   time.Time
}

const draftCols = `id, kind, number, team, title, spec, created_by, created_ns, updated_ns`

func scanDraft(r scanner) (Draft, error) {
	var d Draft
	var spec string
	var c, u int64
	if err := r.Scan(&d.ID, &d.Kind, &d.Number, &d.Team, &d.Title, &spec, &d.CreatedBy, &c, &u); err != nil {
		return d, err
	}
	d.Spec = json.RawMessage(spec)
	d.Created, d.Updated = time.Unix(0, c).UTC(), time.Unix(0, u).UTC()
	return d, nil
}

// InsertDraft stores a new draft and returns its id.
func (s *Store) InsertDraft(ctx context.Context, d Draft) (int64, error) {
	res, err := s.w.ExecContext(ctx, `INSERT INTO report_drafts(kind, number, team, title, spec, created_by, created_ns, updated_ns) VALUES (?,?,?,?,?,?,?,?)`,
		d.Kind, d.Number, d.Team, d.Title, string(d.Spec), d.CreatedBy, d.Created.UnixNano(), d.Created.UnixNano())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateDraft replaces a draft's number, title and spec.
func (s *Store) UpdateDraft(ctx context.Context, d Draft) error {
	res, err := s.w.ExecContext(ctx, `UPDATE report_drafts SET number=?, title=?, spec=?, updated_ns=? WHERE id=?`,
		d.Number, d.Title, string(d.Spec), d.Updated.UnixNano(), d.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoDraft
	}
	return nil
}

// Draft returns one draft.
func (s *Store) Draft(ctx context.Context, id int64) (Draft, error) {
	d, err := scanDraft(s.r.QueryRowContext(ctx, `SELECT `+draftCols+` FROM report_drafts WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNoDraft
	}
	return d, err
}

// Drafts lists drafts of a kind ("" = all), newest first.
func (s *Store) Drafts(ctx context.Context, kind string) ([]Draft, error) {
	q, args := `SELECT `+draftCols+` FROM report_drafts`, []any{}
	if kind != "" {
		q += ` WHERE kind=?`
		args = append(args, kind)
	}
	rows, err := s.r.QueryContext(ctx, q+` ORDER BY id DESC LIMIT 500`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Draft
	for rows.Next() {
		d, err := scanDraft(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// MaxDraftNumber is the highest number used by drafts of a kind (0: none).
func (s *Store) MaxDraftNumber(ctx context.Context, kind string) (int, error) {
	var n sql.NullInt64
	err := s.r.QueryRowContext(ctx, `SELECT MAX(number) FROM report_drafts WHERE kind=?`, kind).Scan(&n)
	return int(n.Int64), err
}

// ---------------------------------------------------------------- audit query

// AuditFilter selects audit rows. Zero fields match everything; Before is a
// cursor (rows with id < Before), 0 for the newest page.
type AuditFilter struct {
	Actor, Action string
	Before        int64
	Limit         int // default 50, max 500
}

// AuditPage returns one page of audit rows, newest first, and the cursor of
// the next (older) page, 0 when there is none.
func (s *Store) AuditPage(ctx context.Context, f AuditFilter) (rows []AuditRow, next int64, err error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	q, args := `SELECT id, time_ns, actor, action, remote, detail FROM ui_audit WHERE 1=1`, []any{}
	if f.Actor != "" {
		q += ` AND actor=?`
		args = append(args, f.Actor)
	}
	if f.Action != "" {
		q += ` AND action=?`
		args = append(args, f.Action)
	}
	if f.Before > 0 {
		q += ` AND id<?`
		args = append(args, f.Before)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, f.Limit+1)
	rs, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rs.Close()
	for rs.Next() {
		var a AuditRow
		var ns int64
		if err := rs.Scan(&a.ID, &ns, &a.Actor, &a.Action, &a.Remote, &a.Detail); err != nil {
			return nil, 0, err
		}
		a.Time = time.Unix(0, ns).UTC()
		rows = append(rows, a)
	}
	if err := rs.Err(); err != nil {
		return nil, 0, err
	}
	if len(rows) > f.Limit {
		rows = rows[:f.Limit]
		next = rows[len(rows)-1].ID
	}
	return rows, next, nil
}

// AuditFacets lists the distinct actors and actions in the audit log.
func (s *Store) AuditFacets(ctx context.Context) (actors, actions []string, err error) {
	col := func(c string) ([]string, error) {
		rs, err := s.r.QueryContext(ctx, `SELECT DISTINCT `+c+` FROM ui_audit ORDER BY 1 LIMIT 200`)
		if err != nil {
			return nil, err
		}
		defer rs.Close()
		var out []string
		for rs.Next() {
			var v string
			if err := rs.Scan(&v); err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, rs.Err()
	}
	if actors, err = col("actor"); err != nil {
		return
	}
	actions, err = col("action")
	return
}

// ---------------------------------------------------------------- size

// DiskSize is the size in bytes of the database file and its WAL.
func (s *Store) DiskSize() (db, wal int64) {
	return fileSize(s.path), fileSize(s.path + "-wal")
}

// AlertQueueDepth counts open alerts.
func (s *Store) AlertQueueDepth(ctx context.Context) (int, error) {
	var n int
	err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE state='open'`).Scan(&n)
	return n, err
}

// CountAll returns the total number of stored events and audit rows.
func (s *Store) CountAll(ctx context.Context) (events, audit int64, err error) {
	if err = s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&events); err != nil {
		return
	}
	err = s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM ui_audit`).Scan(&audit)
	return
}

// GapTotals sums every recorded gap: the number of gap records and the events
// they shed.
func (s *Store) GapTotals(ctx context.Context) (gaps int, dropped int64, err error) {
	err = s.r.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(CASE WHEN count>0 THEN count ELSE to_seq-from_seq+1 END),0) FROM gaps`).Scan(&gaps, &dropped)
	return
}
