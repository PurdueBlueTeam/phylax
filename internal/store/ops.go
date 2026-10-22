package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Operator UI storage: accounts, the audit log and the alert queue
// (design: Web UI, Alerts and incidents).

// ErrNoAccount is returned for an unknown operator.
var ErrNoAccount = errors.New("store: no such account")

// ErrNoAlert is returned for an unknown alert id.
var ErrNoAlert = errors.New("store: no such alert")

// UIAccount is one operator login; PHC is an argon2id PHC string.
type UIAccount struct {
	Name    string
	PHC     string
	Created time.Time
}

// PutAccount inserts or replaces an account.
func (s *Store) PutAccount(ctx context.Context, a UIAccount) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO ui_accounts(name, phc, created_ns) VALUES (?,?,?)
ON CONFLICT(name) DO UPDATE SET phc=excluded.phc`, a.Name, a.PHC, a.Created.UnixNano())
	return err
}

// Account returns one account.
func (s *Store) Account(ctx context.Context, name string) (UIAccount, error) {
	var a UIAccount
	var ns int64
	err := s.r.QueryRowContext(ctx, `SELECT name, phc, created_ns FROM ui_accounts WHERE name=?`, name).Scan(&a.Name, &a.PHC, &ns)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNoAccount
	}
	a.Created = time.Unix(0, ns).UTC()
	return a, err
}

// CountAccounts returns the number of accounts.
func (s *Store) CountAccounts(ctx context.Context) (int, error) {
	var n int
	err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM ui_accounts`).Scan(&n)
	return n, err
}

// AuditRow is one operator action.
type AuditRow struct {
	ID                    int64
	Time                  time.Time
	Actor, Action, Remote string
	Detail                string
}

// AppendAudit records an operator action.
func (s *Store) AppendAudit(ctx context.Context, r AuditRow) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO ui_audit(time_ns, actor, action, remote, detail) VALUES (?,?,?,?,?)`,
		r.Time.UnixNano(), r.Actor, r.Action, r.Remote, r.Detail)
	return err
}

// Audit returns the newest audit rows first (limit <= 0: 200).
func (s *Store) Audit(ctx context.Context, limit int) ([]AuditRow, error) {
	if limit <= 0 || limit > 5000 {
		limit = 200
	}
	rows, err := s.r.QueryContext(ctx, `SELECT id, time_ns, actor, action, remote, detail FROM ui_audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var a AuditRow
		var ns int64
		if err := rows.Scan(&a.ID, &ns, &a.Actor, &a.Action, &a.Remote, &a.Detail); err != nil {
			return nil, err
		}
		a.Time = time.Unix(0, ns).UTC()
		out = append(out, a)
	}
	return out, rows.Err()
}

// AlertRow is one row of the alerts table. Keys is a JSON document the
// producer fills (title, message, evidence refs, ...); the store treats it as
// opaque.
type AlertRow struct {
	ID         int64
	Rule       string
	Host       string
	Severity   int // 0 info, 1 low, 2 medium, 3 high, 4 critical
	State      string
	Time       time.Time
	Keys       string
	Agent      string
	Seq        uint64 // source event (with Agent); 0 when none
	IncidentID int64
}

// InsertAlert adds an alert (state defaults to "open") and returns its id.
func (s *Store) InsertAlert(ctx context.Context, a AlertRow) (int64, error) {
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
	res, err := s.w.ExecContext(ctx, `INSERT INTO alerts(rule, host, severity, state, time_ns, keys, agent, seq) VALUES (?,?,?,?,?,?,?,?)`,
		a.Rule, a.Host, a.Severity, a.State, a.Time.UnixNano(), a.Keys, nullStr(a.Agent), seq)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

const alertCols = `id, rule, host, severity, state, time_ns, keys, agent, seq, incident_id`

func scanAlert(r scanner) (AlertRow, error) {
	var a AlertRow
	var ns int64
	var agent sql.NullString
	var seq, inc sql.NullInt64
	if err := r.Scan(&a.ID, &a.Rule, &a.Host, &a.Severity, &a.State, &ns, &a.Keys, &agent, &seq, &inc); err != nil {
		return a, err
	}
	a.Time = time.Unix(0, ns).UTC()
	a.Agent, a.Seq, a.IncidentID = agent.String, uint64(seq.Int64), inc.Int64
	return a, nil
}

// Alerts lists alerts newest first; state "" means every state.
func (s *Store) Alerts(ctx context.Context, state string, limit int) ([]AlertRow, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	q, args := `SELECT `+alertCols+` FROM alerts`, []any{}
	if state != "" {
		q += ` WHERE state=?`
		args = append(args, state)
	}
	q += ` ORDER BY time_ns DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertRow
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Alert returns one alert.
func (s *Store) Alert(ctx context.Context, id int64) (AlertRow, error) {
	a, err := scanAlert(s.r.QueryRowContext(ctx, `SELECT `+alertCols+` FROM alerts WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNoAlert
	}
	return a, err
}

// SetAlertState changes an alert's state (open, acked, closed).
func (s *Store) SetAlertState(ctx context.Context, id int64, state string) error {
	res, err := s.w.ExecContext(ctx, `UPDATE alerts SET state=? WHERE id=?`, state, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoAlert
	}
	return nil
}

// SetAlertKeys replaces an alert's JSON key document.
func (s *Store) SetAlertKeys(ctx context.Context, id int64, keys string) error {
	res, err := s.w.ExecContext(ctx, `UPDATE alerts SET keys=? WHERE id=?`, keys, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoAlert
	}
	return nil
}
