package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrNoPlan is returned for an unknown plan id.
var ErrNoPlan = errors.New("store: unknown plan")

// PlanRow is one row of the plans table. Body holds the plan definition and
// its approvals as JSON; it never holds secret material.
type PlanRow struct {
	ID      string
	Name    string
	State   string
	Epoch   uint64
	Body    string
	Created time.Time
	Updated time.Time
}

// PlanStepRow is one node of a plan: its state and the history of signed
// results as JSON.
type PlanStepRow struct {
	PlanID  string
	Step    string // node id
	Host    string
	Action  string
	State   string
	Result  string
	Updated time.Time
}

// UpsertPlan inserts or updates a plan row (created time is kept on update).
func (s *Store) UpsertPlan(ctx context.Context, p PlanRow) error {
	now := time.Now().UnixNano()
	created := now
	if !p.Created.IsZero() {
		created = p.Created.UnixNano()
	}
	if p.Body == "" {
		p.Body = "{}"
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO plans(id, name, state, epoch, body, created_ns, updated_ns)
VALUES (?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, state=excluded.state, epoch=excluded.epoch,
  body=excluded.body, updated_ns=excluded.updated_ns`,
		p.ID, p.Name, p.State, p.Epoch, p.Body, created, now)
	return err
}

func scanPlan(r scanner) (PlanRow, error) {
	var p PlanRow
	var c, u int64
	err := r.Scan(&p.ID, &p.Name, &p.State, &p.Epoch, &p.Body, &c, &u)
	p.Created, p.Updated = time.Unix(0, c).UTC(), time.Unix(0, u).UTC()
	return p, err
}

// Plan returns one plan.
func (s *Store) Plan(ctx context.Context, id string) (PlanRow, error) {
	p, err := scanPlan(s.r.QueryRowContext(ctx, `SELECT id, name, state, epoch, body, created_ns, updated_ns FROM plans WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return PlanRow{}, ErrNoPlan
	}
	return p, err
}

// Plans lists plans, newest first.
func (s *Store) Plans(ctx context.Context) ([]PlanRow, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, name, state, epoch, body, created_ns, updated_ns FROM plans ORDER BY created_ns DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PlanRow
	for rows.Next() {
		p, err := scanPlan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpsertPlanStep inserts or updates one node row.
func (s *Store) UpsertPlanStep(ctx context.Context, r PlanStepRow) error {
	if r.Result == "" {
		r.Result = "{}"
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO plan_steps(plan_id, step, host, action, state, result, updated_ns)
VALUES (?,?,?,?,?,?,?)
ON CONFLICT(plan_id, step) DO UPDATE SET host=excluded.host, action=excluded.action, state=excluded.state,
  result=excluded.result, updated_ns=excluded.updated_ns`,
		r.PlanID, r.Step, r.Host, r.Action, r.State, r.Result, time.Now().UnixNano())
	return err
}

// PlanSteps lists a plan's node rows ordered by node id.
func (s *Store) PlanSteps(ctx context.Context, planID string) ([]PlanStepRow, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT plan_id, step, host, action, state, result, updated_ns FROM plan_steps WHERE plan_id=? ORDER BY step`, planID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PlanStepRow
	for rows.Next() {
		var r PlanStepRow
		var u int64
		if err := rows.Scan(&r.PlanID, &r.Step, &r.Host, &r.Action, &r.State, &r.Result, &u); err != nil {
			return nil, err
		}
		r.Updated = time.Unix(0, u).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// NextStepSeq atomically allocates the next per-host plan-step sequence
// number (1, 2, ...). It is durable before it returns, so a controller crash
// never reuses a number an agent may already have accepted.
func (s *Store) NextStepSeq(ctx context.Context, host string) (uint64, error) {
	if host == "" {
		return 0, errors.New("store: step sequence needs a host")
	}
	key := "stepseq:" + host
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var cur uint64
	err = tx.QueryRowContext(ctx, `SELECT CAST(value AS INTEGER) FROM meta WHERE key=?`, key).Scan(&cur)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	cur++
	if _, err := tx.ExecContext(ctx, `INSERT INTO meta(key, value) VALUES (?,?)
ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, fmt.Sprint(cur)); err != nil {
		return 0, err
	}
	return cur, tx.Commit()
}

// InterruptPlans marks every plan in one of the given states as interrupted
// (controller restart) and returns how many changed.
func (s *Store) InterruptPlans(ctx context.Context, states ...string) (int, error) {
	n := 0
	for _, st := range states {
		res, err := s.w.ExecContext(ctx, `UPDATE plans SET state='interrupted', updated_ns=? WHERE state=?`, time.Now().UnixNano(), st)
		if err != nil {
			return n, err
		}
		c, _ := res.RowsAffected()
		n += int(c)
	}
	return n, nil
}
