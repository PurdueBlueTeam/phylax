package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrNoStanding is returned for an unknown standing approval id.
var ErrNoStanding = errors.New("store: unknown standing approval")

// StandingApproval is an operator-granted, scoped, expiring approval for a
// module template. It lives here rather than in plan because plan imports
// module, which imports store.
type StandingApproval struct {
	ID       string    `json:"id"`
	Module   string    `json:"module"`
	Template string    `json:"template"`
	Targets  string    `json:"targets"` // label expression
	Actions  []string  `json:"actions"`
	Expires  time.Time `json:"expires"`
	Approver string    `json:"approver"`
	Created  string    `json:"created"` // operator login
	Revoked  bool      `json:"revoked,omitempty"`
}

// InsertStanding stores a new standing approval.
func (s *Store) InsertStanding(ctx context.Context, sa StandingApproval) error {
	actions, err := json.Marshal(sa.Actions)
	if err != nil {
		return fmt.Errorf("store: standing approval actions: %w", err)
	}
	revoked := 0
	if sa.Revoked {
		revoked = 1
	}
	_, err = s.w.ExecContext(ctx, `INSERT INTO standing_approvals(id, module, template, targets, actions, expires_ns, approver, created, revoked)
VALUES (?,?,?,?,?,?,?,?,?)`,
		sa.ID, sa.Module, sa.Template, sa.Targets, string(actions), sa.Expires.UTC().UnixNano(),
		sa.Approver, sa.Created, revoked)
	return err
}

func scanStanding(r scanner) (StandingApproval, error) {
	var sa StandingApproval
	var actions string
	var expires int64
	var revoked int
	err := r.Scan(&sa.ID, &sa.Module, &sa.Template, &sa.Targets, &actions, &expires, &sa.Approver, &sa.Created, &revoked)
	if err != nil {
		return sa, err
	}
	if actions != "" && actions != "null" {
		if err := json.Unmarshal([]byte(actions), &sa.Actions); err != nil {
			return sa, fmt.Errorf("store: standing approval %s actions: %w", sa.ID, err)
		}
	}
	sa.Expires = time.Unix(0, expires).UTC()
	sa.Revoked = revoked != 0
	return sa, nil
}

const standingColumns = `id, module, template, targets, actions, expires_ns, approver, created, revoked`

// Standing returns one standing approval.
func (s *Store) Standing(ctx context.Context, id string) (StandingApproval, error) {
	sa, err := scanStanding(s.r.QueryRowContext(ctx, `SELECT `+standingColumns+` FROM standing_approvals WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return StandingApproval{}, ErrNoStanding
	}
	return sa, err
}

// ListStanding lists standing approvals, soonest expiry first.
func (s *Store) ListStanding(ctx context.Context) ([]StandingApproval, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+standingColumns+` FROM standing_approvals ORDER BY expires_ns, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StandingApproval
	for rows.Next() {
		sa, err := scanStanding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sa)
	}
	return out, rows.Err()
}

// SetStandingRevoked revokes a standing approval.
func (s *Store) SetStandingRevoked(ctx context.Context, id string) error {
	res, err := s.w.ExecContext(ctx, `UPDATE standing_approvals SET revoked=1 WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoStanding
	}
	return nil
}
