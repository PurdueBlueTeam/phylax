package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrNoProposal is returned for an unknown proposal id.
var ErrNoProposal = errors.New("store: unknown proposal")

// ProposalRow is one one-click plan proposal. Evidence holds "agent:seq"
// references to the events that justify it.
type ProposalRow struct {
	ID       int64
	Module   string
	Title    string
	Template string
	Params   map[string]string
	Evidence []string
	Reason   string
	Created  time.Time
	State    string // open, accepted, dismissed
	PlanID   string
	By       string
}

const maxOpenProposalScan = 10000 // bounds a read of all open proposals

// InsertProposal stores a proposal and returns its id.
func (s *Store) InsertProposal(ctx context.Context, p ProposalRow) (int64, error) {
	params, err := json.Marshal(p.Params)
	if err != nil {
		return 0, fmt.Errorf("store: proposal params: %w", err)
	}
	evidence, err := json.Marshal(p.Evidence)
	if err != nil {
		return 0, fmt.Errorf("store: proposal evidence: %w", err)
	}
	if p.Created.IsZero() {
		p.Created = time.Now()
	}
	if p.State == "" {
		p.State = "open"
	}
	res, err := s.w.ExecContext(ctx, `INSERT INTO proposals(module, title, template, params, evidence, reason, created_ns, state, plan_id, "by")
VALUES (?,?,?,?,?,?,?,?,?,?)`,
		p.Module, p.Title, p.Template, string(params), string(evidence), p.Reason,
		p.Created.UTC().UnixNano(), p.State, p.PlanID, p.By)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func scanProposal(r scanner) (ProposalRow, error) {
	var p ProposalRow
	var params, evidence string
	var created int64
	err := r.Scan(&p.ID, &p.Module, &p.Title, &p.Template, &params, &evidence, &p.Reason, &created, &p.State, &p.PlanID, &p.By)
	if err != nil {
		return p, err
	}
	if params != "" && params != "null" {
		if err := json.Unmarshal([]byte(params), &p.Params); err != nil {
			return p, fmt.Errorf("store: proposal %d params: %w", p.ID, err)
		}
	}
	if evidence != "" && evidence != "null" {
		if err := json.Unmarshal([]byte(evidence), &p.Evidence); err != nil {
			return p, fmt.Errorf("store: proposal %d evidence: %w", p.ID, err)
		}
	}
	p.Created = time.Unix(0, created).UTC()
	return p, nil
}

const proposalColumns = `id, module, title, template, params, evidence, reason, created_ns, state, plan_id, "by"`

// Proposal returns one proposal.
func (s *Store) Proposal(ctx context.Context, id int64) (ProposalRow, error) {
	p, err := scanProposal(s.r.QueryRowContext(ctx, `SELECT `+proposalColumns+` FROM proposals WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ProposalRow{}, ErrNoProposal
	}
	return p, err
}

// OpenProposals lists open proposals, oldest first.
func (s *Store) OpenProposals(ctx context.Context) ([]ProposalRow, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+proposalColumns+` FROM proposals WHERE state='open' ORDER BY created_ns, id LIMIT ?`, maxOpenProposalScan)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProposalRow
	for rows.Next() {
		p, err := scanProposal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CloseProposal moves an open proposal to state and records the plan it
// produced and the operator who decided.
func (s *Store) CloseProposal(ctx context.Context, id int64, state, planID, by string) error {
	switch state {
	case "accepted", "dismissed":
	default:
		return fmt.Errorf("store: proposal close state %q", state)
	}
	res, err := s.w.ExecContext(ctx, `UPDATE proposals SET state=?, plan_id=?, "by"=? WHERE id=?`, state, planID, by, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoProposal
	}
	return nil
}
