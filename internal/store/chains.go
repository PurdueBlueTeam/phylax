package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Accessors for the campaigns, chains, hops and remediation_items tables
// (design: Attack chains). The schema is deliberately minimal, so the chains
// package stores a hop's structured detail (account, process, 5-tuple,
// technique, evidence) as JSON in HopRow.Link and a remediation item's detail
// as JSON in RemItemRow.Action; this file treats both as opaque strings.

// ErrNoChain is returned for an unknown chain id.
var ErrNoChain = errors.New("store: unknown chain")

// CampaignRow is one campaign.
type CampaignRow struct {
	ID      int64
	Name    string
	Created time.Time
}

// ChainRow is one chain with its hops (and their items) when loaded by Chain.
type ChainRow struct {
	ID         int64
	CampaignID int64 // 0 when ungrouped
	IncidentID int64 // 0 when none
	Confidence float64
	Created    time.Time
	Hops       []HopRow
}

// HopRow is one hop; Items are its remediation items.
type HopRow struct {
	ID         int64
	ChainID    int64
	Ord        int
	Kind       string
	Src, Dst   string
	Link       string
	Confidence float64
	Time       time.Time
	Items      []RemItemRow
}

// RemItemRow is one remediation item. State is "open" (a new row's default
// "todo" is read as open), "applied" or "verified".
type RemItemRow struct {
	ID     int64
	HopID  int64
	Action string
	State  string
}

func nullID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

// InsertCampaign creates a campaign.
func (s *Store) InsertCampaign(ctx context.Context, name string, created time.Time) (int64, error) {
	if created.IsZero() {
		created = time.Now()
	}
	res, err := s.w.ExecContext(ctx, `INSERT INTO campaigns(name, created_ns) VALUES (?,?)`, name, created.UnixNano())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Campaigns lists campaigns, oldest first.
func (s *Store) Campaigns(ctx context.Context) ([]CampaignRow, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, name, created_ns FROM campaigns ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CampaignRow
	for rows.Next() {
		var c CampaignRow
		var ns int64
		if err := rows.Scan(&c.ID, &c.Name, &ns); err != nil {
			return nil, err
		}
		c.Created = time.Unix(0, ns).UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}

// RenameCampaign changes a campaign's name.
func (s *Store) RenameCampaign(ctx context.Context, id int64, name string) error {
	_, err := s.w.ExecContext(ctx, `UPDATE campaigns SET name=? WHERE id=?`, name, id)
	return err
}

// InsertChain stores a chain with its hops and their remediation items in one
// transaction and returns the chain id. Ids and chain/hop back references in
// c are ignored and assigned; c is updated with the assigned ids.
func (s *Store) InsertChain(ctx context.Context, c *ChainRow) error {
	if c.Created.IsZero() {
		c.Created = time.Now()
	}
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT INTO chains(campaign_id, incident_id, confidence, created_ns) VALUES (?,?,?,?)`,
		nullID(c.CampaignID), nullID(c.IncidentID), c.Confidence, c.Created.UnixNano())
	if err != nil {
		return err
	}
	if c.ID, err = res.LastInsertId(); err != nil {
		return err
	}
	for i := range c.Hops {
		h := &c.Hops[i]
		h.ChainID = c.ID
		res, err := tx.ExecContext(ctx, `INSERT INTO hops(chain_id, ord, kind, src, dst, link, confidence, time_ns) VALUES (?,?,?,?,?,?,?,?)`,
			c.ID, h.Ord, h.Kind, h.Src, h.Dst, h.Link, h.Confidence, h.Time.UnixNano())
		if err != nil {
			return err
		}
		if h.ID, err = res.LastInsertId(); err != nil {
			return err
		}
		for j := range h.Items {
			it := &h.Items[j]
			it.HopID = h.ID
			if it.State == "" {
				it.State = "open"
			}
			res, err := tx.ExecContext(ctx, `INSERT INTO remediation_items(hop_id, action, state) VALUES (?,?,?)`, h.ID, it.Action, it.State)
			if err != nil {
				return err
			}
			if it.ID, err = res.LastInsertId(); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// SetChainCampaign assigns (or, with 0, clears) a chain's campaign.
func (s *Store) SetChainCampaign(ctx context.Context, chainID, campaignID int64) error {
	res, err := s.w.ExecContext(ctx, `UPDATE chains SET campaign_id=? WHERE id=?`, nullID(campaignID), chainID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoChain
	}
	return nil
}

// SetChainIncident links a chain to an incident.
func (s *Store) SetChainIncident(ctx context.Context, chainID, incidentID int64) error {
	res, err := s.w.ExecContext(ctx, `UPDATE chains SET incident_id=? WHERE id=?`, nullID(incidentID), chainID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoChain
	}
	return nil
}

// DeleteChain removes a chain with its hops and items (a rebuilt chain
// replaces its predecessor).
func (s *Store) DeleteChain(ctx context.Context, id int64) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM remediation_items WHERE hop_id IN (SELECT id FROM hops WHERE chain_id=?)`,
		`DELETE FROM hops WHERE chain_id=?`,
		`DELETE FROM chains WHERE id=?`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const chainCols = `id, COALESCE(campaign_id,0), COALESCE(incident_id,0), confidence, created_ns`

func scanChainRow(r scanner) (ChainRow, error) {
	var c ChainRow
	var ns int64
	err := r.Scan(&c.ID, &c.CampaignID, &c.IncidentID, &c.Confidence, &ns)
	c.Created = time.Unix(0, ns).UTC()
	return c, err
}

// Chain loads one chain with hops (ordered) and items.
func (s *Store) Chain(ctx context.Context, id int64) (ChainRow, error) {
	c, err := scanChainRow(s.r.QueryRowContext(ctx, `SELECT `+chainCols+` FROM chains WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNoChain
	}
	if err != nil {
		return c, err
	}
	if c.Hops, err = s.hopsOf(ctx, id); err != nil {
		return c, err
	}
	return c, nil
}

// Chains lists chains without hops, newest first. campaignID 0 means all.
func (s *Store) Chains(ctx context.Context, campaignID int64) ([]ChainRow, error) {
	q := `SELECT ` + chainCols + ` FROM chains`
	var args []any
	if campaignID != 0 {
		q += ` WHERE campaign_id=?`
		args = append(args, campaignID)
	}
	rows, err := s.r.QueryContext(ctx, q+` ORDER BY id DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ChainRow
	for rows.Next() {
		c, err := scanChainRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) hopsOf(ctx context.Context, chainID int64) ([]HopRow, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, chain_id, ord, kind, src, dst, link, confidence, time_ns FROM hops WHERE chain_id=? ORDER BY ord, id`, chainID)
	if err != nil {
		return nil, err
	}
	var hops []HopRow
	for rows.Next() {
		var h HopRow
		var ns int64
		if err := rows.Scan(&h.ID, &h.ChainID, &h.Ord, &h.Kind, &h.Src, &h.Dst, &h.Link, &h.Confidence, &ns); err != nil {
			rows.Close()
			return nil, err
		}
		h.Time = time.Unix(0, ns).UTC()
		hops = append(hops, h)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	items, err := s.RemediationItems(ctx, chainID)
	if err != nil {
		return nil, err
	}
	byHop := map[int64][]RemItemRow{}
	for _, it := range items {
		byHop[it.HopID] = append(byHop[it.HopID], it)
	}
	for i := range hops {
		hops[i].Items = byHop[hops[i].ID]
	}
	return hops, nil
}

// RemediationItems lists the items of every hop of a chain.
func (s *Store) RemediationItems(ctx context.Context, chainID int64) ([]RemItemRow, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT r.id, r.hop_id, r.action, r.state FROM remediation_items r
JOIN hops h ON h.id=r.hop_id WHERE h.chain_id=? ORDER BY h.ord, r.id`, chainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RemItemRow
	for rows.Next() {
		var it RemItemRow
		if err := rows.Scan(&it.ID, &it.HopID, &it.Action, &it.State); err != nil {
			return nil, err
		}
		if it.State == "todo" {
			it.State = "open"
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// ErrBadRemState rejects a state outside open, applied, verified.
var ErrBadRemState = errors.New("store: remediation state must be open, applied or verified")

// SetRemediationState moves an item to a new state.
func (s *Store) SetRemediationState(ctx context.Context, itemID int64, state string) error {
	switch state {
	case "open", "applied", "verified":
	default:
		return ErrBadRemState
	}
	res, err := s.w.ExecContext(ctx, `UPDATE remediation_items SET state=? WHERE id=?`, state, itemID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
