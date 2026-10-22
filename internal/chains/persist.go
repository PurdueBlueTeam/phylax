package chains

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// The tables are minimal, so a hop's structured detail is JSON in hops.link
// and an item's in remediation_items.action; chain-level notes ride on the
// first hop. hops.src and hops.dst hold the host (or address) for plain SQL.

type chainMeta struct {
	Seed      SeedKind `json:"seed"`
	Truncated bool     `json:"truncated,omitempty"`
	Notes     []string `json:"notes,omitempty"`
}

type hopDoc struct {
	Hop
	Chain *chainMeta `json:"chain,omitempty"`
}

func first(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}

// Save stores a chain, its hops and items in one transaction and sets the ids
// on c.
func Save(ctx context.Context, st *store.Store, c *Chain) error {
	row := store.ChainRow{CampaignID: c.CampaignID, IncidentID: c.IncidentID, Confidence: c.Confidence, Created: c.Created}
	for i := range c.Hops {
		h := &c.Hops[i]
		doc := hopDoc{Hop: *h}
		if i == 0 {
			doc.Chain = &chainMeta{Seed: c.Seed, Truncated: c.Truncated, Notes: c.Notes}
		}
		b, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		hr := store.HopRow{Ord: h.Ord, Kind: string(h.Kind), Src: first(h.SrcHost, h.SrcAddr), Dst: first(h.DstHost, h.DstAddr),
			Link: string(b), Confidence: h.Confidence, Time: h.Start}
		for _, it := range h.Items {
			ib, err := json.Marshal(it)
			if err != nil {
				return err
			}
			hr.Items = append(hr.Items, store.RemItemRow{Action: string(ib), State: first(it.State, StateOpen)})
		}
		row.Hops = append(row.Hops, hr)
	}
	if err := st.InsertChain(ctx, &row); err != nil {
		return err
	}
	c.ID = row.ID
	for i := range c.Hops {
		c.Hops[i].ID = row.Hops[i].ID
		for j := range c.Hops[i].Items {
			c.Hops[i].Items[j].ID = row.Hops[i].Items[j].ID
		}
	}
	return nil
}

// Load reads a chain back.
func Load(ctx context.Context, st *store.Store, id int64) (*Chain, error) {
	row, err := st.Chain(ctx, id)
	if err != nil {
		return nil, err
	}
	return fromRow(row)
}

func fromRow(row store.ChainRow) (*Chain, error) {
	c := &Chain{ID: row.ID, CampaignID: row.CampaignID, IncidentID: row.IncidentID, Confidence: row.Confidence, Created: row.Created}
	for _, hr := range row.Hops {
		var d hopDoc
		if err := json.Unmarshal([]byte(hr.Link), &d); err != nil {
			return nil, fmt.Errorf("chains: hop %d of chain %d: %w", hr.ID, row.ID, err)
		}
		h := d.Hop
		h.ID, h.Ord = hr.ID, hr.Ord
		h.Confidence = hr.Confidence
		if d.Chain != nil {
			c.Seed, c.Truncated, c.Notes = d.Chain.Seed, d.Chain.Truncated, d.Chain.Notes
		}
		for _, ir := range hr.Items {
			var it Item
			if err := json.Unmarshal([]byte(ir.Action), &it); err != nil {
				return nil, fmt.Errorf("chains: item %d: %w", ir.ID, err)
			}
			it.ID, it.State = ir.ID, ir.State
			h.Items = append(h.Items, it)
		}
		c.Hops = append(c.Hops, h)
	}
	return c, nil
}

// LoadAll reads every chain (newest first), with hops.
func LoadAll(ctx context.Context, st *store.Store) ([]*Chain, error) {
	rows, err := st.Chains(ctx, 0)
	if err != nil {
		return nil, err
	}
	var out []*Chain
	for _, r := range rows {
		c, err := Load(ctx, st, r.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// SaveItemStates writes the current item states of c back (after Verify or an
// operator change).
func SaveItemStates(ctx context.Context, st *store.Store, c *Chain) error {
	for _, h := range c.Hops {
		for _, it := range h.Items {
			if it.ID == 0 {
				continue
			}
			if err := st.SetRemediationState(ctx, it.ID, first(it.State, StateOpen)); err != nil {
				return err
			}
		}
	}
	return nil
}

// SyncCampaigns groups chains and records the campaigns: a campaign keeps the
// id of its oldest member's campaign, new ones are created, and every chain is
// assigned. It returns the campaigns.
func SyncCampaigns(ctx context.Context, st *store.Store, chains []*Chain, cfg Config) ([]*Campaign, error) {
	camps := Group(chains, cfg)
	for _, cp := range camps {
		if cp.ID == 0 {
			id, err := st.InsertCampaign(ctx, cp.Name, time.Now())
			if err != nil {
				return nil, err
			}
			cp.ID = id
		} else if err := st.RenameCampaign(ctx, cp.ID, cp.Name); err != nil {
			return nil, err
		}
		for _, c := range cp.Chains {
			if c.CampaignID != cp.ID {
				if err := st.SetChainCampaign(ctx, c.ID, cp.ID); err != nil {
					return nil, err
				}
				c.CampaignID = cp.ID
			}
		}
	}
	return camps, nil
}
