package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestChainAccessors(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, t.TempDir()+"/p.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := &ChainRow{Confidence: 0.7, Hops: []HopRow{
		{Ord: 0, Kind: "access", Src: "1.2.3.4", Dst: "web", Link: `{}`, Confidence: 1, Time: time.Unix(10, 0), Items: []RemItemRow{{Action: "a"}, {Action: "b"}}},
		{Ord: 1, Kind: "exec", Src: "", Dst: "web", Link: `{}`, Confidence: 0.5, Time: time.Unix(20, 0)},
	}}
	if err := s.InsertChain(ctx, c); err != nil || c.ID == 0 || c.Hops[0].Items[1].ID == 0 {
		t.Fatalf("insert: %v %+v", err, c)
	}
	got, err := s.Chain(ctx, c.ID)
	if err != nil || len(got.Hops) != 2 || len(got.Hops[0].Items) != 2 || got.Hops[0].Items[0].State != "open" || got.CampaignID != 0 {
		t.Fatalf("chain: %v %+v", err, got)
	}
	cid, _ := s.InsertCampaign(ctx, "camp", time.Time{})
	if err := s.SetChainCampaign(ctx, c.ID, cid); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.Chains(ctx, cid); len(l) != 1 {
		t.Errorf("chains by campaign: %d", len(l))
	}
	if err := s.SetChainCampaign(ctx, 999, cid); !errors.Is(err, ErrNoChain) {
		t.Errorf("unknown chain: %v", err)
	}
	it := got.Hops[0].Items[0].ID
	if err := s.SetRemediationState(ctx, it, "bogus"); !errors.Is(err, ErrBadRemState) {
		t.Errorf("bad state: %v", err)
	}
	if err := s.SetRemediationState(ctx, it, "verified"); err != nil {
		t.Fatal(err)
	}
	if items, _ := s.RemediationItems(ctx, c.ID); items[0].State != "verified" || items[1].State != "open" {
		t.Errorf("items %+v", items)
	}
	if err := s.DeleteChain(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Chain(ctx, c.ID); !errors.Is(err, ErrNoChain) {
		t.Errorf("after delete: %v", err)
	}
	if items, _ := s.RemediationItems(ctx, c.ID); len(items) != 0 {
		t.Errorf("orphan items")
	}
}
