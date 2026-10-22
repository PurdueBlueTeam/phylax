//go:build linux

package actions

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/PurdueBlueTeam/phylax/internal/firewall"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
)

// NftFirewall adapts internal/firewall.LinuxManager to FirewallBackend. The
// agent owns the declared policy; Declared returns it and SetDeclared records
// the accepted delta so drift detection compares against the new intent.
type NftFirewall struct {
	Mgr         *firewall.LinuxManager
	Declared    func() *render.HostPolicy
	SetDeclared func(*render.HostPolicy)
}

type nftSnap struct {
	Nft    *firewall.Snapshot `json:"nft"`
	Policy *render.HostPolicy `json:"policy"`
}

func (n *NftFirewall) Policy(context.Context) (*render.HostPolicy, error) {
	hp := n.Declared()
	if hp == nil {
		return nil, errors.New("no declared host policy")
	}
	cp := *hp
	cp.Rules = append([]render.Rule(nil), hp.Rules...)
	return &cp, nil
}

func (n *NftFirewall) Apply(ctx context.Context, hp *render.HostPolicy) error {
	if _, err := n.Mgr.Apply(ctx, hp, firewall.ApplyOptions{Mode: firewall.ModeEnforce}); err != nil {
		return err
	}
	n.SetDeclared(hp)
	return nil
}

func (n *NftFirewall) Snapshot(ctx context.Context) (json.RawMessage, error) {
	s, err := n.Mgr.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	return json.Marshal(nftSnap{Nft: s, Policy: n.Declared()})
}

func (n *NftFirewall) Restore(ctx context.Context, raw json.RawMessage) error {
	var s nftSnap
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	if _, err := n.Mgr.Restore(ctx, s.Nft); err != nil {
		return err
	}
	if s.Policy != nil {
		n.SetDeclared(s.Policy)
	}
	return nil
}

var _ FirewallBackend = (*NftFirewall)(nil)
