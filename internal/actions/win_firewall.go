package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
	"github.com/PurdueBlueTeam/phylax/internal/firewall"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
)

const kindWinFW = "win.firewall.restore"

// winServiceGroup is the Windows rule group for declared listeners, derived
// from the renderer so it cannot drift (the same trick internal/firewall uses).
var winServiceGroup = func() string {
	wp, err := render.WindowsRules(&render.HostPolicy{Host: "probe", Family: "windows", Rules: []render.Rule{
		{Group: render.GroupService, Kind: render.KindService, Dir: render.In, Action: render.Accept, Proto: "tcp"}}})
	if err != nil || len(wp.Rules) == 0 {
		panic("actions: cannot derive the Windows service rule group")
	}
	return wp.Rules[0].Group
}()

func init() {
	RegisterUndo(kindWinFW, func(ctx context.Context, env *Env, e deadman.Entry) error {
		var s firewall.WinSnapshot
		if err := json.Unmarshal(e.Data, &s); err != nil {
			return err
		}
		if env.Win.Firewall == nil {
			return Unsupported("windows firewall")
		}
		return firewall.NewWindows(firewall.WinOptions{NewBackend: env.Win.Firewall, Now: env.Now}).Restore(ctx, &s)
	})
}

var ruleNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]{0,100}$`)

type winFirewall struct{}

func (winFirewall) Spec() Spec {
	return Spec{Name: "win.firewall", Risk: RiskLockout,
		Doc: "Add (or remove) an inbound allow rule for ports from given sources in Phylax's own Windows Firewall rule group through the COM API. Only Phylax-group rules are ever touched. A dead-man restores the previous rule state.",
		Params: []ParamSpec{
			{Name: "name", Type: String, Required: true, Check: func(v any) error {
				if !ruleNameRe.MatchString(v.(string)) {
					return errors.New("invalid rule name")
				}
				return nil
			}},
			{Name: "ports", Type: String, Required: true, Max: 256},
			{Name: "proto", Type: Enum, Enum: []string{"tcp", "udp"}, Default: "tcp"},
			{Name: "from", Type: String, Max: 1024, Default: "any"},
			{Name: "remove", Type: Bool}}}
}

func (winFirewall) Locks(Params) []string  { return []string{LockFirewall} }
func (winFirewall) Touches(Params) []Touch { return nil }

func (winFirewall) rule(p Params) (firewall.WinRuleState, error) {
	ports := firewall.NormPorts(p.Str("ports"))
	if ports == "" {
		return firewall.WinRuleState{}, errors.New("ports required (a rule for every port is not allowed here)")
	}
	for _, c := range ports {
		if !strings.ContainsRune("0123456789,-", c) {
			return firewall.WinRuleState{}, fmt.Errorf("ports %q: only numbers and ranges", p.Str("ports"))
		}
	}
	addrs, err := firewall.NormAddrs(p.Str("from"))
	if err != nil {
		return firewall.WinRuleState{}, err
	}
	return firewall.WinRuleState{
		Name: "phylax-" + p.Str("name"), Description: "phylax-managed", Group: winServiceGroup,
		Direction: "Inbound", Action: "Allow", Protocol: strings.ToUpper(p.Str("proto")),
		LocalPorts: ports, RemoteAddresses: addrs, Profiles: "Any", Enabled: true}, nil
}

func (a winFirewall) mgr(env *Env) (*firewall.WinManager, error) {
	if env.Win.Firewall == nil {
		return nil, Unsupported("windows firewall")
	}
	return firewall.NewWindows(firewall.WinOptions{NewBackend: env.Win.Firewall, Now: env.Now}), nil
}

// desired is the current Phylax state with the rule added, replaced or removed.
func (a winFirewall) desired(cur *firewall.WinState, p Params) (*firewall.WinState, error) {
	r, err := a.rule(p)
	if err != nil {
		return nil, err
	}
	want := &firewall.WinState{Profiles: append([]firewall.WinProfileState(nil), cur.Profiles...)}
	for _, x := range cur.Rules {
		if x.Name != r.Name {
			want.Rules = append(want.Rules, x)
		}
	}
	if !p.Bool("remove") {
		want.Rules = append(want.Rules, r)
	}
	return want, nil
}

func (a winFirewall) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	m, err := a.mgr(env)
	if err != nil {
		return Plan{}, err
	}
	snap, err := m.Snapshot(ctx)
	if err != nil {
		return Plan{}, err
	}
	want, err := a.desired(snap.State, p)
	if err != nil {
		return Plan{}, err
	}
	d := firewall.DiffWinStates(want, snap.State)
	if len(d) == 0 {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: strings.Join(d, "\n")}, nil
}

func (a winFirewall) Capture(ctx context.Context, env *Env, _ Params) (Rollback, error) {
	m, err := a.mgr(env)
	if err != nil {
		return Rollback{}, err
	}
	snap, err := m.Snapshot(ctx)
	if err != nil {
		return Rollback{}, err
	}
	return Rollback{Kind: kindWinFW, Data: snap}, nil
}

func (a winFirewall) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	m, err := a.mgr(env)
	if err != nil {
		return nil, err
	}
	snap, err := m.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	want, err := a.desired(snap.State, p)
	if err != nil {
		return nil, err
	}
	res, err := m.ApplyState(ctx, want, firewall.ApplyOptions{})
	if err != nil {
		return nil, err
	}
	out := Output{"hash": res.Hash}
	for _, f := range res.ForeignBlockers {
		out["foreign_blocker."+f.Name] = f.Direction + " " + f.LocalPorts
	}
	return out, nil
}

func (a winFirewall) Verify(ctx context.Context, env *Env, p Params) error {
	m, err := a.mgr(env)
	if err != nil {
		return err
	}
	snap, err := m.Snapshot(ctx)
	if err != nil {
		return err
	}
	r, err := a.rule(p)
	if err != nil {
		return err
	}
	found := false
	for _, x := range snap.State.Rules {
		if x.Name == r.Name {
			found = true
			if p.Bool("remove") {
				return errors.New("rule still present")
			}
			if x.LocalPorts != r.LocalPorts || x.RemoteAddresses != r.RemoteAddresses || !x.Enabled {
				return fmt.Errorf("rule differs after apply: %+v", x)
			}
		}
	}
	if !found && !p.Bool("remove") {
		return errors.New("rule missing after apply")
	}
	return nil
}
