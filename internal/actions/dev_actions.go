package actions

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/devices"
	"github.com/PurdueBlueTeam/phylax/internal/devices/palo"
	"github.com/PurdueBlueTeam/phylax/internal/devices/palo/xmlapi"
	"github.com/PurdueBlueTeam/phylax/internal/devices/vyos"
)

// Device actions run on the controller's Env for a device target (Env.Host is
// the device name). They wrap devices.SafeChange, which owns the protocol:
// preflight, config lock, snapshot, stage, validate, commit, health on a fresh
// connection, then confirm or roll back. Rollback is therefore the device
// protocol's, and the executor's own dead-man is not armed (Capture returns no
// rollback).

var devParam = ParamSpec{Name: "device", Type: String, Max: 128}

func deviceName(env *Env, p Params) string {
	if d := p.Str("device"); d != "" {
		return d
	}
	return env.Host
}

func devDir(env *Env) (DeviceDirectory, error) {
	if env.Win.Devices == nil {
		return nil, unsupported("network devices")
	}
	return env.Win.Devices, nil
}

type devBase struct{}

func (devBase) Touches(Params) []Touch                                  { return nil }
func (devBase) Capture(context.Context, *Env, Params) (Rollback, error) { return Rollback{}, nil }

// planID names transactions in the device's audit log.
func txOpts(env *Env, node string, scope string, risk devices.Risk, desc string) devices.TxOptions {
	return devices.TxOptions{Plan: "phylax", Node: node, Scope: scope, Risk: risk, Description: desc}
}

// parseAddrList splits a comma list into canonical CIDRs ("10.0.0.5" -> "10.0.0.5/32").
func parseAddrList(s string) ([]string, error) {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.String())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q", f)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()).String())
	}
	return out, nil
}

func checkAddrList(v any) error {
	_, err := parseAddrList(v.(string))
	return err
}

func writeEvidence(env *Env, path string, data []byte) error {
	p := env.Resolve(path)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return atomicfile.WriteFile(p, data, 0o600)
}

// ---- palo.permitted_ips ----

type paloPermittedIPs struct{ devBase }

func (paloPermittedIPs) Spec() Spec {
	return Spec{Name: "palo.permitted_ips", Risk: RiskLockout,
		Doc: "Add (and optionally remove) management permitted-IP entries on a Palo Alto firewall as its own management-scoped commit. Additive first: a brand-new connection must work after the commit or the change is rolled back; removal goes in a separate call once the new entry is proven. Needs the Network role's console acknowledgement (PAN-OS has no commit-confirm).",
		Params: []ParamSpec{
			{Name: "add", Type: String, Required: true, Max: 1024, Check: checkAddrList},
			{Name: "remove", Type: String, Max: 1024, Check: checkAddrList},
			devParam}}
}
func (paloPermittedIPs) Locks(Params) []string { return nil }

func (paloPermittedIPs) sets(p Params) (add, remove []string, err error) {
	add, err = parseAddrList(p.Str("add"))
	if err != nil {
		return
	}
	remove, err = parseAddrList(p.Str("remove"))
	if err != nil {
		return
	}
	if len(add) == 0 {
		return nil, nil, errors.New("add must name at least one address (the controller)")
	}
	for _, x := range add {
		if x == "0.0.0.0/0" || x == "::/0" {
			return nil, nil, errors.New("refusing to add a permit-all entry; the point is to narrow the ACL")
		}
		for _, r := range remove {
			if r == x {
				return nil, nil, fmt.Errorf("%s is in both add and remove", x)
			}
		}
	}
	return
}

func (paloPermittedIPs) adapter(ctx context.Context, env *Env, p Params) (*palo.Adapter, error) {
	d, err := devDir(env)
	if err != nil {
		return nil, err
	}
	return d.Palo(ctx, deviceName(env, p))
}

func (a paloPermittedIPs) current(ctx context.Context, ad *palo.Adapter) (map[string]bool, error) {
	n, err := ad.Client().ConfigShow(ctx, ad.PermittedIPPath())
	if err != nil {
		return nil, err
	}
	cur := map[string]bool{}
	if n != nil {
		for _, e := range n.Children {
			if e.Name == "entry" {
				cur[e.Attr("name")] = true
			}
		}
	}
	return cur, nil
}

func (a paloPermittedIPs) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	add, remove, err := a.sets(p)
	if err != nil {
		return Plan{}, err
	}
	ad, err := a.adapter(ctx, env, p)
	if err != nil {
		return Plan{}, err
	}
	cur, err := a.current(ctx, ad)
	if err != nil {
		return Plan{}, err
	}
	var d []string
	for _, x := range add {
		if !cur[x] {
			d = append(d, "+ permitted-ip "+x)
		}
	}
	for _, x := range remove {
		if cur[x] {
			d = append(d, "- permitted-ip "+x)
		}
	}
	if len(d) == 0 {
		return Plan{Done: true}, nil
	}
	notes := []string{"its own management commit; verified with a fresh connection"}
	if !devConsoleAck(ctx, env, deviceName(env, p)) {
		notes = append(notes, "no console acknowledgement from the Network role: the change will be refused")
	}
	return Plan{Diff: strings.Join(d, "\n"), Notes: notes}, nil
}

func devConsoleAck(ctx context.Context, env *Env, device string) bool {
	return env.Win.Devices != nil && env.Win.Devices.ConsoleAck(ctx, device)
}

func (a paloPermittedIPs) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	add, remove, err := a.sets(p)
	if err != nil {
		return nil, err
	}
	ad, err := a.adapter(ctx, env, p)
	if err != nil {
		return nil, err
	}
	var cs devices.ChangeSet
	for _, x := range add {
		cs.Ops = append(cs.Ops, palo.MakeOp("mgmt.permit", x, xmlapi.EntryXPath(ad.PermittedIPPath(), x), `<entry name="`+x+`"/>`))
	}
	for _, x := range remove {
		cs.Ops = append(cs.Ops, palo.MakeOp("mgmt.remove", x, xmlapi.EntryXPath(ad.PermittedIPPath(), x), ""))
	}
	res, err := devices.SafeChange(ctx, ad, devices.Request{
		Opts:       txOpts(env, "permitted-ips", devices.ScopeManagement, devices.RiskLockout, "phylax: management permitted IPs"),
		Changes:    cs,
		Health:     ad.HealthCheck(nil, nil),
		ConsoleAck: devConsoleAck(ctx, env, deviceName(env, p))})
	return safeChangeOutput(res), err
}

func (a paloPermittedIPs) Verify(ctx context.Context, env *Env, p Params) error {
	add, remove, _ := a.sets(p)
	ad, err := a.adapter(ctx, env, p)
	if err != nil {
		return err
	}
	cur, err := a.current(ctx, ad)
	if err != nil {
		return err
	}
	for _, x := range add {
		if !cur[x] {
			return fmt.Errorf("permitted-ip %s missing after commit", x)
		}
	}
	for _, x := range remove {
		if cur[x] {
			return fmt.Errorf("permitted-ip %s still present after commit", x)
		}
	}
	return ad.Probe(ctx)
}

func safeChangeOutput(r *devices.Result) Output {
	if r == nil {
		return nil
	}
	out := Output{"tx": r.TxID, "rolled_back": fmt.Sprint(r.RolledBack)}
	if r.Before != nil {
		out["before_hash"] = r.Before.Hash
	}
	if r.After != nil {
		out["after_hash"] = r.After.Hash
	}
	if r.Commit.NoChanges {
		out["no_changes"] = "true"
	}
	if len(r.Tainted) > 0 {
		out["tainted"] = strings.Join(r.Tainted, "; ")
	}
	return out
}

// ---- palo.commit (verification of the management path) ----

type paloCommit struct{ devBase }

func (paloCommit) Spec() Spec {
	return Spec{Name: "palo.commit", Risk: RiskNone, ReadOnly: true,
		Doc:    "Management-path commit check. palo.permitted_ips and palo.apply already commit through the safe-change protocol (their own scoped commit, verified on a brand-new connection); this step proves a fresh connection works and that no uncommitted candidate changes remain, and fails otherwise. It never commits other people's staged changes.",
		Params: []ParamSpec{{Name: "description", Type: String, Max: 256}, devParam}}
}
func (paloCommit) Locks(Params) []string { return nil }
func (paloCommit) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	if _, err := devDir(env); err != nil {
		return Plan{}, err
	}
	return Plan{Diff: "verify fresh connection and clean candidate on " + deviceName(env, p)}, nil
}
func (paloCommit) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	d, err := devDir(env)
	if err != nil {
		return nil, err
	}
	ad, err := d.Palo(ctx, deviceName(env, p))
	if err != nil {
		return nil, err
	}
	if err := ad.Probe(ctx); err != nil {
		return nil, fmt.Errorf("fresh connection: %w", err)
	}
	tx, err := ad.Begin(ctx, txOpts(env, "commit-check", devices.ScopeManagement, devices.RiskNone, p.Str("description")))
	if err != nil {
		return nil, err
	}
	defer tx.Close(context.WithoutCancel(ctx))
	pf, err := tx.Preflight(ctx)
	if err != nil {
		return nil, err
	}
	if !pf.OK {
		reasons := append([]string(nil), pf.Reasons...)
		reasons = append(reasons, pf.Foreign...)
		return nil, fmt.Errorf("%w: %s", devices.ErrPreflight, strings.Join(reasons, "; "))
	}
	return Output{"candidate": "clean", "fresh_connection": "ok"}, nil
}
func (paloCommit) Verify(context.Context, *Env, Params) error { return nil }

// ---- palo.apply (policy rule push / management lockdown from the manifest) ----

type paloApply struct{ devBase }

func (paloApply) Spec() Spec {
	return Spec{Name: "palo.apply", Risk: RiskService,
		Doc: "Push the manifest's Palo intent through the safe-change protocol. scope=policy stages the tagged address objects, NAT and security rules and commits only them; scope=management is the additive permitted-IP half of the lockdown (its own commit), with remove_old=true running the removal commit afterwards. Policy health requires every scored flow to still match an allow rule.",
		Params: []ParamSpec{
			{Name: "scope", Type: Enum, Required: true, Enum: []string{devices.ScopePolicy, devices.ScopeManagement}},
			{Name: "remove_old", Type: Bool}, devParam}}
}
func (paloApply) Locks(Params) []string { return nil }

func (paloApply) setup(ctx context.Context, env *Env, p Params) (*palo.Adapter, *palo.Translation, *palo.Translation, error) {
	d, err := devDir(env)
	if err != nil {
		return nil, nil, nil, err
	}
	dev := deviceName(env, p)
	ad, err := d.Palo(ctx, dev)
	if err != nil {
		return nil, nil, nil, err
	}
	in, err := d.PaloIntent(ctx, dev)
	if err != nil {
		return nil, nil, nil, err
	}
	tr, err := ad.Translate(in)
	if err != nil {
		return nil, nil, nil, err
	}
	return ad, tr, nil, nil
}

func (a paloApply) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	_, tr, _, err := a.setup(ctx, env, p)
	if err != nil {
		return Plan{}, err
	}
	cs := tr.Policy
	if p.Str("scope") == devices.ScopeManagement {
		cs = tr.Mgmt
	}
	if len(cs.Ops) == 0 {
		return Plan{Done: true, Notes: tr.Warnings}, nil
	}
	var d []string
	for _, o := range cs.Ops {
		d = append(d, o.Kind+" "+o.Key)
	}
	return Plan{Diff: strings.Join(d, "\n"), Notes: tr.Warnings}, nil
}

func (a paloApply) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	ad, tr, _, err := a.setup(ctx, env, p)
	if err != nil {
		return nil, err
	}
	d := env.Win.Devices
	dev := deviceName(env, p)
	ack := d.ConsoleAck(ctx, dev)
	if p.Str("scope") == devices.ScopePolicy {
		in, _ := d.PaloIntent(ctx, dev)
		res, err := devices.SafeChange(ctx, ad, devices.Request{
			Opts:    txOpts(env, "policy", devices.ScopePolicy, tr.PolicyRisk, "phylax: policy"),
			Changes: tr.Policy, Health: ad.HealthCheck(palo.FlowsFromIntent(in), nil), ConsoleAck: ack})
		return safeChangeOutput(res), err
	}
	res, err := devices.SafeChange(ctx, ad, devices.Request{
		Opts:    txOpts(env, "mgmt-add", devices.ScopeManagement, devices.RiskLockout, "phylax: management lockdown (add)"),
		Changes: tr.Mgmt, Health: ad.HealthCheck(nil, nil), ConsoleAck: ack})
	out := safeChangeOutput(res)
	if err != nil || !p.Bool("remove_old") {
		return out, err
	}
	rem, err := ad.MgmtRemovals(ctx, tr)
	if err != nil || len(rem.Ops) == 0 {
		return out, err
	}
	res2, err := devices.SafeChange(ctx, ad, devices.Request{
		Opts:    txOpts(env, "mgmt-remove", devices.ScopeManagement, devices.RiskLockout, "phylax: management lockdown (remove)"),
		Changes: rem, Health: ad.HealthCheck(nil, nil), ConsoleAck: ack})
	for k, v := range safeChangeOutput(res2) {
		out["remove."+k] = v
	}
	return out, err
}

func (a paloApply) Verify(ctx context.Context, env *Env, p Params) error {
	ad, _, _, err := a.setup(ctx, env, p)
	if err != nil {
		return err
	}
	return ad.Probe(ctx)
}

// ---- palo.snapshot / vyos.snapshot (config export to evidence) ----

type devSnapshot struct {
	devBase
	kind devices.Kind
}

func (s devSnapshot) Spec() Spec {
	name, doc := "palo.snapshot", "Export the running PAN-OS configuration (canonical form) to an evidence file."
	if s.kind == devices.VyOS {
		name, doc = "vyos.snapshot", "Export the VyOS configuration commands to an evidence file."
	}
	return Spec{Name: name, Risk: RiskNone, ReadOnly: true, Doc: doc,
		Params: []ParamSpec{{Name: "out", Type: Path, Required: true}, devParam}}
}
func (devSnapshot) Locks(Params) []string { return nil }
func (s devSnapshot) adapter(ctx context.Context, env *Env, p Params) (devices.Adapter, error) {
	d, err := devDir(env)
	if err != nil {
		return nil, err
	}
	if s.kind == devices.VyOS {
		a, err := d.VyOS(ctx, deviceName(env, p))
		return a, err
	}
	a, err := d.Palo(ctx, deviceName(env, p))
	return a, err
}
func (s devSnapshot) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	if _, err := devDir(env); err != nil {
		return Plan{}, err
	}
	return Plan{Diff: "write " + p.Str("out")}, nil
}
func (s devSnapshot) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	ad, err := s.adapter(ctx, env, p)
	if err != nil {
		return nil, err
	}
	snap, err := ad.Snapshot(ctx, "evidence-"+env.now().UTC().Format("20060102T150405Z"))
	if err != nil {
		return nil, err
	}
	if err := writeEvidence(env, p.Str("out"), snap.Data); err != nil {
		return nil, err
	}
	return Output{"hash": snap.Hash, "bytes": fmt.Sprint(len(snap.Data)), "taken": snap.Taken.UTC().Format(time.RFC3339)}, nil
}
func (s devSnapshot) Verify(_ context.Context, env *Env, p Params) error {
	st, err := os.Stat(env.Resolve(p.Str("out")))
	if err != nil {
		return err
	}
	if st.Size() == 0 {
		return errors.New("evidence file is empty")
	}
	return nil
}

// ---- vyos.apply ----

type vyosApply struct{ devBase }

func (vyosApply) Spec() Spec {
	return Spec{Name: "vyos.apply", Risk: RiskLockout,
		Doc: "Push the manifest's VyOS intent (source NAT and forward firewall rules, phylax-managed only) with an SSH-armed soft revert: the router reverts on its own unless the change is confirmed after a fresh connection and health check. scope=management applies the SSH/HTTPS lockdown as its own change.",
		Params: []ParamSpec{
			{Name: "scope", Type: Enum, Required: true, Enum: []string{devices.ScopePolicy, devices.ScopeManagement}},
			{Name: "outbound_interface", Type: String, Max: 32}, devParam}}
}
func (vyosApply) Locks(Params) []string { return nil }

func (vyosApply) setup(ctx context.Context, env *Env, p Params) (*vyos.Adapter, *vyos.Translation, error) {
	d, err := devDir(env)
	if err != nil {
		return nil, nil, err
	}
	dev := deviceName(env, p)
	ad, err := d.VyOS(ctx, dev)
	if err != nil {
		return nil, nil, err
	}
	in, err := d.VyOSIntent(ctx, dev)
	if err != nil {
		return nil, nil, err
	}
	tr, err := ad.Translate(in, vyos.TranslateOpts{OutboundInterface: p.Str("outbound_interface")})
	return ad, tr, err
}
func (a vyosApply) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	_, tr, err := a.setup(ctx, env, p)
	if err != nil {
		return Plan{}, err
	}
	cs := tr.Policy
	if p.Str("scope") == devices.ScopeManagement {
		cs = tr.Mgmt
	}
	if len(cs.Ops) == 0 {
		return Plan{Done: true, Notes: tr.Warnings}, nil
	}
	var d []string
	for _, o := range cs.Ops {
		d = append(d, o.Kind+" "+o.Key)
	}
	sort.Strings(d)
	return Plan{Diff: strings.Join(d, "\n"), Notes: tr.Warnings}, nil
}
func (a vyosApply) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	ad, tr, err := a.setup(ctx, env, p)
	if err != nil {
		return nil, err
	}
	cs, scope, risk := tr.Policy, devices.ScopePolicy, tr.PolicyRisk
	if p.Str("scope") == devices.ScopeManagement {
		cs, scope, risk = tr.Mgmt, devices.ScopeManagement, tr.MgmtRisk
	}
	res, err := devices.SafeChange(ctx, ad, devices.Request{
		Opts:    txOpts(env, "vyos-"+scope, scope, risk, "phylax: "+scope),
		Changes: cs, Health: ad.HealthCheck(nil),
		ConsoleAck: env.Win.Devices.ConsoleAck(ctx, deviceName(env, p))})
	return safeChangeOutput(res), err
}
func (a vyosApply) Verify(ctx context.Context, env *Env, p Params) error {
	ad, _, err := a.setup(ctx, env, p)
	if err != nil {
		return err
	}
	return ad.Probe(ctx)
}
