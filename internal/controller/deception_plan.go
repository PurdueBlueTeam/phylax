package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// Secret-bearing plan nodes. A node of file.plant or ad.honey_account names its
// secret parameters (secret_params) and the vault entry for each (secret_refs).
// The plan, its hash, its stored JSON, the signed step params and every diff
// carry only those names. When the controller issues the step it resolves the
// refs from the vault into the step's secrets blob (a JSON object, digest
// signed with the step), which the agent hands to the action through its
// context.

// secretActions are the actions allowed to take vault secrets, and the only
// parameter names each may take.
var secretActions = map[string][]string{"file.plant": {"content"}, "ad.honey_account": {"password"}}

// maxSecretRefs bounds one node's secrets.
const maxSecretRefs = 4

// stepSecrets returns the secrets blob for node n (nil when it has none).
// Only vault entries under honeytoken/ can be referenced, so a plan author
// cannot make the controller ship an administrator password to a host.
func (c *Controller) stepSecrets(n plan.Node) ([]byte, error) {
	allowed, ok := secretActions[n.Action]
	if !ok {
		return nil, nil
	}
	names, err := nodeStringList(n.Params["secret_params"])
	if err != nil {
		return nil, fmt.Errorf("node %s: secret_params: %w", n.ID, err)
	}
	if len(names) == 0 {
		return nil, nil
	}
	if len(names) > maxSecretRefs {
		return nil, fmt.Errorf("node %s: too many secret parameters", n.ID)
	}
	refs, _ := n.Params["secret_refs"].(map[string]any)
	if c.opt.Vault == nil {
		return nil, fmt.Errorf("node %s needs secrets but no vault is configured", n.ID)
	}
	out := map[string]string{}
	for _, name := range names {
		if !containsStr(allowed, name) {
			return nil, fmt.Errorf("node %s: %q cannot be a secret parameter of %s", n.ID, name, n.Action)
		}
		ref, _ := refs[name].(string)
		if !strings.HasPrefix(ref, honeyVaultPrefix) || strings.Contains(ref, "..") {
			return nil, fmt.Errorf("node %s: secret %q has no usable vault reference", n.ID, name)
		}
		s, _, err := c.opt.Vault.Get(ref)
		if err != nil {
			// The vault error names the entry, not its value.
			return nil, fmt.Errorf("node %s: secret %q (%s): %w", n.ID, name, ref, err)
		}
		out[name] = s.Reveal()
	}
	return json.Marshal(out)
}

func nodeStringList(v any) ([]string, error) {
	switch l := v.(type) {
	case nil:
		return nil, nil
	case []string:
		return l, nil
	case []any:
		out := make([]string, 0, len(l))
		for _, e := range l {
			s, ok := e.(string)
			if !ok {
				return nil, errors.New("not a list of strings")
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, errors.New("not a list of strings")
}

// DeceptionPlan generates the honeytokens that do not exist yet for hosts (all
// hosts with decoys.yml tokens if none are named) and returns the deploy plan:
// a gate, a decoy listener check per decoy host, and one planting node per
// token, each needing the gate. It mirrors plans/deception.deploy.yaml, whose
// per-token nodes the generated tokens fill in. Secret values are in the vault;
// the returned plan holds references only. Create it with CreatePlan.
func (c *Controller) DeceptionPlan(ctx context.Context, id string, hosts ...string) (plan.Plan, error) {
	if _, err := c.GenerateHoneytokens(ctx, hosts...); err != nil {
		return plan.Plan{}, err
	}
	c.cfgs.mu.Lock()
	in := c.cfgs.in
	c.cfgs.mu.Unlock()
	if in == nil {
		return plan.Plan{}, errors.New("deception plan: no manifest loaded")
	}
	m := in.Manifest
	p := plan.Plan{ID: id, Name: "Deploy decoys and honeytokens", OnFailure: plan.Continue}
	p.Nodes = append(p.Nodes, plan.Node{ID: "approve-deception", Gate: true,
		Note: "Review the decoy ports (never a scored port) and the honey file paths. Planting never replaces an existing file."})
	var dh []string
	for h, d := range m.Decoys {
		if len(d.Listeners) > 0 && (len(hosts) == 0 || containsStr(hosts, h)) {
			dh = append(dh, h)
		}
	}
	sort.Strings(dh)
	for _, h := range dh {
		var ports []any
		for _, l := range m.Decoys[h].Listeners {
			ports = append(ports, fmt.Sprint(l.Port))
		}
		p.Nodes = append(p.Nodes, plan.Node{ID: "decoys-up." + h, Action: "deception.decoy_check", Target: h,
			Needs: []string{"approve-deception"}, Risk: plan.RiskNone,
			Params: map[string]any{"ports": ports, "wait_sec": 30}})
	}
	for _, s := range c.HoneytokenSteps(hosts...) {
		params := map[string]any{}
		for k, v := range s.Params {
			params[k] = v
		}
		if s.OnlyIfAbsent {
			params["only_if_absent"] = true
		}
		if len(s.SecretParams) > 0 {
			sp := make([]any, len(s.SecretParams))
			for i, n := range s.SecretParams {
				sp[i] = n
			}
			refs := map[string]any{}
			for k, v := range s.SecretRefs {
				refs[k] = v
			}
			params["secret_params"], params["secret_refs"] = sp, refs
		}
		if s.Action == "ad.honey_account" {
			delete(params, "password")
		}
		p.Nodes = append(p.Nodes, plan.Node{ID: "plant." + s.Token, Action: s.Action, Target: s.Host,
			Needs: []string{"approve-deception"}, Risk: plan.Risk(s.Risk), Params: params, Note: s.Note})
	}
	if len(p.Nodes) == 1 {
		return plan.Plan{}, errors.New("deception plan: no decoys or honeytokens are declared for these hosts")
	}
	return p, nil
}

// attributeHoneytoken names the honeytoken and the looted host on an alert
// whose events involve one. The rules that fire on DC and service events
// (D15d honey logon, D15e Kerberos on a honey SPN or account) see only the
// account or SPN; the registry knows which token that is and where it was
// planted, so the operator reads "token planted on rocky-ecom" rather than a
// bare account name. Alerts that already carry token_origin (decoy hits, honey
// file reads) keep it.
func (c *Controller) attributeHoneytoken(e event.Event, k *alertKeys) {
	if k.Entities["token_origin"] != "" {
		return
	}
	cands := []map[string]any{}
	ents := map[string]any{}
	for n, v := range k.Entities {
		ents[n] = v
	}
	cands = append(cands, ents)
	if evs, ok := e.Fields["evidence"].([]any); ok {
		for _, v := range evs {
			if m, ok := v.(map[string]any); ok {
				if f, ok := m["fields"].(map[string]any); ok {
					cands = append(cands, f)
				}
			}
		}
	}
	for _, f := range cands {
		if t, ok := c.AttributeHoneytoken(f); ok {
			if k.Entities == nil {
				k.Entities = map[string]string{}
			}
			k.Entities["honeytoken"], k.Entities["token_origin"], k.Entities["token_kind"] = t.ID, t.Host, string(t.Kind)
			return
		}
	}
}
