package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/store"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

// Controller-side execution of plan nodes whose action is a network-device
// (palo.*, vyos.*) or Splunk (splunk.*) action. Such a node's Target is the
// device name (or the Splunk host) and no agent is involved: the controller
// runs the action on an actions.Env backed by the Directory. There is no
// signed step or signed result (the controller is both ends); the result is
// recorded unsigned. Rollback is the device protocol's own (devices.SafeChange
// reverts a failed change before returning), so no dead-man is armed.

const ackAction = "plan.ack_console"

// DeviceExecOptions turns on controller-side device and Splunk execution.
type DeviceExecOptions struct {
	DirectoryOptions
	// Timeout bounds one node phase (default 10m: a PAN-OS commit can be slow).
	Timeout time.Duration
}

type devExec struct {
	c       *Controller
	dir     *Directory
	locks   *actions.Locks
	timeout time.Duration
	vault   VaultStore

	mu   sync.Mutex
	acks map[string]bool
}

// isLocalAction reports whether an action runs on the controller, by its
// Spec (not its name): API-only actions do; filesystem actions on a Splunk
// host (splunk.sidecar_off) run on that host's agent.
func (c *Controller) isLocalAction(name string) bool {
	a, err := c.reg.Get(name)
	return err == nil && a.Spec().OnController()
}

func needsConsoleAck(reg *actions.Registry, name string) bool {
	a, err := reg.Get(name)
	return err == nil && a.Spec().NeedsConsoleAck
}

// EnableDeviceExec switches on controller-side execution of device and Splunk
// nodes. It returns the Directory (for rotations that must drop pooled
// adapters).
func (c *Controller) EnableDeviceExec(opt DeviceExecOptions) (*Directory, error) {
	x := &devExec{c: c, locks: actions.NewLocks(), timeout: opt.Timeout, vault: opt.Vault, acks: map[string]bool{}}
	if x.timeout <= 0 {
		x.timeout = 10 * time.Minute
	}
	opt.Acked = x.acked
	dir, err := NewDirectory(opt.DirectoryOptions)
	if err != nil {
		return nil, err
	}
	x.dir = dir
	c.dx.Store(x)
	return dir, nil
}

func (c *Controller) isLocalNode(n plan.Node) bool {
	return !n.Gate && c.dx.Load() != nil && c.isLocalAction(n.Action)
}

func ackKey(planID, node string) string { return planID + "/" + node }

func ackDetail(planID, node, device string) string {
	return "plan=" + planID + " node=" + node + " device=" + device
}

// acked reports whether the node has a console acknowledgement: remembered in
// memory, else found in the audit log (the CLI writes there from another
// process).
func (x *devExec) acked(ctx context.Context, planID, node string) bool {
	k := ackKey(planID, node)
	x.mu.Lock()
	ok := x.acks[k]
	x.mu.Unlock()
	if ok {
		return true
	}
	rows, err := x.c.st.Audit(ctx, 5000)
	if err != nil {
		return false
	}
	prefix := "plan=" + planID + " node=" + node + " "
	for _, r := range rows {
		if r.Action == ackAction && strings.HasPrefix(r.Detail, prefix) {
			x.mu.Lock()
			x.acks[k] = true
			x.mu.Unlock()
			return true
		}
	}
	return false
}

func ackTarget(reg *actions.Registry, p *plan.Plan, node string) (string, error) {
	for _, n := range p.Nodes {
		if n.ID != node {
			continue
		}
		if n.Gate || !needsConsoleAck(reg, n.Action) {
			return "", fmt.Errorf("node %q (%s) does not need a console acknowledgement", node, n.Action)
		}
		return n.Target, nil
	}
	return "", fmt.Errorf("plan %s has no node %q", p.ID, node)
}

func recordAck(ctx context.Context, st *store.Store, now time.Time, planID, node, device, operator, remote string) error {
	return st.AppendAudit(ctx, store.AuditRow{Time: now, Actor: operator, Action: ackAction, Remote: remote,
		Detail: ackDetail(planID, node, device) + " (console access to the device confirmed by the Network role)"})
}

// AckConsole records that the Network role confirmed console access to the
// device a plan node targets, which lets a lockout-risk change run on a device
// with no dead-man switch. The operator is mandatory and the acknowledgement is
// written to the audit log. It applies to this plan node only.
func (c *Controller) AckConsole(ctx context.Context, planID, nodeID, operator string) error {
	if strings.TrimSpace(operator) == "" {
		return errors.New("controller: console acknowledgement needs an operator name")
	}
	rt, err := c.plan(planID)
	if err != nil {
		return err
	}
	rt.mu.Lock()
	state, p := rt.state, rt.p
	rt.mu.Unlock()
	if state == PlanSucceeded || state == PlanFailed || state == PlanRolledBack {
		return ErrPlanState
	}
	dev, err := ackTarget(c.reg, p, nodeID)
	if err != nil {
		return err
	}
	if err := recordAck(ctx, c.st, c.now(), planID, nodeID, dev, operator, "controller"); err != nil {
		return err
	}
	if x := c.dx.Load(); x != nil {
		x.mu.Lock()
		x.acks[ackKey(planID, nodeID)] = true
		x.mu.Unlock()
	}
	c.log.Info("console acknowledged", "plan", planID, "node", nodeID, "device", dev, "operator", operator)
	return nil
}

// AckConsoleStored records the same acknowledgement from outside the running
// controller (the `phylax plan ack-console` CLI), straight into the store the
// controller reads.
func AckConsoleStored(ctx context.Context, st *store.Store, planID, nodeID, operator string) error {
	if strings.TrimSpace(operator) == "" {
		return errors.New("console acknowledgement needs an operator name")
	}
	row, err := st.Plan(ctx, planID)
	if err != nil {
		return fmt.Errorf("plan %q: %w", planID, err)
	}
	switch row.State {
	case PlanSucceeded, PlanFailed, PlanRolledBack:
		return ErrPlanState
	}
	var body planBody
	if err := json.Unmarshal([]byte(row.Body), &body); err != nil || body.Plan == nil {
		return fmt.Errorf("plan %q: unreadable body", planID)
	}
	dev, err := ackTarget(actions.Core(), body.Plan, nodeID)
	if err != nil {
		return err
	}
	return recordAck(ctx, st, time.Now(), planID, nodeID, dev, operator, "cli")
}

// ---- running a node ----

func (x *devExec) env(host string) *actions.Env {
	env := &actions.Env{Host: host, Registry: x.c.reg, Locks: x.locks,
		Win: actions.WinEnv{Devices: x.dir, Splunk: x.dir}}
	if x.c.opt.Guard != nil {
		env.Guard = x.c.opt.Guard(host)
	}
	return env
}

type localOut struct {
	outcome string
	err     string
	detail  []byte
	diff    string
	done    bool
}

func (x *devExec) clean(err error) string {
	s := x.dir.Redact(err.Error())
	if len(s) > 4000 {
		s = s[:4000]
	}
	return s
}

// exec runs one phase of a node with the device lock held.
func (x *devExec) exec(ctx context.Context, planID string, n plan.Node, phase string) localOut {
	release, err := x.dir.Lock(ctx, n.Target)
	if err != nil {
		return localOut{outcome: plan.OutcomeFailed, err: x.clean(err)}
	}
	defer release()
	ctx = actions.WithTag(ctx, actions.Tag{Plan: planID, Node: n.ID})
	env := x.env(n.Target)
	req := actions.Request{Action: n.Action, Params: n.Params, NodeID: nodeKey(planID, n.ID), Deadman: actions.NoDeadman}
	fail := func(err error) localOut { return localOut{outcome: plan.OutcomeFailed, err: x.clean(err)} }
	switch phase {
	case plan.PhaseCheck:
		req.DryRun = true
		o, err := env.Execute(ctx, req)
		if err != nil {
			return fail(err)
		}
		return localOut{outcome: plan.OutcomeChecked, diff: x.dir.Redact(o.Plan.Diff), done: o.Plan.Done}
	case plan.PhaseApply:
		o, err := env.Execute(ctx, req)
		if err != nil {
			return fail(err)
		}
		note := x.keepSecrets(planID, n.ID, o.Output)
		d, _ := json.Marshal(map[string]any{"done": o.Plan.Done, "changed": o.Changed, "diff": x.dir.Redact(o.Plan.Diff),
			"notes": o.Plan.Notes, "risk": o.Risk, "output": publicOutput(x.dir, o.Output), "secrets": note})
		return localOut{outcome: plan.OutcomeApplied, detail: d}
	case plan.PhaseVerify:
		a, err := x.c.reg.Get(n.Action)
		if err != nil {
			return fail(err)
		}
		p, err := a.Spec().Validate(n.Params)
		if err == nil {
			err = a.Verify(ctx, env, p)
		}
		if err != nil {
			return fail(fmt.Errorf("verify: %w", err))
		}
		return localOut{outcome: plan.OutcomeVerified}
	case plan.PhaseRollback:
		return fail(errors.New("device and Splunk changes are not rolled back by the controller after they are applied: SafeChange already reverted a failed change; undo a verified one with a new plan"))
	}
	return fail(fmt.Errorf("unknown phase %q", phase))
}

// publicOutput drops secret outputs (and redacts the rest).
func publicOutput(d *Directory, o actions.Output) map[string]string {
	out := map[string]string{}
	for k, v := range o {
		if strings.HasPrefix(k, "secret.") {
			continue
		}
		out[k] = d.Redact(v)
	}
	return out
}

// keepSecrets stores "secret.*" outputs (a new HEC token, say) in the vault and
// returns the vault names; the value itself goes nowhere else.
func (x *devExec) keepSecrets(planID, node string, o actions.Output) []string {
	var names []string
	keys := make([]string, 0, len(o))
	for k := range o {
		if strings.HasPrefix(k, "secret.") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		sec := vault.NewSecretString(o[k])
		x.dir.track(sec)
		name := "out/" + planID + "/" + node + "/" + strings.TrimPrefix(k, "secret.")
		if x.vault == nil {
			names = append(names, "NOT STORED (no vault): "+k)
			continue
		}
		if _, err := x.vault.Put(name, sec, "plan output of "+planID+"/"+node); err != nil {
			names = append(names, "NOT STORED ("+x.dir.Redact(err.Error())+"): "+k)
			continue
		}
		names = append(names, "vault:"+name)
	}
	return names
}

// localCheck is the dry-run check of a controller-side node.
func (c *Controller) localCheck(ctx context.Context, planID string, n plan.Node) (plan.NodeCheck, bool) {
	if !c.isLocalNode(n) {
		return plan.NodeCheck{}, false
	}
	x := c.dx.Load()
	cctx, cancel := context.WithTimeout(ctx, x.timeout)
	defer cancel()
	r := x.exec(cctx, planID, n, plan.PhaseCheck)
	if r.outcome != plan.OutcomeChecked {
		return plan.NodeCheck{NodeID: n.ID, LintReject: r.err}, true
	}
	return plan.NodeCheck{NodeID: n.ID, WillChange: !r.done, Diff: r.diff}, true
}

// dispatchLocalLocked runs a node phase on the controller (rt.mu held).
func (rt *planRT) dispatchLocalLocked(id string, nr *nodeRT, n plan.Node) {
	c := rt.c
	x := c.dx.Load()
	phase := nr.want
	nr.inflight, nr.want = true, ""
	// Recorded before the change starts: after a controller crash an apply with
	// no result is reported failed (unknown), never applied twice.
	nr.cur = &inflightRec{Phase: phase, Digest: "controller-local"}
	if err := rt.persistLocked(context.Background()); err != nil {
		nr.inflight, nr.cur = false, nil
		rt.failLocked(id, "cannot persist the plan: "+err.Error(), phase)
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				rt.localDone(id, phase, localOut{outcome: plan.OutcomeFailed, err: fmt.Sprintf("controller panic: %v", r)})
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), x.timeout)
		defer cancel()
		rt.localDone(id, phase, x.exec(ctx, rt.p.ID, n, phase))
	}()
}

func (rt *planRT) localDone(id, phase string, r localOut) {
	c := rt.c
	if c.closed.Load() {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	pr := phaseRec{Phase: phase, Outcome: r.outcome, Error: r.err, AtMS: c.now().UnixMilli(), Detail: string(r.detail)}
	rt.onResultLocked(id, pr)
}
