package controller

// Controller-side execution of plan nodes whose action runs on the controller
// (Spec.Runs == actions.RunsController): API-only actions such as the device
// and Splunk ones, and every module action that runs here. The executor is
// installed by New, so a controller-side action runs whether or not a device
// directory was set up; device and Splunk actions without one fail with
// "no device directory". There is no signed step or signed result (the
// controller is both ends); the result is recorded unsigned. Rollback is the
// device protocol's own (devices.SafeChange reverts a failed change before
// returning), so no dead-man is armed.

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
	"github.com/PurdueBlueTeam/phylax/internal/devices/palo"
	"github.com/PurdueBlueTeam/phylax/internal/devices/vyos"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

// errNoDeviceDir is what a device or Splunk action gets when the controller
// has no directory (no -vault, so no credentials and no adapters).
var errNoDeviceDir = errors.New("no device directory")

type devExec struct {
	c       *Controller
	locks   *actions.Locks
	timeout time.Duration

	mu    sync.Mutex
	dir   *Directory // nil until EnableDeviceExec
	vault VaultStore
	acks  map[string]bool
}

func newDevExec(c *Controller, opt Options) *devExec {
	return &devExec{c: c, locks: actions.NewLocks(), timeout: 10 * time.Minute, vault: opt.Vault, acks: map[string]bool{}}
}

// attach installs the device directory created by EnableDeviceExec.
func (x *devExec) attach(dir *Directory, timeout time.Duration, v VaultStore) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.dir = dir
	if timeout > 0 {
		x.timeout = timeout
	}
	if v != nil {
		x.vault = v
	}
}

func (x *devExec) directory() *Directory {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.dir
}

func (x *devExec) phaseTimeout() time.Duration {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.timeout
}

func (x *devExec) vaultStore() VaultStore {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.vault
}

func (x *devExec) isLocalNode(n plan.Node) bool {
	return !n.Gate && x.c.isLocalAction(n.Action)
}

// isLocalNode reports whether the node runs on the controller.
func (c *Controller) isLocalNode(n plan.Node) bool {
	x := c.dx
	return x != nil && x.isLocalNode(n)
}

// noDeviceDirectory stands in for a missing Directory so a device or Splunk
// action fails with a clear error instead of a nil dereference.
type noDeviceDirectory struct{}

func (noDeviceDirectory) Palo(context.Context, string) (*palo.Adapter, error) {
	return nil, errNoDeviceDir
}
func (noDeviceDirectory) VyOS(context.Context, string) (*vyos.Adapter, error) {
	return nil, errNoDeviceDir
}
func (noDeviceDirectory) PaloIntent(context.Context, string) (*render.PaloIntent, error) {
	return nil, errNoDeviceDir
}
func (noDeviceDirectory) VyOSIntent(context.Context, string) (*render.VyOSIntent, error) {
	return nil, errNoDeviceDir
}
func (noDeviceDirectory) ConsoleAck(context.Context, string) bool { return false }
func (noDeviceDirectory) Client(context.Context, string) (actions.SplunkAPI, error) {
	return nil, errNoDeviceDir
}

func (x *devExec) env(host string) *actions.Env {
	env := &actions.Env{Host: host, Registry: x.c.reg, Locks: x.locks, Probe: x.c.opt.Probe}
	if d := x.directory(); d != nil {
		env.Win = actions.WinEnv{Devices: d, Splunk: d}
	} else {
		nd := noDeviceDirectory{}
		env.Win = actions.WinEnv{Devices: nd, Splunk: nd}
	}
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

func (x *devExec) redact(s string) string {
	if d := x.directory(); d != nil {
		return d.Redact(s)
	}
	return s
}

func (x *devExec) clean(err error) string {
	s := x.redact(err.Error())
	if len(s) > 4000 {
		s = s[:4000]
	}
	return s
}

// exec runs one phase of a node and records its agent.step_result.
func (x *devExec) exec(ctx context.Context, planID string, class plan.ApprovalClass, n plan.Node, phase string) localOut {
	r := x.runPhase(ctx, planID, n, phase)
	x.stepResult(ctx, planID, class, n, phase, r)
	return r
}

// runPhase runs one phase of a node with the device lock held (when there is a
// device directory).
func (x *devExec) runPhase(ctx context.Context, planID string, n plan.Node, phase string) localOut {
	if d := x.directory(); d != nil {
		release, err := d.Lock(ctx, n.Target)
		if err != nil {
			return localOut{outcome: plan.OutcomeFailed, err: x.clean(err)}
		}
		defer release()
	}
	ctx = actions.WithTag(ctx, actions.Tag{Plan: planID, Node: n.ID})
	env := x.env(n.Target)
	req := actions.Request{Action: n.Action, Params: n.ActionParams(), NodeID: nodeKey(planID, n.ID), Deadman: actions.NoDeadman}
	fail := func(err error) localOut { return localOut{outcome: plan.OutcomeFailed, err: x.clean(err)} }
	switch phase {
	case plan.PhaseCheck:
		req.DryRun = true
		o, err := env.Execute(ctx, req)
		if err != nil {
			return fail(err)
		}
		return localOut{outcome: plan.OutcomeChecked, diff: x.redact(o.Plan.Diff), done: o.Plan.Done}
	case plan.PhaseApply:
		o, err := env.Execute(ctx, req)
		if err != nil {
			return fail(err)
		}
		note := x.keepSecrets(planID, n.ID, o.Output)
		d, _ := json.Marshal(map[string]any{"done": o.Plan.Done, "changed": o.Changed, "diff": x.redact(o.Plan.Diff),
			"notes": o.Plan.Notes, "risk": o.Risk, "output": x.publicOutput(o.Output), "secrets": note})
		return localOut{outcome: plan.OutcomeApplied, detail: d}
	case plan.PhaseVerify:
		a, err := x.c.reg.Get(n.Action)
		if err != nil {
			return fail(err)
		}
		p, err := a.Spec().Validate(n.ActionParams())
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

// stepResult emits agent.step_result (agent "controller") for a finished phase.
func (x *devExec) stepResult(ctx context.Context, planID string, class plan.ApprovalClass, n plan.Node, phase string, r localOut) {
	e, err := event.New("agent.step_result", event.AgentStepResult{
		Plan: planID, Node: n.ID, Host: n.Target, Phase: phase, Outcome: r.outcome, Error: r.err, Class: string(class)})
	if err != nil {
		x.c.log.Error("cannot build the step result event", "plan", planID, "node", n.ID, "err", err)
		return
	}
	if _, err := x.c.EmitController(context.WithoutCancel(ctx), e); err != nil {
		x.c.log.Error("cannot emit the step result event", "plan", planID, "node", n.ID, "err", err)
	}
}

// publicOutput drops secret outputs (and redacts the rest).
func (x *devExec) publicOutput(o actions.Output) map[string]string {
	out := map[string]string{}
	for k, v := range o {
		if strings.HasPrefix(k, "secret.") {
			continue
		}
		out[k] = x.redact(v)
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
		if d := x.directory(); d != nil {
			d.track(sec)
		}
		name := "out/" + planID + "/" + node + "/" + strings.TrimPrefix(k, "secret.")
		v := x.vaultStore()
		if v == nil {
			names = append(names, "NOT STORED (no vault): "+k)
			continue
		}
		if _, err := v.Put(name, sec, "plan output of "+planID+"/"+node); err != nil {
			names = append(names, "NOT STORED ("+x.redact(err.Error())+"): "+k)
			continue
		}
		names = append(names, "vault:"+name)
	}
	return names
}

// localCheck is the dry-run check of a controller-side node.
func (c *Controller) localCheck(ctx context.Context, planID string, class plan.ApprovalClass, n plan.Node) (plan.NodeCheck, bool) {
	x := c.dx
	if x == nil || !x.isLocalNode(n) {
		return plan.NodeCheck{}, false
	}
	cctx, cancel := context.WithTimeout(ctx, x.phaseTimeout())
	defer cancel()
	r := x.exec(cctx, planID, class, n, plan.PhaseCheck)
	if r.outcome != plan.OutcomeChecked {
		return plan.NodeCheck{NodeID: n.ID, LintReject: r.err}, true
	}
	return plan.NodeCheck{NodeID: n.ID, WillChange: !r.done, Diff: r.diff}, true
}

// dispatchLocalLocked runs a node phase on the controller (rt.mu held).
func (rt *planRT) dispatchLocalLocked(id string, nr *nodeRT, n plan.Node) {
	c := rt.c
	x := c.dx
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
		ctx, cancel := context.WithTimeout(context.Background(), x.phaseTimeout())
		defer cancel()
		rt.localDone(id, phase, x.exec(ctx, rt.p.ID, rt.p.Class, n, phase))
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
