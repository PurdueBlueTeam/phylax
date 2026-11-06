package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// Device and Splunk setup for controller-side execution: the Directory (the
// pooled adapters and their credentials) and the console acknowledgements.
// The executor itself is in exec.go.

const ackAction = "plan.ack_console"

// DeviceExecOptions turns on controller-side device and Splunk execution.
type DeviceExecOptions struct {
	DirectoryOptions
	// Timeout bounds one node phase (default 10m: a PAN-OS commit can be slow).
	Timeout time.Duration
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
	x := c.dx.Load()
	if x == nil {
		return nil, errors.New("controller: the executor is not installed")
	}
	opt.Acked = x.acked
	dir, err := NewDirectory(opt.DirectoryOptions)
	if err != nil {
		return nil, err
	}
	x.attach(dir, opt.Timeout, opt.Vault)
	return dir, nil
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
