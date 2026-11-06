package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// Restore epoch handling (design: Controller recovery; review R7). A restore
// raises the epoch, and a second restore from the same or an older snapshot
// would produce the same epoch again, which agents that accepted it from the
// first restored controller refuse. So the restored controller waits for every
// agent enrolled in the snapshot to report its highest accepted epoch in
// hello, raises the epoch above all of them, and signs nothing until then.

// restoreWaitKey is the store's kv key holding the hosts a restored controller
// is still waiting to hear from, so a restart during the wait keeps waiting.
const restoreWaitKey = "restore_wait"

// SigningReady reports whether the controller may sign, and the hosts it is
// still waiting for after a restore. Signing waits until every agent enrolled
// in the snapshot has reported its epoch in hello, or an operator released it.
func (c *Controller) SigningReady() (ready bool, waiting []string) {
	c.rwmu.Lock()
	defer c.rwmu.Unlock()
	if len(c.restoreWait) == 0 {
		return true, nil
	}
	out := make([]string, 0, len(c.restoreWait))
	for h := range c.restoreWait {
		out = append(out, h)
	}
	sort.Strings(out)
	return false, out
}

// signingWaitErr refuses a signing call while a restored controller waits.
func (c *Controller) signingWaitErr() error {
	if ready, waiting := c.SigningReady(); !ready {
		return fmt.Errorf("controller: restored: waiting for %d agents: %s", len(waiting), strings.Join(waiting, ", "))
	}
	return nil
}

// ReleaseRestoreWait ends the wait for the named agents (all when none are
// named), recording the epoch in force and the operator in the audit trail.
func (c *Controller) ReleaseRestoreWait(ctx context.Context, by string, hosts ...string) error {
	release := append([]string(nil), hosts...)
	if len(release) == 0 {
		c.rwmu.Lock()
		for h := range c.restoreWait {
			release = append(release, h)
		}
		c.rwmu.Unlock()
	}
	c.rwmu.Lock()
	changed := false
	for _, h := range release {
		if c.restoreWait[h] {
			delete(c.restoreWait, h)
			changed = true
		}
	}
	c.rwmu.Unlock()
	if changed {
		if err := c.persistRestoreWait(ctx); err != nil {
			return err
		}
	}
	ep, err := c.st.Epoch(ctx)
	if err != nil {
		return err
	}
	sort.Strings(release)
	return c.st.AppendAudit(ctx, store.AuditRow{Time: c.now(), Actor: by, Action: "restore_wait_release",
		Detail: fmt.Sprintf("epoch %d released %s", ep, strings.Join(release, ", "))})
}

// loadRestoreWait restores the wait set: the store's kv record when a restart
// interrupted one, else the agents whose row records a restore. A normal start
// has no such agent and nothing to wait for.
func (c *Controller) loadRestoreWait(ctx context.Context) error {
	wait := map[string]bool{}
	v, err := c.st.MetaGet(ctx, restoreWaitKey)
	switch {
	case err == nil:
		for _, h := range strings.Split(v, "\n") {
			if h != "" {
				wait[h] = true
			}
		}
	case !errors.Is(err, store.ErrNoMeta):
		return err
	default:
		agents, err := c.st.Agents(ctx)
		if err != nil {
			return err
		}
		for _, a := range agents {
			// The controller's own event chain is not a host.
			if a.RestoredSeq > 0 && a.ID != ControllerAgent {
				wait[a.ID] = true
			}
		}
	}
	c.rwmu.Lock()
	c.restoreWait = wait
	c.rwmu.Unlock()
	if len(wait) == 0 {
		return nil
	}
	return c.persistRestoreWait(ctx)
}

// noteRestoreReport handles an agent's hello during a restore wait: a reported
// epoch at or above the current one raises the controller above it, and the
// host stops blocking signing.
func (c *Controller) noteRestoreReport(ctx context.Context, h *link.Hello) error {
	if ready, _ := c.SigningReady(); ready {
		return nil // no wait in effect: a normal start, nothing to fence
	}
	ep, err := c.st.Epoch(ctx)
	if err != nil {
		return err
	}
	if h.Epoch >= ep {
		if _, err := c.st.RaiseEpoch(ctx, h.Epoch+1, fmt.Sprintf("agent reported epoch %d", h.Epoch)); err != nil {
			return err
		}
	}
	c.rwmu.Lock()
	delete(c.restoreWait, h.Host)
	c.rwmu.Unlock()
	return c.persistRestoreWait(ctx)
}

// persistRestoreWait writes the remaining hosts to the kv key, or clears it
// when nobody is left.
func (c *Controller) persistRestoreWait(ctx context.Context) error {
	ready, waiting := c.SigningReady()
	if ready {
		return c.st.MetaDelete(ctx, restoreWaitKey)
	}
	return c.st.MetaSet(ctx, restoreWaitKey, strings.Join(waiting, "\n"))
}
