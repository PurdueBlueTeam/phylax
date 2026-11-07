package controller

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// lockedEvery is how often the critical controller.locked alarm is re-emitted
// while signing stays locked, so notify keeps ringing.
const lockedEvery = 5 * time.Minute

// lockedStopped is what a locked controller does not do. One list feeds the
// event, the banner and the Overview tile.
var lockedStopped = []string{"auto plans", "facts", "deadman_confirm", "safe_mode toggles", "snapshots"}

// ErrLocked is returned while plan signing is locked after a restart.
var ErrLocked = errors.New("controller: plan signing is locked; enter the operator passphrase to unlock")

// requireUnlocked refuses a signing path while the controller is locked.
func (c *Controller) requireUnlocked() error {
	if locked, _ := c.Locked(); locked {
		return ErrLocked
	}
	return nil
}

// lockState is the one flag behind the banner, the alarm, the snapshot writer
// and the dead-man confirm check.
type lockState struct {
	mu    sync.Mutex
	on    bool
	since time.Time
}

// setLocked records the locked state; it is called once at start.
func (c *Controller) setLocked(on bool) {
	c.lock.mu.Lock()
	defer c.lock.mu.Unlock()
	if c.lock.on == on {
		return
	}
	c.lock.on = on
	if on {
		c.lock.since = c.now()
	} else {
		c.lock.since = time.Time{}
	}
}

// Locked reports whether plan signing is locked (a vault exists and no
// passphrase has been entered since start), and since when.
func (c *Controller) Locked() (locked bool, since time.Time) {
	c.lock.mu.Lock()
	defer c.lock.mu.Unlock()
	return c.lock.on, c.lock.since
}

// Unlock is the operator passphrase entry. On success it clears the flag; the
// controller.locked alarm is then not repeated.
func (c *Controller) Unlock(pass []byte) error {
	c.lock.mu.Lock()
	v := c.opt.Vault
	c.lock.mu.Unlock()
	if v == nil {
		return errors.New("controller: no vault to unlock")
	}
	if u, ok := v.(interface{ Unlock([]byte) error }); ok {
		if err := u.Unlock(pass); err != nil {
			return err
		}
	}
	if u, ok := v.(interface{ Locked() bool }); ok && u.Locked() {
		return errors.New("controller: vault is still locked")
	}
	c.setSnapshotPass(pass)
	c.setLocked(false)
	return nil
}

// emitLocked puts one critical controller.locked event on the controller chain.
func (c *Controller) emitLocked(ctx context.Context, since time.Time) {
	e, err := event.New(event.KindControllerLocked, event.ControllerLocked{
		Since:   since.UTC().Format(time.RFC3339),
		Stopped: append([]string(nil), lockedStopped...),
	})
	if err != nil {
		c.log.Error("cannot build controller.locked", "err", err)
		return
	}
	e.Priority = event.PriorityCritical
	if _, err := c.EmitController(ctx, e); err != nil {
		c.log.Error("cannot emit controller.locked", "err", err)
	}
}

// lockedLoop re-emits the alarm every five minutes until the controller is
// unlocked. Serve starts it when the controller starts locked.
func (c *Controller) lockedLoop(ctx context.Context) {
	t := c.clk.NewTicker(lockedEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
			locked, since := c.Locked()
			if !locked {
				return
			}
			c.emitLocked(ctx, since)
		}
	}
}
