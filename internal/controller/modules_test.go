package controller

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/module"
)

type flakyMod struct {
	ctlMod
	starts *atomic.Int32
}

func (f flakyMod) Start(ctx context.Context, h module.Host) error {
	if f.starts.Add(1) == 1 {
		panic("first start fails")
	}
	<-ctx.Done()
	return nil
}

func TestRunModulesEnablement(t *testing.T) {
	c := newTestControllerWithManifest(t, map[string]string{"modules/ctltest.yml": "enabled: true\n", "modules/offmod.yml": "enabled: false\n"})
	off := testMod()
	off.m.Name = "offmod"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.RunModules(ctx, []module.ControllerModule{testMod(), off}) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		h := c.ModuleHealth()
		if h["ctltest"].State == module.StateOK && h["offmod"].State == module.StateDisabled {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("health did not settle: %+v", h)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("RunModules did not return")
	}
}

func TestRunModulesRestartsAfterPanic(t *testing.T) {
	c := newTestControllerWithManifest(t, map[string]string{"modules/ctltest.yml": "enabled: true\n"})
	c.modBackoffMin = 10 * time.Millisecond
	f := flakyMod{testMod(), new(atomic.Int32)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.RunModules(ctx, []module.ControllerModule{f})
	deadline := time.Now().Add(3 * time.Second)
	for {
		h := c.ModuleHealth()["ctltest"]
		if f.starts.Load() == 2 && h.State == module.StateOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("starts %d, health %+v", f.starts.Load(), h)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type panicHealthMod struct{ ctlMod }

func (panicHealthMod) Health() module.Health { panic("health exploded") }

func TestModuleHealthRecoversPanic(t *testing.T) {
	c := newTestControllerWithManifest(t, map[string]string{"modules/ctltest.yml": "enabled: true\n"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.RunModules(ctx, []module.ControllerModule{panicHealthMod{testMod()}})
	deadline := time.Now().Add(2 * time.Second)
	for {
		h := c.ModuleHealth()["ctltest"]
		found := false
		for _, gap := range h.Gaps {
			if gap.What == "health" && gap.Why == "panic: health exploded" {
				found = true
			}
		}
		if found && h.State == module.StateError && c.moduleRunning("ctltest") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("health panic not recovered: %+v running=%v", h, c.moduleRunning("ctltest"))
		}
		time.Sleep(10 * time.Millisecond)
	}
}
