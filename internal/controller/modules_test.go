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
	t.Skip("unimplemented: W1 Task 19")
	c := newTestControllerWithManifest(t, map[string]string{"modules/ctltest.yml": "enabled: true\n", "modules/offmod.yml": "enabled: false\n"})
	off := testMod()
	off.m.Name = "offmod"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.RunModules(ctx, []module.ControllerModule{testMod(), off}) }()
	// poll up to 2 s: c.ModuleHealth()["ctltest"].State == module.StateOK and ["offmod"].State == module.StateDisabled
	cancel()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("RunModules did not return")
	}
}

func TestRunModulesRestartsAfterPanic(t *testing.T) {
	t.Skip("unimplemented: W1 Task 19")
	c := newTestControllerWithManifest(t, map[string]string{"modules/ctltest.yml": "enabled: true\n"})
	c.modBackoffMin = 10 * time.Millisecond
	f := flakyMod{testMod(), new(atomic.Int32)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.RunModules(ctx, []module.ControllerModule{f})
	// poll up to 3 s: f.starts.Load() == 2 && c.ModuleHealth()["ctltest"].State == module.StateOK
}
