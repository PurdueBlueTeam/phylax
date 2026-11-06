package controller

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// ledgerOpen reads the persisted breaker state for a key.
func ledgerOpen(c *Controller, host, object, kind string) (bool, error) {
	raw, err := c.st.MetaGet(ctx, autoLedgerKey(host, object, kind))
	if errors.Is(err, store.ErrNoMeta) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var l autoLedger
	if err := json.Unmarshal([]byte(raw), &l); err != nil {
		return false, err
	}
	return l.Open, nil
}

func TestLedgerHaltsAfterTwoAttempts(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nautonomy: {t1: auto}\n")
	c.opt.Probe = func(context.Context, string) error { return nil }
	setHeartbeat(c, "h1", false, time.Now())
	now := time.Now()
	c.now = func() time.Time { return now }
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); err != nil {
		t.Fatalf("first attempt: %v", err)
	}
	now = now.Add(9 * time.Minute)
	setHeartbeat(c, "h1", false, now)
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); err != nil {
		t.Fatalf("second attempt: %v", err)
	}
	if halted, err := ledgerOpen(c, "h1", "/etc/hosts", "t1"); !halted || err != nil {
		t.Fatalf("the ledger did not trip: %v %v", halted, err)
	}
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) || !strings.Contains(err.Error(), "halted") {
		t.Fatalf("got %v", err)
	}
	e, err := c.st.Latest(ctx, "controller", event.KindPlanFailed)
	if err != nil || e.Priority != event.PriorityCritical || e.Fields["reason"] != event.ReasonAutoHalted ||
		e.Fields["object"] != "/etc/hosts" || e.Fields["kind"] != "t1" || e.Fields["trigger"] != "repeat" {
		t.Fatalf("%+v %v", e, err)
	}
	if err := c.ReenableAuto(ctx, "h1", "/etc/hosts", "t1", "driver"); err != nil {
		t.Fatal(err)
	}
	rows, err := c.st.Audit(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.Action == "auto_reenable" && r.Actor == "driver" && strings.Contains(r.Detail, "t1 on h1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no audit row for the re-enabling operator: %+v", rows)
	}
	now = now.Add(time.Second)
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); err != nil {
		t.Fatalf("after re-enable: %v", err)
	}
}

func TestLedgerWindow(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nautonomy: {t1: auto}\n")
	now := time.Now()
	if _, opened, err := c.noteAutoAttempt(ctx, "h1", "/etc/hosts", "t1", now); err != nil || opened {
		t.Fatalf("first attempt: %v %v", opened, err)
	}
	if _, opened, err := c.noteAutoAttempt(ctx, "h1", "/etc/hosts", "t1", now.Add(11*time.Minute)); err != nil || opened {
		t.Fatalf("attempt outside the window opened the breaker: %v %v", opened, err)
	}
	halted, err := ledgerOpen(c, "h1", "/etc/hosts", "t1")
	if err != nil || halted {
		t.Fatalf("ledgerOpen = %v, %v; want false, nil", halted, err)
	}
	if _, err := c.st.MetaGet(ctx, autoLedgerKey("h1", "/etc/hosts", "t1")); err != nil {
		t.Fatalf("the attempt was not persisted: %v", err)
	}
}

func TestLedgerConcurrentAttempts(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nautonomy: {t1: auto}\n")
	c.opt.Probe = func(context.Context, string) error { return nil }
	// One frozen clock: every attempt is inside the ledger window, and the two
	// admitted attempts share one plan id, so at most one of them creates a plan.
	base := time.Now().UTC().Truncate(time.Second)
	c.now = func() time.Time { return base }
	setHeartbeat(c, "h1", false, base)

	const n = 16
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"})
		}(i)
	}
	close(start)
	wg.Wait()

	runs, admitted, refused := 0, 0, 0
	for i, err := range errs {
		switch {
		case err == nil:
			runs++
			admitted++
		case errors.Is(err, ErrPlanExists):
			// The other admitted attempt lost the shared plan id.
			admitted++
		case errors.Is(err, module.ErrProposed) && strings.Contains(err.Error(), "halted"):
			refused++
		default:
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if admitted != 2 || runs > 2 || refused != n-2 {
		t.Fatalf("admitted=%d runs=%d refused=%d, want 2, <=2 and %d", admitted, runs, refused, n-2)
	}
	if open, err := ledgerOpen(c, "h1", "/etc/hosts", "t1"); err != nil || !open {
		t.Fatalf("ledger open=%v, %v; want true", open, err)
	}
	evs, err := c.st.Events(ctx, store.Query{Agent: ControllerAgent, Kind: event.KindPlanFailed, Limit: n})
	if err != nil {
		t.Fatal(err)
	}
	halted := 0
	for _, e := range evs {
		if e.Fields["reason"] == event.ReasonAutoHalted {
			halted++
		}
	}
	if halted != 1 {
		t.Fatalf("plan.failed{auto_halted} emitted %d times, want 1", halted)
	}
}
