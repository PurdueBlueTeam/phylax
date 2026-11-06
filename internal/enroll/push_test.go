package enroll

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
)

func TestPushAllBounded(t *testing.T) {
	var live, maxLive atomic.Int32
	failed := map[string]bool{}
	push := func(ctx context.Context, t Target) error {
		n := live.Add(1)
		defer live.Add(-1)
		for {
			m := maxLive.Load()
			if n <= m || maxLive.CompareAndSwap(m, n) {
				break
			}
		}
		if t.Host == "h7" {
			return errors.New("boom")
		}
		return nil
	}
	targets := make([]Target, 20)
	for i := range targets {
		targets[i] = Target{Host: fmt.Sprintf("h%d", i)}
	}
	res := PushAll(context.Background(), targets, 4, push)
	if len(res) != len(targets) {
		t.Fatalf("%d results for %d targets", len(res), len(targets))
	}
	if m := maxLive.Load(); m > 4 {
		t.Fatalf("max concurrency = %d, want <= 4", m)
	}
	for i, r := range res {
		if r.Target.Host != targets[i].Host {
			t.Fatalf("result %d is for %s, want %s (input order)", i, r.Target.Host, targets[i].Host)
		}
		if r.Target.Host == "h7" && r.Err == nil {
			t.Fatal("h7's failure was lost")
		}
		if r.Err != nil {
			failed[r.Target.Host] = true
		}
	}
	if len(failed) != 1 {
		t.Fatalf("failed hosts = %v, want only h7", failed)
	}
	if live.Load() != 0 {
		t.Fatalf("%d pushes still running after PushAll returned", live.Load())
	}
}
