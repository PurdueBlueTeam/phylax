package enroll

import (
	"context"
	"sync"
)

// PushResult is one target's outcome, in the input order.
type PushResult struct {
	Target Target
	Err    error
}

// PushAll runs push for every target with at most parallel (default 8) at
// once and returns one result per target in input order. One failure does not
// stop the others.
func PushAll(ctx context.Context, targets []Target, parallel int, push func(context.Context, Target) error) []PushResult {
	if parallel <= 0 {
		parallel = 8
	}
	if parallel > len(targets) {
		parallel = len(targets)
	}
	results := make([]PushResult, len(targets))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t Target) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = PushResult{Target: t, Err: push(ctx, t)}
		}(i, t)
	}
	wg.Wait()
	return results
}
