package actions

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Named per-host resource locks (design: Locks).
const (
	LockFirewall = "firewall"
	LockAccounts = "accounts"
	LockSSHD     = "sshd"
	LockPackages = "packages"
	LockAudit    = "audit"
	// LockAgent is the agent binary and its service (agent.replace_binary,
	// agent.rename): one swap at a time, so the verified copy cannot be
	// overwritten under a running helper.
	LockAgent = "agent"
)

// LockService is the lock name for one service/unit.
func LockService(unit string) string { return "service:" + strings.TrimSuffix(unit, ".service") }

// Locks is a set of named locks for one host. Plan nodes and tier-0 responses
// use the same set and the same names. Locks are context-aware.
type Locks struct {
	mu   sync.Mutex
	held map[string]chan struct{}
}

func NewLocks() *Locks { return &Locks{held: map[string]chan struct{}{}} }

func (l *Locks) ch(name string) chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.held[name]
	if c == nil {
		c = make(chan struct{}, 1)
		l.held[name] = c
	}
	return c
}

func dedupSorted(names []string) []string {
	s := append([]string(nil), names...)
	sort.Strings(s)
	out := s[:0]
	for i, n := range s {
		if i == 0 || n != s[i-1] {
			out = append(out, n)
		}
	}
	return out
}

// Acquire takes all names (in sorted order, so concurrent callers cannot
// deadlock) and returns the release function. It gives up when ctx is done.
func (l *Locks) Acquire(ctx context.Context, names ...string) (func(), error) {
	names = dedupSorted(names)
	var got []chan struct{}
	release := func() {
		for i := len(got) - 1; i >= 0; i-- {
			<-got[i]
		}
	}
	for _, n := range names {
		c := l.ch(n)
		select {
		case c <- struct{}{}:
			got = append(got, c)
		case <-ctx.Done():
			release()
			return nil, fmt.Errorf("waiting for lock %q: %w", n, ctx.Err())
		}
	}
	var once sync.Once
	return func() { once.Do(release) }, nil
}

// TryAcquire is Acquire without waiting. busy names the first lock that is held.
func (l *Locks) TryAcquire(names ...string) (release func(), busy string) {
	names = dedupSorted(names)
	var got []chan struct{}
	for _, n := range names {
		c := l.ch(n)
		select {
		case c <- struct{}{}:
			got = append(got, c)
		default:
			for i := len(got) - 1; i >= 0; i-- {
				<-got[i]
			}
			return nil, n
		}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			for i := len(got) - 1; i >= 0; i-- {
				<-got[i]
			}
		})
	}, ""
}

// lockForPath maps well-known files to the resource lock that guards them.
func lockForPath(p string) []string {
	switch {
	case strings.HasPrefix(p, "/etc/ssh/"):
		return []string{LockSSHD}
	case strings.HasPrefix(p, "/etc/audit/"):
		return []string{LockAudit}
	case p == "/etc/passwd" || p == "/etc/shadow" || p == "/etc/group" || p == "/etc/gshadow" ||
		p == "/etc/sudoers" || strings.HasPrefix(p, "/etc/sudoers.d/"):
		return []string{LockAccounts}
	}
	return nil
}
