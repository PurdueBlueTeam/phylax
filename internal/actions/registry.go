package actions

import (
	"fmt"
	"sort"
	"sync"
)

// Registry maps action names to implementations.
type Registry struct {
	mu sync.RWMutex
	m  map[string]Action
}

func NewRegistry() *Registry { return &Registry{m: map[string]Action{}} }

// Register adds a; registering a name twice panics (programming error).
func (r *Registry) Register(a Action) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := a.Spec().Name
	if _, dup := r.m[n]; dup {
		panic(fmt.Sprintf("actions: duplicate registration %q", n))
	}
	r.m[n] = a
}

func (r *Registry) Get(name string) (Action, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.m[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknown, name)
	}
	return a, nil
}

func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.m))
	for n := range r.m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Core returns a registry with every core action.
func Core() *Registry {
	r := NewRegistry()
	for _, a := range coreActions() {
		r.Register(a)
	}
	return r
}
