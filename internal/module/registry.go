package module

import (
	"sort"
	"sync"
)

var (
	regMu    sync.RWMutex
	registry = map[string]ControllerModule{}
)

// Register adds a controller module from init. It panics on a duplicate name
// or an invalid manifest.
func Register(m ControllerModule) {
	man := m.Manifest()
	if err := man.Validate(); err != nil {
		panic(err)
	}
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := registry[man.Name]; dup {
		panic("module: duplicate registration " + man.Name)
	}
	registry[man.Name] = m
}

// Registered returns every registered controller module sorted by name.
func Registered() []ControllerModule {
	regMu.RLock()
	out := make([]ControllerModule, 0, len(registry))
	for _, m := range registry {
		out = append(out, m)
	}
	regMu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest().Name < out[j].Manifest().Name })
	return out
}

// Lookup returns a registered controller module by name.
func Lookup(name string) (ControllerModule, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	m, ok := registry[name]
	return m, ok
}
