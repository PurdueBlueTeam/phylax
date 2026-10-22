package detect

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// profileDef declares a baseline. With Learn > 0 it is learned from events of
// Kinds: per key (the Key fields), the first event starts a learning window
// during which every Value seen is added; afterwards in_profile is membership.
// During the window in_profile is true, so rules stay quiet while learning.
// With Learn == 0 it is a static list filled by Engine.Seed (rotation state,
// scored accounts, declared dependencies ...).
type profileDef struct {
	Name      string
	Kinds     []string
	Key       []fieldRef
	Value     string
	value     fieldRef
	Learn     time.Duration
	MaxKeys   int
	MaxValues int
	where     node
}

const (
	defMaxKeys   = 4096
	defMaxValues = 512
)

func (env *compileEnv) compileProfile(d *profileDoc) (*profileDef, error) {
	where := "profile " + d.Name
	if !fieldNameRE.MatchString(d.Name) || d.Name == "" {
		return nil, fmt.Errorf("profile %q: invalid name", d.Name)
	}
	p := &profileDef{Name: d.Name, Value: d.Value, MaxKeys: d.MaxKeys, MaxValues: d.MaxValues}
	var err error
	if p.Key, err = refs(d.Key, where+".key"); err != nil {
		return nil, err
	}
	if p.MaxKeys == 0 {
		p.MaxKeys = defMaxKeys
	}
	if p.MaxValues == 0 {
		p.MaxValues = defMaxValues
	}
	if p.MaxKeys < 0 || p.MaxValues < 0 {
		return nil, fmt.Errorf("%s: negative limit", where)
	}
	if d.Learn == "" {
		if d.Event.Kind != 0 || d.Value != "" || len(d.Where) > 0 {
			return nil, fmt.Errorf("%s: event/value/where need a learn window", where)
		}
		return p, nil
	}
	if p.Learn, err = parseDur(d.Learn, where+".learn"); err != nil {
		return nil, err
	}
	if p.Kinds, err = parseKinds(&d.Event, where+".event"); err != nil {
		return nil, err
	}
	if d.Value == "" || !fieldNameRE.MatchString(d.Value) {
		return nil, fmt.Errorf("%s: value field is required for a learned profile", where)
	}
	p.value = newFieldRef(d.Value)
	if len(d.Where) > 0 {
		l, err := env.compileList(d.Where, where+".where")
		if err != nil {
			return nil, err
		}
		p.where = allNode(l)
	}
	return p, nil
}

type pkey struct {
	start time.Time
	vals  map[string]struct{}
}

type profileState struct {
	def  *profileDef
	keys map[string]*pkey
}

func profileKey(refs []fieldRef, c *evalCtx) (string, bool) {
	switch len(refs) {
	case 0:
		return "", true
	case 1:
		v, ok := refs[0].get(c)
		if !ok {
			return "", false
		}
		s, _ := toStr(v)
		return strings.ToLower(s), true
	}
	var b strings.Builder
	for i, r := range refs {
		v, ok := r.get(c)
		if !ok {
			return "", false
		}
		if i > 0 {
			b.WriteByte(0)
		}
		s, _ := toStr(v)
		b.WriteString(strings.ToLower(s))
	}
	return b.String(), true
}

func (e *Engine) inProfile(pd *profileDef, c *evalCtx, val string) bool {
	ps := e.profiles[pd.Name]
	key, ok := profileKey(pd.Key, c)
	if !ok {
		return false
	}
	k := ps.keys[key]
	if k == nil {
		return pd.Learn > 0 // the window opens with this event
	}
	if pd.Learn > 0 && c.ev.Time.Before(k.start.Add(pd.Learn)) {
		return true
	}
	_, hit := k.vals[strings.ToLower(val)]
	return hit
}

// observe feeds a learned profile with an event.
func (e *Engine) observe(ps *profileState, c *evalCtx) {
	pd := ps.def
	if pd.where != nil && !pd.where.eval(c) {
		return
	}
	key, ok := profileKey(pd.Key, c)
	if !ok {
		return
	}
	v, ok := pd.value.get(c)
	if !ok {
		return
	}
	k := ps.keys[key]
	if k == nil {
		if len(ps.keys) >= pd.MaxKeys {
			ps.evictOldest()
		}
		k = &pkey{start: c.ev.Time, vals: map[string]struct{}{}}
		ps.keys[key] = k
	}
	if !c.ev.Time.Before(k.start.Add(pd.Learn)) {
		return
	}
	anyElem(v, func(el any) bool {
		if s, ok := toStr(el); ok && s != "" && len(k.vals) < pd.MaxValues {
			k.vals[strings.ToLower(s)] = struct{}{}
		}
		return false
	})
}

func (ps *profileState) evictOldest() {
	var oldK string
	var oldT time.Time
	first := true
	for k, v := range ps.keys {
		if first || v.start.Before(oldT) {
			oldK, oldT, first = k, v.start, false
		}
	}
	delete(ps.keys, oldK)
}

// Seed adds values to a profile for a key (nil key for a keyless list). Seeded
// keys on a learned profile start their window at the zero time, so they are
// treated as already learned.
func (e *Engine) Seed(profile string, key []string, values ...string) error {
	ps, ok := e.profiles[profile]
	if !ok {
		return fmt.Errorf("detect: unknown profile %q", profile)
	}
	if len(key) != len(ps.def.Key) {
		return fmt.Errorf("detect: profile %q has %d key fields, got %d", profile, len(ps.def.Key), len(key))
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range key {
		key[i] = strings.ToLower(key[i])
	}
	k := ps.keys[strings.Join(key, "\x00")]
	if k == nil {
		if len(ps.keys) >= ps.def.MaxKeys {
			return fmt.Errorf("detect: profile %q key limit reached", profile)
		}
		k = &pkey{vals: map[string]struct{}{}}
		ps.keys[strings.Join(key, "\x00")] = k
	}
	for _, v := range values {
		if len(k.vals) >= ps.def.MaxValues {
			return fmt.Errorf("detect: profile %q value limit reached", profile)
		}
		k.vals[strings.ToLower(v)] = struct{}{}
	}
	return nil
}

// KeyState is the exported baseline of one profile key.
type KeyState struct {
	Start  time.Time `json:"start"`
	Values []string  `json:"values"`
}

// ExportProfiles snapshots all learned and seeded baselines (for persistence
// across agent restarts).
func (e *Engine) ExportProfiles() map[string]map[string]KeyState {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[string]map[string]KeyState{}
	for n, ps := range e.profiles {
		m := map[string]KeyState{}
		for k, v := range ps.keys {
			vals := make([]string, 0, len(v.vals))
			for s := range v.vals {
				vals = append(vals, s)
			}
			sort.Strings(vals)
			m[k] = KeyState{Start: v.start, Values: vals}
		}
		out[n] = m
	}
	return out
}

// ImportProfiles restores a snapshot made by ExportProfiles; unknown profiles
// are ignored and limits are enforced.
func (e *Engine) ImportProfiles(st map[string]map[string]KeyState) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for n, keys := range st {
		ps, ok := e.profiles[n]
		if !ok {
			continue
		}
		for k, v := range keys {
			if len(ps.keys) >= ps.def.MaxKeys {
				break
			}
			pk := &pkey{start: v.Start, vals: map[string]struct{}{}}
			for _, s := range v.Values {
				if len(pk.vals) < ps.def.MaxValues {
					pk.vals[s] = struct{}{}
				}
			}
			ps.keys[k] = pk
		}
	}
}

var _ = yaml.Node{}
