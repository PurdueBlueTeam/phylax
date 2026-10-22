package capture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// KindAlert is the detect module's alert event kind (mods.KindAlert).
const KindAlert = "detect.alert"

// Freeze-on-alert defaults: alert minus 5 minutes to plus 10 minutes, at most
// 8 windows being held at once, 512 MiB of pcaps on disk.
const (
	DefaultFreezeBefore = 5 * time.Minute
	DefaultFreezeAfter  = 10 * time.Minute
	DefaultDiskBudget   = 512 << 20
	defaultMaxFreezes   = 8
)

// Freezer pins ring windows when an alert for this host arrives and writes
// them as pcaps under Dir, within DiskBudget.
type Freezer struct {
	Ring *Ring
	// Dir receives <id>.pcap files; created on first use.
	Dir string
	// Budget caps the total size of the pcaps in Dir. A capture larger than
	// the whole budget is refused; otherwise the oldest other pcaps are
	// removed to make room.
	Budget int64
	Before time.Duration // default 5m
	After  time.Duration // default 10m
	// Max concurrent windows (default 8): more alerts than that extend the
	// window with the same id or are skipped, never queued without bound.
	Max int
	// Local reports this host's own addresses, which are never used as the
	// freeze filter (every packet involves them).
	Local func(netip.Addr) bool
	Emit  func(event.Event) error
	Log   *slog.Logger

	mu     sync.Mutex
	active map[string]*freezeState
	wg     sync.WaitGroup
	skips  uint64
}

type freezeState struct {
	deadline time.Time // wall clock: when the final pcap is written
	rule     string
	ips      []netip.Addr
}

// Skipped counts alerts that were not frozen because Max windows were open.
func (f *Freezer) Skipped() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.skips
}

// Wait blocks until all windows have been written (tests, shutdown).
func (f *Freezer) Wait() { f.wg.Wait() }

// WantsFreeze reports whether ev is an alert whose rule asks for the ring to
// be frozen (collect contains freeze_ring).
func WantsFreeze(ev event.Event) bool {
	if ev.Kind != KindAlert {
		return false
	}
	switch c := ev.Fields["collect"].(type) {
	case []any:
		for _, v := range c {
			if s, _ := v.(string); s == "freeze_ring" {
				return true
			}
		}
	case []string:
		for _, s := range c {
			if s == "freeze_ring" {
				return true
			}
		}
	}
	return false
}

// AlertIPs extracts the remote addresses an alert involves: every field value
// that parses as an address in the alert's entities and in its evidence
// events, excluding loopback, unspecified, and the host's own addresses.
func (f *Freezer) AlertIPs(ev event.Event) []netip.Addr {
	seen := map[netip.Addr]bool{}
	consider := func(v any) {
		s, ok := v.(string)
		if !ok || len(s) > 64 {
			return
		}
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return
		}
		a = a.Unmap()
		if a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || (f.Local != nil && f.Local(a)) {
			return
		}
		seen[a] = true
	}
	if ents, ok := ev.Fields["entities"].(map[string]any); ok {
		for _, v := range ents {
			consider(v)
		}
	}
	if evs, ok := ev.Fields["evidence"].([]any); ok {
		for _, e := range evs {
			m, _ := e.(map[string]any)
			fl, _ := m["fields"].(map[string]any)
			for _, v := range fl {
				consider(v)
			}
		}
	}
	out := make([]netip.Addr, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

func freezeID(rule string, ips []netip.Addr) string {
	h := sha256.New()
	h.Write([]byte(rule))
	for _, a := range ips {
		h.Write([]byte{0})
		h.Write([]byte(a.String()))
	}
	return "fz-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// OnAlert freezes the window around ev. ctx bounds the wait for the window to
// close: on cancellation the pcap is written with what the hold has so far.
func (f *Freezer) OnAlert(ctx context.Context, ev event.Event) {
	if !WantsFreeze(ev) {
		return
	}
	if f.Before == 0 {
		f.Before = DefaultFreezeBefore
	}
	if f.After == 0 {
		f.After = DefaultFreezeAfter
	}
	max := f.Max
	if max <= 0 {
		max = defaultMaxFreezes
	}
	at := ev.Time
	if at.IsZero() {
		at = time.Now()
	}
	rule, _ := ev.Fields["rule"].(string)
	ips := f.AlertIPs(ev)
	id := freezeID(rule, ips)

	f.mu.Lock()
	if f.active == nil {
		f.active = map[string]*freezeState{}
	}
	if st, ok := f.active[id]; ok { // same rule and peers again: extend, one pcap
		st.deadline = time.Now().Add(f.After)
		f.mu.Unlock()
		f.Ring.Freeze(id, at.Add(-f.Before), at.Add(f.After), ips)
		return
	}
	if len(f.active) >= max {
		f.skips++
		f.mu.Unlock()
		return
	}
	st := &freezeState{deadline: time.Now().Add(f.After), rule: rule, ips: ips}
	f.active[id] = st
	f.wg.Add(1)
	f.mu.Unlock()

	from, to := at.Add(-f.Before), at.Add(f.After)
	f.Ring.Freeze(id, from, to, ips)
	go func() {
		defer f.wg.Done()
		defer func() {
			f.mu.Lock()
			delete(f.active, id)
			f.mu.Unlock()
			f.Ring.Release(id)
		}()
		f.write(id, st, from, to, at, false) // what the ring held at the alert
		for {
			f.mu.Lock()
			wait := time.Until(st.deadline)
			f.mu.Unlock()
			if wait <= 0 {
				break
			}
			t := time.NewTimer(wait)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				f.write(id, st, from, to, at, true)
				return
			}
		}
		f.write(id, st, from, to, at, true)
	}()
}

// write stores the hold as <id>.pcap (atomically replacing an earlier, shorter
// version) and publishes the evidence event.
func (f *Freezer) write(id string, st *freezeState, from, to, alertAt time.Time, final bool) {
	ev := event.Event{Time: time.Now(), Kind: KindEvidence, Priority: event.PriorityHigh, Fields: map[string]any{
		"id": id, "rule": st.rule, "final": final, "alert_time": alertAt.UTC().Format(time.RFC3339Nano),
		"from": from.UTC().Format(time.RFC3339Nano), "to": to.UTC().Format(time.RFC3339Nano),
	}}
	ips := make([]any, 0, len(st.ips))
	for _, a := range st.ips {
		ips = append(ips, a.String())
	}
	ev.Fields["ips"] = ips
	fail := func(err error) {
		ev.Fields["error"] = err.Error()
		if f.Log != nil {
			f.Log.Warn("capture: freeze not stored", "id", id, "err", err)
		}
		if f.Emit != nil {
			_ = f.Emit(ev)
		}
	}
	var buf bytes.Buffer
	n, err := f.Ring.WriteFrozen(&buf, id)
	if err != nil {
		fail(err)
		return
	}
	if info, err := f.Ring.Frozen(id); err == nil && info.Full {
		ev.Fields["truncated"] = true // hold budget was hit: some packets are missing
	}
	path := filepath.Join(f.Dir, id+".pcap")
	evicted, err := f.makeRoom(path, int64(buf.Len()))
	if err != nil {
		fail(err)
		return
	}
	if err := atomicfile.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		fail(err)
		return
	}
	sum := sha256.Sum256(buf.Bytes())
	ev.Fields["path"], ev.Fields["bytes"], ev.Fields["packets"] = path, buf.Len(), n
	ev.Fields["sha256"] = hex.EncodeToString(sum[:])
	if evicted > 0 {
		ev.Fields["evicted"] = evicted
	}
	if f.Emit != nil {
		_ = f.Emit(ev)
	}
}

// ErrOverBudget means one capture is larger than the whole disk budget.
var ErrOverBudget = errors.New("capture: pcap larger than the disk budget")

// makeRoom removes the oldest other pcaps until size bytes fit in the budget.
func (f *Freezer) makeRoom(self string, size int64) (evicted int, err error) {
	budget := f.Budget
	if budget <= 0 {
		budget = DefaultDiskBudget
	}
	if size > budget {
		return 0, fmt.Errorf("%w (%d > %d bytes)", ErrOverBudget, size, budget)
	}
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return 0, err
	}
	ents, err := os.ReadDir(f.Dir)
	if err != nil {
		return 0, err
	}
	type pf struct {
		path string
		size int64
		mod  time.Time
	}
	var files []pf
	var used int64
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pcap") {
			continue
		}
		p := filepath.Join(f.Dir, e.Name())
		if p == self {
			continue // replaced by this write
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, pf{p, fi.Size(), fi.ModTime()})
		used += fi.Size()
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.Before(files[j].mod) })
	for _, x := range files {
		if used+size <= budget {
			break
		}
		if os.Remove(x.path) == nil {
			used -= x.size
			evicted++
		}
	}
	if used+size > budget {
		return evicted, ErrOverBudget
	}
	return evicted, nil
}
