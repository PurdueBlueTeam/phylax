package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// changeClass is the set of kinds a work window may tag: changes made by hand
// on the host. Process, network, authentication and honeytoken events are
// never stamped (design: Tagging and adoption, "What may be tagged"; R6).
var changeClass = map[string]bool{
	event.KindFileChange:  true,
	"inventory.row":       true,
	"audit.rules_changed": true,
}

// secEventKinds are the names the winevt module uses for a Security event. It
// emits sec_event today; the design name is winevt.sec_event.
var secEventKinds = map[string]bool{"sec_event": true, "winevt.sec_event": true}

// accountChangeIDs are the Security ids the winevt module maps to an account,
// group or computer-account change. Logon and authentication ids (4624, 4625,
// 4648, 4672, 4768, 4769, 4771, 4776 ...) are deliberately absent: they never
// get a work-window tag (R6).
var accountChangeIDs = map[int]bool{
	// account_change
	4720: true, 4722: true, 4724: true, 4738: true, 4781: true,
	// group_change
	4728: true, 4729: true, 4732: true, 4733: true, 4756: true, 4757: true,
	// computer_account_change
	4739: true, 4741: true, 4742: true,
}

// changeKind reports whether a work window may stamp e: a change-class kind, or
// a winevt Security event that is an account change rather than a logon.
func changeKind(e event.Event) bool {
	if changeClass[e.Kind] {
		return true
	}
	return secEventKinds[e.Kind] && accountChangeIDs[intField(e.Fields, "event_id")]
}

// windowSaveEvery is how often the remaining window time is persisted, so a
// restart keeps roughly what was left (downtime does not count).
const windowSaveEvery = 10 * time.Second

// workWindow is the open tagged work window. The deadline is on the agent's
// monotonic clock: changing the system clock neither extends nor ends it.
type workWindow struct {
	id       string
	tag      string
	user     string
	deadline time.Duration
}

// windowFile is the persisted form: the remaining time, not an absolute
// deadline, so the clock the agent restarts with does not matter.
type windowFile struct {
	Window    string `json:"window"`
	Tag       string `json:"tag"`
	User      string `json:"user"`
	Remaining int64  `json:"remaining_ms"`
}

// windowState is the agent's one work window. A fact for another window
// replaces it; `end` closes it early.
type windowState struct {
	mu       sync.Mutex
	path     string // "" when the agent has no state directory
	mono     func() time.Duration
	loaded   bool
	open     *workWindow
	lastSave time.Duration
}

func newWindowState(root string, mono func() time.Duration) *windowState {
	w := &windowState{mono: mono}
	if root != "" {
		w.path = filepath.Join(root, "work_window.json")
	}
	return w
}

// windowFactData is the typed work_window fact payload.
type windowFactData struct {
	Window string `json:"window"`
	Tag    string `json:"tag"`
	User   string `json:"user"`
	Until  string `json:"until"` // display only: the controller's wall clock
	For    string `json:"for"`   // a Go duration, counted from the agent's receipt
	End    bool   `json:"end"`
}

// apply opens, extends or ends the window from a work_window fact. A fact for
// another window replaces the open one.
func (w *windowState) apply(f event.ControllerFact) error {
	raw, err := json.Marshal(f.Data)
	if err != nil {
		return fmt.Errorf("work_window data: %w", err)
	}
	var d windowFactData
	if err := json.Unmarshal(raw, &d); err != nil {
		return fmt.Errorf("work_window data: %w", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.mono()
	w.ensureLocked(now)
	if d.End {
		if w.open != nil && (d.Window == "" || d.Window == w.open.id) {
			w.open = nil
			w.saveLocked(now)
		}
		return nil
	}
	if d.Window == "" || d.Tag == "" {
		return errors.New("work_window fact has no window or tag")
	}
	dur := time.Duration(0)
	if d.For != "" {
		v, err := time.ParseDuration(d.For)
		if err != nil {
			return fmt.Errorf("work_window for %q: %w", d.For, err)
		}
		dur = v
	}
	if dur <= 0 && d.Until != "" {
		// Fallback for a fact without `for`: the controller's own clocks, so
		// the remaining duration is the same on both ends.
		until, err := time.Parse(time.RFC3339, d.Until)
		if err == nil {
			dur = until.Sub(f.TS)
		}
	}
	if dur <= 0 {
		return errors.New("work_window fact has no positive duration")
	}
	w.open = &workWindow{id: d.Window, tag: d.Tag, user: d.User, deadline: now + dur}
	w.saveLocked(now)
	return nil
}

// tagFor returns the window tag an event may carry: only a change-class event
// attributed to the claimed user, and only while the window is open. It also
// persists the remaining time every windowSaveEvery.
func (w *windowState) tagFor(e event.Event) string {
	if !changeKind(e) {
		return ""
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.mono()
	w.ensureLocked(now)
	if w.open == nil {
		return ""
	}
	if now >= w.open.deadline {
		w.open = nil // the window ends by itself, link or no link
		w.saveLocked(now)
		return ""
	}
	if now-w.lastSave >= windowSaveEvery {
		w.saveLocked(now)
	}
	user, _ := e.Fields["user"].(string)
	if user == "" || user != w.open.user {
		return ""
	}
	return w.open.tag
}

// ensureLocked loads the persisted window once.
func (w *windowState) ensureLocked(now time.Duration) {
	if w.loaded {
		return
	}
	w.loaded = true
	if w.path == "" {
		return
	}
	b, err := os.ReadFile(w.path)
	if err != nil {
		return
	}
	var f windowFile
	if json.Unmarshal(b, &f) != nil || f.Tag == "" || f.Remaining <= 0 {
		return
	}
	w.open = &workWindow{id: f.Window, tag: f.Tag, user: f.User, deadline: now + time.Duration(f.Remaining)}
	w.lastSave = now
}

// saveLocked persists the window's remaining time (or removes the file).
func (w *windowState) saveLocked(now time.Duration) {
	w.lastSave = now
	if w.path == "" {
		return
	}
	if w.open == nil {
		if err := os.Remove(w.path); err != nil && !os.IsNotExist(err) {
			w.lastSave = now
		}
		return
	}
	b, err := json.Marshal(windowFile{Window: w.open.id, Tag: w.open.tag, User: w.open.user,
		Remaining: int64(w.open.deadline - now)})
	if err != nil {
		return
	}
	_ = atomicfile.WriteFile(w.path, b, 0o600)
}
