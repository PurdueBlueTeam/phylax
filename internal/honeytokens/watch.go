package honeytokens

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// KindHoneyRead is the event kind of a read of a watched honey file.
const KindHoneyRead = "honey.read"

// ErrWatchUnavailable is returned by NewFanotify where fanotify cannot be used
// (not Linux, or not root).
var ErrWatchUnavailable = errors.New("honeytokens: fanotify unavailable")

// ReadEvent is one open or read of a watched file.
type ReadEvent struct {
	Path string
	PID  int
	Exe  string
	Time time.Time
}

// Watcher reports reads of honey files. The Linux implementation is fanotify
// (NewFanotify); tests and the Windows path (SACL, event 4663 through winevt
// and rules/deception.yml) do not need it.
type Watcher interface {
	// Watch adds a file. Watching a missing file is an error.
	Watch(path string) error
	// Events delivers reads until Close. The channel is closed on Close.
	Events() <-chan ReadEvent
	Close() error
}

// WatchModule is an agent module turning Watcher events into honey.read events
// attributed to the token that was planted at the path.
type WatchModule struct {
	W     Watcher
	Paths []string
	Reg   *Registry
	Host  string
	// IgnoreExe lists executables whose opens are not sightings (the agent's
	// own hash sweep must not touch honey files, but belt and braces).
	IgnoreExe []string
	// IgnorePID is the agent's own pid.
	IgnorePID int
}

// Name implements agent.Module.
func (*WatchModule) Name() string { return "honeywatch" }

// Start implements agent.Module.
func (m *WatchModule) Start(ctx context.Context, emit agent.Emit) error {
	var errs []error
	for _, p := range m.Paths {
		if err := m.W.Watch(p); err != nil {
			errs = append(errs, fmt.Errorf("watch %s: %w", p, err))
		}
	}
	if len(errs) == len(m.Paths) && len(errs) > 0 {
		_ = m.W.Close()
		return errors.Join(errs...)
	}
	go func() { <-ctx.Done(); _ = m.W.Close() }()
	for ev := range m.W.Events() {
		if ev.PID == m.IgnorePID && m.IgnorePID != 0 {
			continue
		}
		skip := false
		for _, x := range m.IgnoreExe {
			if x == ev.Exe {
				skip = true
			}
		}
		if skip {
			continue
		}
		f := map[string]any{"path": ev.Path, "pid": ev.PID, "exe": ev.Exe, "severity": "critical", "host": m.Host}
		if m.Reg != nil {
			if t, ok := m.Reg.Attribute(map[string]any{"path": ev.Path}); ok {
				f["honeytoken"], f["token_origin"], f["token_kind"] = t.ID, t.Host, string(t.Kind)
			}
		}
		tm := ev.Time
		if tm.IsZero() {
			tm = time.Now()
		}
		_ = emit(event.Event{Time: tm, Kind: KindHoneyRead, Priority: event.PriorityCritical, Fields: f})
	}
	return nil
}
