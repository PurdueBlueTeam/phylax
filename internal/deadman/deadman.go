// Package deadman is the agent-side dead-man switch (design: Execution,
// "Dead-man switch"). Before a risky step the agent calls Arm with the rollback
// data; the entry is made durable in a journal, an in-process timer starts, and
// an OS-level backstop (systemd transient timer / Windows scheduled task) is
// armed so the rollback still runs if the agent dies. Confirm disarms
// everything; otherwise Fire applies the recorded rollback idempotently and
// records the outcome. Recover, on agent start, fires expired entries and
// re-arms live ones.
package deadman

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Handler applies the rollback for one entry. It MUST be idempotent: it can run
// more than once (crash after the rollback but before the outcome was saved,
// retries after failure, in-process timer racing the OS timer).
type Handler func(ctx context.Context, e Entry) error

// Backstop is the OS-level timer that fires the rollback if the agent cannot.
type Backstop interface {
	// Arm schedules `<phylax> ... fire id` at deadline. Re-arming an id that is
	// already armed replaces it.
	Arm(ctx context.Context, id string, deadline time.Time) error
	// Disarm cancels the pending timer. Disarming an unknown id is not an error.
	// It never stops a rollback that is already running.
	Disarm(ctx context.Context, id string) error
}

// Options configures a Manager.
type Options struct {
	// Backstop may be nil (journal and in-process timer only; not crash-proof).
	Backstop Backstop
	// Handlers maps entry Kind to rollback code. KindFileRestore is built in.
	Handlers map[string]Handler
	// Now defaults to time.Now.
	Now func() time.Time
	// FireTimeout bounds one rollback attempt (default 60s).
	FireTimeout time.Duration
	// RetryInterval and MaxRetries govern in-process retries of a failed rollback
	// (defaults 5s, 5).
	RetryInterval time.Duration
	MaxRetries    int
	// OnResult, if set, is called after every in-process timer fire attempt.
	OnResult func(Entry, error)
}

// Manager owns a journal directory and the in-process timers.
type Manager struct {
	j    *journal
	opt  Options
	mu   sync.Mutex
	tm   map[string]*time.Timer
	done bool
	wg   sync.WaitGroup
	ctx  context.Context
	stop context.CancelFunc
}

// Open opens (creating if needed) the journal in dir. It does not start any
// timer; call Recover to resume entries left by a previous process.
func Open(dir string, opt Options) (*Manager, error) {
	j, err := openJournal(dir)
	if err != nil {
		return nil, err
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.FireTimeout <= 0 {
		opt.FireTimeout = 60 * time.Second
	}
	if opt.RetryInterval <= 0 {
		opt.RetryInterval = 5 * time.Second
	}
	if opt.MaxRetries <= 0 {
		opt.MaxRetries = 5
	}
	h := map[string]Handler{KindFileRestore: restoreFiles}
	for k, v := range opt.Handlers {
		h[k] = v
	}
	opt.Handlers = h
	ctx, stop := context.WithCancel(context.Background())
	return &Manager{j: j, opt: opt, tm: map[string]*time.Timer{}, ctx: ctx, stop: stop}, nil
}

// Close stops in-process timers and waits for running fires. It does not
// disarm the OS backstop: that is the point.
func (m *Manager) Close() error {
	m.mu.Lock()
	m.done = true
	for id, t := range m.tm {
		if t.Stop() {
			m.wg.Done()
		}
		delete(m.tm, id)
	}
	m.mu.Unlock()
	m.stop()
	m.wg.Wait()
	return nil
}

// ArmRequest describes a rollback to arm.
type ArmRequest struct {
	ID      string
	NodeID  string
	Timeout time.Duration // time until the deadline; the design default is 90s
	Kind    string
	Data    any // JSON-encoded into the entry (e.g. a FileRestore)
}

// Arm durably records the rollback, arms the OS backstop and starts the
// in-process timer. Only when Arm returns nil may the caller apply the change.
// If the backstop cannot be armed, the entry is cancelled and an error returned.
func (m *Manager) Arm(ctx context.Context, r ArmRequest) (Entry, error) {
	if !ValidID(r.ID) {
		return Entry{}, ErrBadID
	}
	if r.Timeout <= 0 {
		return Entry{}, errors.New("deadman: timeout must be positive")
	}
	if _, ok := m.opt.Handlers[r.Kind]; !ok {
		return Entry{}, fmt.Errorf("deadman: no handler for kind %q", r.Kind)
	}
	data, err := json.Marshal(r.Data)
	if err != nil {
		return Entry{}, err
	}
	unlock, err := m.j.lock(ctx, r.ID)
	if err != nil {
		return Entry{}, err
	}
	defer unlock()
	if _, err := m.j.load(r.ID); err == nil {
		return Entry{}, ErrExists
	} else if !errors.Is(err, ErrNotFound) {
		return Entry{}, err
	}
	now := m.opt.Now()
	e := Entry{ID: r.ID, NodeID: r.NodeID, Kind: r.Kind, Data: data, State: StateArmed,
		ArmedAt: now, Deadline: now.Add(r.Timeout)}
	if err := m.j.save(e); err != nil {
		return Entry{}, fmt.Errorf("deadman: journal: %w", err)
	}
	if m.opt.Backstop != nil {
		if err := m.opt.Backstop.Arm(ctx, e.ID, e.Deadline); err != nil {
			e.State, e.FinishedAt, e.Error = StateCancelled, m.opt.Now(), "backstop arm failed: "+err.Error()
			_ = m.j.save(e)
			return Entry{}, fmt.Errorf("deadman: arm OS backstop: %w", err)
		}
	}
	m.startTimer(e)
	return e, nil
}

// Confirm records that the controller confirmed: no rollback will run. A
// confirm that arrives after the deadline but before the rollback ran is
// accepted (the link demonstrably works). Confirming twice is a no-op.
func (m *Manager) Confirm(ctx context.Context, id string) (Entry, error) {
	return m.finish(ctx, id, StateConfirmed)
}

// Cancel discards an armed entry whose change was never applied.
func (m *Manager) Cancel(ctx context.Context, id string) (Entry, error) {
	return m.finish(ctx, id, StateCancelled)
}

func (m *Manager) finish(ctx context.Context, id string, to State) (Entry, error) {
	unlock, err := m.j.lock(ctx, id)
	if err != nil {
		return Entry{}, err
	}
	defer unlock()
	e, err := m.j.load(id)
	if err != nil {
		return Entry{}, err
	}
	switch e.State {
	case to:
		return e, nil
	case StateArmed:
	case StateRolledBack, StateRollbackFailed:
		return e, ErrAlreadyFired
	default:
		return e, ErrNotArmed
	}
	e.State, e.FinishedAt = to, m.opt.Now()
	if err := m.j.save(e); err != nil {
		return e, err
	}
	m.stopTimer(id)
	if m.opt.Backstop != nil {
		if err := m.opt.Backstop.Disarm(ctx, id); err != nil {
			// The journal says finished, so a stray OS timer fire is a no-op.
			return e, fmt.Errorf("deadman: %s recorded but OS timer not removed: %w", to, err)
		}
	}
	return e, nil
}

// Fire applies the rollback if the entry is still pending. It is safe to call
// concurrently from several goroutines and processes and any number of times:
// once the outcome is recorded further calls return the entry unchanged. The
// returned error is the rollback error, if any (the entry then stays pending
// as StateRollbackFailed for a retry).
func (m *Manager) Fire(ctx context.Context, id, by string) (Entry, error) {
	unlock, err := m.j.lock(ctx, id)
	if err != nil {
		return Entry{}, err
	}
	defer unlock()
	e, err := m.j.load(id)
	if err != nil {
		return Entry{}, err
	}
	if !e.Pending() {
		return e, nil
	}
	h, ok := m.opt.Handlers[e.Kind]
	var herr error
	if !ok {
		herr = fmt.Errorf("no handler for kind %q", e.Kind)
	} else {
		fctx, cancel := context.WithTimeout(ctx, m.opt.FireTimeout)
		herr = h(fctx, e)
		cancel()
	}
	e.Attempts++
	e.FiredBy = by
	e.FinishedAt = m.opt.Now()
	if herr != nil {
		e.State, e.Error = StateRollbackFailed, herr.Error()
	} else {
		e.State, e.Error, e.Outcome = StateRolledBack, "", "rolled back"
	}
	if err := m.j.save(e); err != nil {
		return e, fmt.Errorf("deadman: rollback ran but outcome not saved: %w", err)
	}
	if herr == nil {
		m.stopTimer(id)
		if m.opt.Backstop != nil {
			_ = m.opt.Backstop.Disarm(ctx, id) // timer only; never the running service
		}
	}
	return e, herr
}

// Recover resumes the journal after an agent (re)start: pending entries whose
// deadline has passed fire immediately, the rest get their in-process timer and
// OS backstop re-armed. Call it before the agent does anything else. It returns
// the entries it acted on; the error joins every failure.
func (m *Manager) Recover(ctx context.Context) ([]Entry, error) {
	entries, errs := m.j.list()
	var acted []Entry
	for _, e := range entries {
		if !e.Pending() {
			continue
		}
		if e.State == StateRollbackFailed || !e.Deadline.After(m.opt.Now()) {
			fe, err := m.Fire(ctx, e.ID, "recovery")
			acted = append(acted, fe)
			if err != nil {
				errs = append(errs, fmt.Errorf("fire %s: %w", e.ID, err))
			}
			continue
		}
		if m.opt.Backstop != nil {
			if err := m.opt.Backstop.Arm(ctx, e.ID, e.Deadline); err != nil {
				// Cannot guarantee the OS timer: fail safe and roll back now.
				errs = append(errs, fmt.Errorf("re-arm backstop %s: %w", e.ID, err))
				fe, ferr := m.Fire(ctx, e.ID, "recovery")
				acted = append(acted, fe)
				if ferr != nil {
					errs = append(errs, fmt.Errorf("fire %s: %w", e.ID, ferr))
				}
				continue
			}
		}
		m.startTimer(e)
		acted = append(acted, e)
	}
	return acted, errors.Join(errs...)
}

// Get returns one entry.
func (m *Manager) Get(id string) (Entry, error) { return m.j.load(id) }

// List returns all entries ordered by deadline.
func (m *Manager) List() ([]Entry, error) {
	e, errs := m.j.list()
	return e, errors.Join(errs...)
}

// Prune deletes finished entries older than age, returning how many.
func (m *Manager) Prune(age time.Duration) (int, error) {
	entries, errs := m.j.list()
	n := 0
	for _, e := range entries {
		if e.Pending() || m.opt.Now().Sub(e.FinishedAt) < age {
			continue
		}
		if err := m.j.remove(e.ID); err != nil {
			errs = append(errs, err)
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

func (m *Manager) startTimer(e Entry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.done {
		return
	}
	if old := m.tm[e.ID]; old != nil && old.Stop() {
		m.wg.Done()
	}
	d := e.Deadline.Sub(m.opt.Now())
	if d < 0 {
		d = 0
	}
	id := e.ID
	m.wg.Add(1)
	m.tm[id] = time.AfterFunc(d, func() {
		defer m.wg.Done()
		m.timerFire(id)
	})
}

func (m *Manager) stopTimer(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t := m.tm[id]; t != nil {
		if t.Stop() {
			m.wg.Done() // callback will never run
		}
		delete(m.tm, id)
	}
}

func (m *Manager) timerFire(id string) {
	for attempt := 0; ; attempt++ {
		e, err := m.Fire(m.ctx, id, "timer")
		if m.opt.OnResult != nil && e.ID != "" {
			m.opt.OnResult(e, err)
		}
		if err == nil || attempt >= m.opt.MaxRetries {
			return
		}
		select {
		case <-m.ctx.Done():
			return
		case <-time.After(m.opt.RetryInterval):
		}
	}
}
