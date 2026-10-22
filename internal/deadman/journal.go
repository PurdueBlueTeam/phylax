package deadman

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
)

// State is the lifecycle state of a journal entry.
type State string

const (
	// StateArmed: rollback data is durable and a timer is (or must be) running.
	StateArmed State = "armed"
	// StateConfirmed: the controller confirmed; no rollback needed. Terminal.
	StateConfirmed State = "confirmed"
	// StateCancelled: discarded before the change was applied. Terminal.
	StateCancelled State = "cancelled"
	// StateRolledBack: the rollback ran successfully. Terminal.
	StateRolledBack State = "rolled_back"
	// StateRollbackFailed: the rollback handler errored. Retried by Fire/Recover.
	StateRollbackFailed State = "rollback_failed"
)

// Entry is one armed rollback as stored in the journal.
type Entry struct {
	ID         string          `json:"id"`
	NodeID     string          `json:"node_id,omitempty"`
	Kind       string          `json:"kind"`
	Data       json.RawMessage `json:"data"`
	State      State           `json:"state"`
	ArmedAt    time.Time       `json:"armed_at"`
	Deadline   time.Time       `json:"deadline"`
	FinishedAt time.Time       `json:"finished_at,omitempty"`
	Attempts   int             `json:"attempts,omitempty"`
	FiredBy    string          `json:"fired_by,omitempty"`
	Outcome    string          `json:"outcome,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// Pending reports whether the entry still needs a confirm or a rollback.
func (e Entry) Pending() bool { return e.State == StateArmed || e.State == StateRollbackFailed }

var idRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidID reports whether id is usable as an entry id. Ids end up in file names,
// systemd unit names and task names, so they are restricted.
func ValidID(id string) bool { return idRe.MatchString(id) && !strings.Contains(id, "..") }

var (
	ErrExists       = errors.New("deadman: entry already exists")
	ErrNotFound     = errors.New("deadman: no such entry")
	ErrNotArmed     = errors.New("deadman: entry is not armed")
	ErrAlreadyFired = errors.New("deadman: rollback already ran")
	ErrBadID        = errors.New("deadman: invalid id")
)

const maxEntryBytes = 48 << 20

// journal is a directory holding one JSON file per entry, each replaced
// atomically, plus a lock file per entry for cross-process exclusion (the agent
// and the OS-timer process can both try to fire the same entry).
type journal struct{ dir string }

func openJournal(dir string) (*journal, error) {
	if dir == "" {
		return nil, errors.New("deadman: empty journal directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &journal{dir: dir}, nil
}

func (j *journal) path(id string) string { return filepath.Join(j.dir, id+".json") }

func (j *journal) load(id string) (Entry, error) {
	if !ValidID(id) {
		return Entry{}, ErrBadID
	}
	f, err := os.Open(j.path(id))
	if errors.Is(err, fs.ErrNotExist) {
		return Entry{}, ErrNotFound
	}
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	var e Entry
	dec := json.NewDecoder(&limitedReader{f: f, n: maxEntryBytes})
	if err := dec.Decode(&e); err != nil {
		return Entry{}, fmt.Errorf("deadman: corrupt entry %s: %w", id, err)
	}
	if e.ID != id {
		return Entry{}, fmt.Errorf("deadman: entry file %s holds id %q", id, e.ID)
	}
	return e, nil
}

type limitedReader struct {
	f *os.File
	n int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errors.New("deadman: entry too large")
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.f.Read(p)
	l.n -= int64(n)
	return n, err
}

func (j *journal) save(e Entry) error {
	b, err := json.MarshalIndent(e, "", " ")
	if err != nil {
		return err
	}
	if len(b) > maxEntryBytes {
		return errors.New("deadman: entry too large")
	}
	return atomicfile.WriteFile(j.path(e.ID), b, 0o600)
}

// list returns all readable entries sorted by deadline, and the errors for the
// ones that could not be read.
func (j *journal) list() ([]Entry, []error) {
	ents, err := os.ReadDir(j.dir)
	if err != nil {
		return nil, []error{err}
	}
	var out []Entry
	var errs []error
	for _, de := range ents {
		name := de.Name()
		if !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".") {
			continue
		}
		e, err := j.load(strings.TrimSuffix(name, ".json"))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Deadline.Before(out[b].Deadline) })
	return out, errs
}

const lockWait = 15 * time.Second

// lock takes the per-entry cross-process lock, waiting up to lockWait.
func (j *journal) lock(ctx context.Context, id string) (func(), error) {
	if !ValidID(id) {
		return nil, ErrBadID
	}
	f, err := os.OpenFile(filepath.Join(j.dir, id+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(lockWait)
	for {
		ok, err := tryLockFile(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		if ok {
			return func() { unlockFile(f); f.Close() }, nil
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("deadman: timed out waiting for lock on %s", id)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (j *journal) remove(id string) error {
	err := os.Remove(j.path(id))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	os.Remove(filepath.Join(j.dir, id+".lock"))
	return nil
}
