package agent

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"sync"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/link"
)

// Statuses of a step_result that carry no signature: the step was refused
// before verification, or the answer to a step_status query that has no signed
// result to give.
const (
	StatusRejected = "rejected" // refused (bad signature, replay, ...)
	StatusUnknown  = "unknown"  // never accepted: (epoch, seq) is above the verifier mark
	StatusLost     = "lost"     // accepted, but no result is on record (agent restarted mid-step)
	StatusRunning  = "running"  // accepted and still executing
)

const maxLoggedResults = 256

type resultKey struct{ Epoch, Seq uint64 }

// resultLog is the agent's bounded, durable record of the signed results it
// produced, so that a result the controller never received can be sent again
// (after a link drop, a controller restart or an agent restart).
type resultLog struct {
	path string
	mu   sync.Mutex
	list []*link.StepResult
}

func openResultLog(path string) (*resultLog, error) {
	l := &resultLog{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &l.list); err != nil {
		// A corrupt record only loses re-sends (they answer "lost"); never fail the agent.
		l.list = nil
	}
	return l, nil
}

func (l *resultLog) add(m *link.StepResult) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := *m
	l.list = append(l.list, &cp)
	if len(l.list) > maxLoggedResults {
		l.list = l.list[len(l.list)-maxLoggedResults:]
	}
	b, err := json.Marshal(l.list)
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(l.path, b, 0o600)
}

// get returns the newest recorded result for (epoch, seq).
func (l *resultLog) get(k resultKey) (*link.StepResult, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := len(l.list) - 1; i >= 0; i-- {
		if r := l.list[i]; r.Epoch == k.Epoch && r.Seq == k.Seq {
			cp := *r
			return &cp, true
		}
	}
	return nil, false
}
