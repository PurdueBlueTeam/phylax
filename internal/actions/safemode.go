package actions

import (
	"errors"
	"io/fs"
	"os"
	"sync/atomic"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
)

// SafeMode is the per-agent safe-mode switch. While on, the executor refuses
// every Apply; rollback (dead-man or manual) is always allowed. The state is
// persisted so it survives agent restarts.
type SafeMode struct {
	on   atomic.Bool
	path string
}

// NewSafeMode loads the persisted state from path ("" = memory only).
func NewSafeMode(path string) (*SafeMode, error) {
	s := &SafeMode{path: path}
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			s.on.Store(true)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	return s, nil
}

func (s *SafeMode) On() bool { return s != nil && s.on.Load() }

// Set switches safe mode and persists it (marker file present = on).
func (s *SafeMode) Set(on bool) error {
	if s.path != "" {
		if on {
			if err := atomicfile.WriteFile(s.path, []byte("safe\n"), 0o600); err != nil {
				return err
			}
		} else if err := os.Remove(s.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	s.on.Store(on)
	return nil
}
