package plan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
)

// FileSeqStore persists the high-water mark in a small JSON file, replaced
// atomically. A corrupt file is an error (fail closed): silently resetting to
// zero would re-open the replay window.
type FileSeqStore struct{ Path string }

// Load implements SeqStore.
func (f FileSeqStore) Load() (Mark, error) {
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return Mark{}, nil
	}
	if err != nil {
		return Mark{}, err
	}
	var m Mark
	if err := json.Unmarshal(b, &m); err != nil {
		return Mark{}, fmt.Errorf("corrupt sequence store %s: %w", f.Path, err)
	}
	return m, nil
}

// Save implements SeqStore. It never moves the mark backwards.
func (f FileSeqStore) Save(m Mark) error {
	cur, err := f.Load()
	if err != nil {
		return err
	}
	if m.Less(cur) {
		return fmt.Errorf("refusing to lower sequence mark (%d,%d) -> (%d,%d)", cur.Epoch, cur.Seq, m.Epoch, m.Seq)
	}
	b, _ := json.Marshal(m)
	return atomicfile.WriteFile(f.Path, b, 0o600)
}
