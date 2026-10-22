package deadman

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
)

// KindFileRestore is the built-in rollback kind that puts files back exactly
// as they were snapshotted.
const KindFileRestore = "file.restore"

// MaxSnapshotBytes bounds the total file content one entry may carry.
const MaxSnapshotBytes = 16 << 20

// FileSnapshot is the pre-change state of one file.
type FileSnapshot struct {
	Path    string      `json:"path"`
	Existed bool        `json:"existed"`
	Mode    fs.FileMode `json:"mode,omitempty"`
	Content []byte      `json:"content,omitempty"`
}

// FileRestore is the Data payload of a KindFileRestore entry.
type FileRestore struct {
	Files []FileSnapshot `json:"files"`
}

// SnapshotFiles records the current state of paths (a missing path is recorded
// as "did not exist", so rollback removes whatever the step created).
func SnapshotFiles(paths ...string) (FileRestore, error) {
	var fr FileRestore
	total := 0
	for _, p := range paths {
		st, err := os.Stat(p)
		if errors.Is(err, fs.ErrNotExist) {
			fr.Files = append(fr.Files, FileSnapshot{Path: p})
			continue
		}
		if err != nil {
			return FileRestore{}, err
		}
		if !st.Mode().IsRegular() {
			return FileRestore{}, fmt.Errorf("deadman: %s is not a regular file", p)
		}
		total += int(st.Size())
		if total > MaxSnapshotBytes {
			return FileRestore{}, fmt.Errorf("deadman: snapshot exceeds %d bytes", MaxSnapshotBytes)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return FileRestore{}, err
		}
		fr.Files = append(fr.Files, FileSnapshot{
			Path: p, Existed: true, Content: b,
			Mode: st.Mode() & (fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky),
		})
	}
	return fr, nil
}

// restoreFiles is the built-in Handler. It is idempotent: it converges the
// files to the snapshot whatever their current state.
func restoreFiles(_ context.Context, e Entry) error {
	var fr FileRestore
	if err := json.Unmarshal(e.Data, &fr); err != nil {
		return fmt.Errorf("decode file.restore data: %w", err)
	}
	var errs []error
	for _, s := range fr.Files {
		if !s.Existed {
			if err := os.Remove(s.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		if err := atomicfile.WriteFile(s.Path, s.Content, s.Mode.Perm()); err != nil {
			errs = append(errs, err)
			continue
		}
		// atomicfile keeps the *current* mode; the snapshot's mode wins on rollback.
		if err := os.Chmod(s.Path, s.Mode); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
