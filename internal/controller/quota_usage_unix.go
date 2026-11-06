//go:build !windows

package controller

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// diskUsedPct returns the used percentage of the filesystem holding dir.
//
// shortcut: usage is the whole filesystem's, not the data directory's,
// upgrade when the data disk is shared.
func diskUsedPct(dir string) (float64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", dir, err)
	}
	bsize := uint64(st.Bsize)
	total := st.Blocks * bsize
	if total == 0 {
		return 0, nil
	}
	used := (st.Blocks - st.Bfree) * bsize
	return float64(used) * 100 / float64(total), nil
}
