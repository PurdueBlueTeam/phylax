//go:build windows

package controller

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// diskUsedPct returns the used percentage of the volume holding dir.
//
// shortcut: usage is the whole volume's, not the data directory's, upgrade
// when the data disk is shared.
func diskUsedPct(dir string) (float64, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var free, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree); err != nil {
		return 0, fmt.Errorf("GetDiskFreeSpaceEx %s: %w", dir, err)
	}
	if total == 0 {
		return 0, nil
	}
	return float64(total-totalFree) * 100 / float64(total), nil
}
