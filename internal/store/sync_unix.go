//go:build !windows

package store

import (
	"os"
	"path/filepath"
)

func syncDir(path string) error {
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
