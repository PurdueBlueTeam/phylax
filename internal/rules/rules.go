// Package rules ships the default detection rule set. The agent embeds
// it; a signed config step can replace it at run time (docs: Local
// detection rules).
package rules

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed *.yml
var FS embed.FS

// Default writes the embedded rules into dir (used by the agent at
// startup and by config hot-reload).
func Default(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		return err
	}
	for _, e := range entries {
		b, err := FS.ReadFile(e.Name())
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o600); err != nil {
			return err
		}
	}
	return nil
}
