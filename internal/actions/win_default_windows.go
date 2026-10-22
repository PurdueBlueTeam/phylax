//go:build windows

package actions

import (
	"os"
	"path/filepath"
)

func defaultWinEnv() WinEnv {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	ex := NewAllowExec()
	w := WinEnv{Exec: ex, DepotDir: filepath.Join(pd, "phylax", "depot")}
	platformWinEnv(&w)
	return w
}
