//go:build !windows

package actions

func defaultWinEnv() WinEnv { return WinEnv{Exec: NewAllowExec()} }
