//go:build !linux

package actions

func defaultUnloadModule(string) error { return ErrUnsupported }
