//go:build linux

package actions

import "golang.org/x/sys/unix"

func defaultUnloadModule(name string) error { return unix.DeleteModule(name, unix.O_NONBLOCK) }
