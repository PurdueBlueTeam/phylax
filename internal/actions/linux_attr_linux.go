//go:build linux

package actions

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type realAttr struct{}

func open(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
}

func (realAttr) Get(path string) (uint32, error) {
	f, err := open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	v, err := unix.IoctlGetUint32(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		return 0, fmt.Errorf("FS_IOC_GETFLAGS %s: %w", path, err)
	}
	return v, nil
}

func (realAttr) Set(path string, flags uint32) error {
	f, err := open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, int(flags)); err != nil {
		return fmt.Errorf("FS_IOC_SETFLAGS %s: %w", path, err)
	}
	return nil
}
