//go:build !linux

package gotools

import (
	"errors"
	"io"
)

// ErrUnsupported: ps, ss and lsof read Linux /proc and netlink.
var ErrUnsupported = errors.New("gotools: only available on linux")

func Unsupported(io.Writer) error { return ErrUnsupported }
