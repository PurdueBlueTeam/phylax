//go:build !linux

package main

import (
	"errors"
	"io"
)

func runProcTool(name string, _ []string, _ io.Writer) error {
	return errors.New(name + ": only available on linux (use the depot's Sysinternals tools on Windows)")
}
