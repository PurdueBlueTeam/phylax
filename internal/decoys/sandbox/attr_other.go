//go:build !linux

package sandbox

import (
	"errors"
	"syscall"
)

// Credential dropping and no_new_privs are Linux mechanisms. Windows would use
// a restricted token (CreateRestrictedToken); until then the module runs the
// listeners in-process there (see docs/deception.md).
func sysProcAttr(string) (*syscall.SysProcAttr, bool, error) {
	return &syscall.SysProcAttr{}, false, nil
}

const noNewPrivsSupported = false

func noNewPrivs() error { return errors.New("no_new_privs is not available on this platform") }
