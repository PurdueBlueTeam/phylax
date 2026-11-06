//go:build !linux

package depot

import "os/exec"

// prepareExec runs the on-disk file; the hash was checked immediately before.
func prepareExec(cmd *exec.Cmd, path, _ string, _ []byte) (func(), error) {
	cmd.Path = path
	return func() {}, nil
}
