package depot

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// prepareExecCopy writes the verified bytes to a private file under execDir (a
// 0700 directory) with mode 0500 and points cmd at it. The bytes that were
// hashed are what runs: the deployed file can be swapped after Command returns
// without changing the exec. It is the fallback for platforms where a memfd
// cannot be executed (see prepareExec).
func prepareExecCopy(cmd *exec.Cmd, execDir string, content []byte) (func(), error) {
	dir, err := os.MkdirTemp(execDir, ".exec-")
	if err != nil {
		return nil, err
	}
	p := filepath.Join(dir, "tool")
	if err := os.WriteFile(p, content, 0o500); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("depot: exec copy: %w", err)
	}
	if err := os.Chmod(p, 0o500); err != nil { // the umask may have cleared bits
		os.RemoveAll(dir)
		return nil, fmt.Errorf("depot: exec copy: %w", err)
	}
	cmd.Path = p
	return func() { os.RemoveAll(dir) }, nil
}
