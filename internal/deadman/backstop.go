package deadman

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Runner runs an external command and returns its combined output. It is the
// seam for testing the OS backstops without touching the host.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// ExecRunner is the real Runner. Running systemctl/systemd-run/schtasks is the
// one sanctioned host-binary use in the dead-man path (see the package notes in
// the design: the backstop must outlive the agent, and a transient unit or
// scheduled task is created by those tools' own interfaces).
func ExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil {
		return out.Bytes(), fmt.Errorf("%s: %w: %s", name, err, bytes.TrimSpace(out.Bytes()))
	}
	return out.Bytes(), nil
}

// Command says how the OS timer invokes the rollback: Binary Args... <id>.
// The default is `<this executable> agent rollback <id>` as written in the
// design. Put any journal/config flags in Args.
type Command struct {
	Binary string
	Args   []string
}

func (c Command) resolve() (Command, error) {
	if c.Binary == "" {
		exe, err := os.Executable()
		if err != nil {
			return c, err
		}
		c.Binary = exe
	}
	if c.Args == nil {
		c.Args = []string{"agent", "rollback"}
	}
	return c, nil
}

// argv returns the full command line for id.
func (c Command) argv(id string) []string {
	return append(append([]string{c.Binary}, c.Args...), id)
}

func ceilSeconds(d time.Duration) int {
	s := int((d + time.Second - 1) / time.Second)
	if s < 1 {
		s = 1
	}
	return s
}
