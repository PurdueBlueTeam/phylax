package depot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
)

// ErrTampered is returned when a deployed tool fails verification; the tool is
// not executed.
var ErrTampered = errors.New("depot: tool failed verification, refusing to run")

// CleanEnv builds the environment for depot tools from scratch. PATH is only
// the depot's bin directory; the dynamic-loader variables (LD_*), shell
// startup hooks and everything else inherited from the host are dropped, so a
// poisoned login environment cannot reach the tool. Only TERM, TZ (and on
// Windows SystemRoot/windir) are carried over. extra is applied last, except
// that LD_* and PATH can never be set through it.
func (d *Deployed) CleanEnv(host []string, extra map[string]string) []string {
	env := map[string]string{
		"PATH":   d.BinDir(),
		"HOME":   d.Dir,
		"LANG":   "C",
		"LC_ALL": "C",
	}
	keep := []string{"TERM", "TZ"}
	if runtime.GOOS == "windows" {
		keep = append(keep, "SystemRoot", "windir", "SYSTEMROOT")
	}
	for _, kv := range host {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		for _, w := range keep {
			if strings.EqualFold(k, w) {
				env[k] = v
			}
		}
	}
	for k, v := range extra {
		if strings.HasPrefix(strings.ToUpper(k), "LD_") || strings.EqualFold(k, "PATH") || k == "" || strings.Contains(k, "=") {
			continue
		}
		env[k] = v
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// IO carries a run's streams; nil streams are the null device.
type IO struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
}

// Command verifies the named tool (an exact tool or a multi-call applet)
// against the manifest and returns a command that runs exactly the bytes that
// were hashed. On Linux that means an in-memory copy (memfd), so the file on
// disk cannot be swapped between the check and the exec.
func (d *Deployed) Command(ctx context.Context, name string, args []string, extraEnv map[string]string, io IO) (*exec.Cmd, func(), error) {
	e, applet, err := d.M.Lookup(d.GOOS, d.GOARCH, name)
	if err != nil {
		return nil, nil, err
	}
	b, err := d.readTool(e)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrTampered, err)
	}
	cmd := &exec.Cmd{Args: append([]string{applet}, args...)}
	cleanup, err := prepareExec(cmd, d.BinDir()+string(os.PathSeparator)+e.File(), b)
	if err != nil {
		return nil, nil, err
	}
	cmd.Env = d.CleanEnv(os.Environ(), extraEnv)
	cmd.Dir = d.Dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = io.Stdin, io.Stdout, io.Stderr
	_ = ctx
	return cmd, cleanup, nil
}

// Run verifies and runs a tool to completion, returning its exit code.
func (d *Deployed) Run(ctx context.Context, name string, args []string, extraEnv map[string]string, io IO) (int, error) {
	cmd, cleanup, err := d.Command(ctx, name, args, extraEnv, io)
	if err != nil {
		return 127, err
	}
	defer cleanup()
	if err := cmd.Start(); err != nil {
		return 126, err
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			cmd.Process.Kill()
		case <-done:
		}
	}()
	err = cmd.Wait()
	close(done)
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return 126, err
	}
	return 0, nil
}

// Shell verifies the whole depot, then runs the depot's sh (a busybox applet
// normally) with the clean environment and a marked prompt. Only the shell
// itself is re-hashed per start; tools it launches by PATH are the files in
// bin/, so run `phylax depot verify` again if anything looks off.
func (d *Deployed) Shell(ctx context.Context, io IO) (int, error) {
	if ps := d.Verify(); len(ps) > 0 {
		return 1, fmt.Errorf("%w: %s", ErrTampered, ps[0])
	}
	return d.Run(ctx, "sh", nil, map[string]string{"PS1": "[depot] \\w # ", "PHYLAX_DEPOT": d.Dir}, io)
}
