package actions

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// AllowExec is the Executor used on real hosts: it runs only programs on its
// allowlist (by base name), with a deadline and bounded output. It is the
// explicit escape hatch of the design ("host.exec"); actions use it only where
// no native API exists (auditpol fallback, Defender cmdlets, wusa).
type AllowExec struct {
	Allow   []string
	Timeout time.Duration
	MaxOut  int
}

// NewAllowExec returns the default allowlist.
func NewAllowExec() *AllowExec {
	return &AllowExec{Allow: []string{"auditpol.exe", "powershell.exe", "wusa.exe", "shutdown.exe"}, Timeout: 5 * time.Minute, MaxOut: 1 << 20}
}

type limitBuf struct {
	b   bytes.Buffer
	max int
}

func (l *limitBuf) Write(p []byte) (int, error) {
	if room := l.max - l.b.Len(); room > 0 {
		l.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (e *AllowExec) Run(ctx context.Context, prog string, args ...string) (string, int, error) {
	base := strings.ToLower(filepath.Base(strings.ReplaceAll(prog, `\`, "/")))
	ok := false
	for _, a := range e.Allow {
		if strings.EqualFold(a, base) {
			ok = true
		}
	}
	if !ok {
		return "", -1, fmt.Errorf("exec: %q is not on the allowlist", prog)
	}
	if e.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.Timeout)
		defer cancel()
	}
	max := e.MaxOut
	if max <= 0 {
		max = 1 << 20
	}
	out := &limitBuf{max: max}
	cmd := exec.CommandContext(ctx, prog, args...)
	cmd.Stdout, cmd.Stderr = out, out
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out.b.String(), ee.ExitCode(), nil
	}
	if err != nil {
		return out.b.String(), -1, err
	}
	return out.b.String(), 0, nil
}
