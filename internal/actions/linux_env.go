package actions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

// Cmd is one host command (the host.exec escape hatch, used only by the
// package and probe actions, with fixed argv built by the action, never by a
// shell).
type Cmd struct {
	Argv    []string
	Env     []string // extra KEY=VALUE entries (e.g. the patch-window proxy)
	Timeout time.Duration
}

// CmdResult is a finished command.
type CmdResult struct {
	Stdout, Stderr string
	ExitCode       int
}

// CommandRunner runs host commands. Tests use a fake; the default runs
// os/exec with bounded output and a deadline.
type CommandRunner interface {
	Run(ctx context.Context, c Cmd) (CmdResult, error)
}

// PatchWindow is an open, time-boxed patch window for this host (design:
// "Patch windows and the cache").
type PatchWindow struct {
	ID    string
	Tag   string
	Proxy string // loopback proxy URL the package manager uses
	Until time.Time
}

// LinuxEnv carries the replaceable backends of the Linux/application actions.
// Every field is optional; the zero value selects real defaults.
type LinuxEnv struct {
	Exec CommandRunner
	// PatchWindow returns the open patch window for this host, or an error
	// (or nil) when none is open. nil means "no window ever".
	PatchWindow func(ctx context.Context) (*PatchWindow, error)
	// DepotDir is the local package depot ("depot:<rel>" sources resolve here).
	DepotDir string
	// PinnedTools maps a tool path to its expected sha256 (hex). A tool listed
	// here is hashed before every run; unlisted tools are not checked.
	PinnedTools map[string]string
	Firewall    FirewallBackend
	MySQL       MySQLDialer
	// MySQLAuth is the account the agent connects to the local database as
	// (default root with no password, i.e. unix_socket authentication). The
	// password is never part of a param or a rollback entry.
	MySQLAuth struct{ User, Password string }
	HTTP      *http.Client
	Dial      func(ctx context.Context, network, addr string) (net.Conn, error)
	Wazuh     func(ctx context.Context, api, minVersion string) (WazuhAPI, error)
	Attr      AttrBackend
	// UnloadModule unloads a kernel module (default: delete_module(2)).
	UnloadModule func(name string) error
	// PackageManager forces "apt" or "dnf"; empty detects from the filesystem.
	PackageManager string
}

// lx returns the Linux backends, never nil.
func (e *Env) lx() *LinuxEnv {
	if e.Linux == nil {
		return &LinuxEnv{}
	}
	return e.Linux
}

func (l *LinuxEnv) runner() CommandRunner {
	if l.Exec != nil {
		return l.Exec
	}
	return execRunner{pinned: l.PinnedTools}
}

const maxCmdOutput = 1 << 20

type execRunner struct{ pinned map[string]string }

type capBuf struct {
	b bytes.Buffer
	n int
}

func (c *capBuf) Write(p []byte) (int, error) {
	if room := c.n - c.b.Len(); room > 0 {
		if len(p) > room {
			c.b.Write(p[:room])
		} else {
			c.b.Write(p)
		}
	}
	return len(p), nil // drop the excess, never block the child
}

func (r execRunner) Run(ctx context.Context, c Cmd) (CmdResult, error) {
	if len(c.Argv) == 0 || !filepath.IsAbs(c.Argv[0]) {
		return CmdResult{}, errors.New("host command needs an absolute path")
	}
	if want, ok := r.pinned[c.Argv[0]]; ok {
		got, err := hashFile(c.Argv[0], "sha256")
		if err != nil {
			return CmdResult{}, err
		}
		if !strings.EqualFold(got, want) {
			return CmdResult{}, fmt.Errorf("%s does not match its pinned hash", c.Argv[0])
		}
	}
	to := c.Timeout
	if to <= 0 {
		to = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Argv[0], c.Argv[1:]...)
	cmd.Env = append([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive"}, c.Env...)
	var so, se capBuf
	so.n, se.n = maxCmdOutput, maxCmdOutput
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	res := CmdResult{Stdout: so.b.String(), Stderr: se.b.String()}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		res.ExitCode = ee.ExitCode()
		return res, nil
	}
	return res, err
}

// requireWindow returns the open patch window or an error naming the rule.
func (e *Env) requireWindow(ctx context.Context) (*PatchWindow, error) {
	l := e.lx()
	if l.PatchWindow == nil {
		return nil, errors.New("package change refused: no patch window is declared on this host")
	}
	w, err := l.PatchWindow(ctx)
	if err != nil {
		return nil, fmt.Errorf("package change refused: %w", err)
	}
	if w == nil || (!w.Until.IsZero() && !e.now().Before(w.Until)) {
		return nil, errors.New("package change refused: no open patch window (it closed or never opened)")
	}
	return w, nil
}

func sha256Hex(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// readFileIfExists returns (nil, false, nil) for a missing file.
func readFileIfExists(path string) ([]byte, bool, error) {
	b, _, err := readBounded(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

// linuxHandlers returns the dead-man rollback handlers of this file group.
func linuxHandlers(env *Env) map[string]deadman.Handler {
	return map[string]deadman.Handler{
		kindSysctlRestore: func(ctx context.Context, e deadman.Entry) error { return undoSysctl(ctx, env, e) },
		kindAttrUndo:      func(ctx context.Context, e deadman.Entry) error { return undoAttr(ctx, env, e) },
		kindRenameUndo:    undoRename,
		kindMySQLUnlock:   func(ctx context.Context, e deadman.Entry) error { return undoMySQLLock(ctx, env, e) },
		kindFWAllowUndo:   func(ctx context.Context, e deadman.Entry) error { return undoFirewallAllow(ctx, env, e) },
		kindRestoreThen:   func(ctx context.Context, e deadman.Entry) error { return undoRestoreThen(ctx, env, e) },
		kindMultiService:  func(ctx context.Context, e deadman.Entry) error { return undoMultiService(ctx, env, e) },
	}
}

// restoreSnapshots puts snapshotted files back (idempotent), like the
// built-in file.restore handler, for composite rollbacks.
func restoreSnapshots(fr deadman.FileRestore) error {
	var errs []error
	for _, s := range fr.Files {
		if !s.Existed {
			if err := os.Remove(s.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		if err := atomicfile.WriteExactMode(s.Path, s.Content, s.Mode); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// DaemonReloader is implemented by service managers that can reload their
// unit definitions (systemd daemon-reload).
type DaemonReloader interface {
	DaemonReload(ctx context.Context) error
}

const kindRestoreThen = "linux.restore_then"

// restoreThen is the rollback data of actions that change files and then
// reload/restart something: put the files back, then redo the reload.
type restoreThen struct {
	Files        deadman.FileRestore `json:"files"`
	DaemonReload bool                `json:"daemon_reload,omitempty"`
	Restart      []string            `json:"restart,omitempty"`
}

func undoRestoreThen(ctx context.Context, env *Env, e deadman.Entry) error {
	var r restoreThen
	if err := json.Unmarshal(e.Data, &r); err != nil {
		return err
	}
	errs := []error{restoreSnapshots(r.Files)}
	if r.DaemonReload {
		if dr, ok := env.Services.(DaemonReloader); ok {
			errs = append(errs, dr.DaemonReload(ctx))
		}
	}
	for _, u := range r.Restart {
		if env.Services != nil {
			errs = append(errs, env.Services.Restart(ctx, u))
		}
	}
	return errors.Join(errs...)
}
