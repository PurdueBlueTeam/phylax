package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/decoys"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/honeytokens"
)

// ChildEnv, set to "1" in the environment of the child, makes RunChild take
// over the process. The agent's init calls MaybeRunChild before anything else.
const ChildEnv = "PHYLAX_DECOY_CHILD"

const (
	maxSpecBytes = 8 << 20
	maxLineBytes = 1 << 20
)

// Spec is the child's configuration. It travels on stdin.
type Spec struct {
	Host        string              `json:"host"`
	Bind        string              `json:"bind,omitempty"`
	Listeners   []decoys.Listener   `json:"listeners"`
	ScoredPorts []uint16            `json:"scored_ports,omitempty"`
	Tokens      []honeytokens.Token `json:"tokens,omitempty"`
	HostKeyPEM  string              `json:"host_key_pem,omitempty"`
	// MustBeUnprivileged makes the child refuse to run as root: set when the
	// parent asked for a credential drop, so a silently failed drop is fatal.
	MustBeUnprivileged bool `json:"must_be_unprivileged,omitempty"`
	// Tuning overrides, for tests.
	AllowEphemeral bool `json:"allow_ephemeral,omitempty"`
}

// Options configures the parent-side module.
type Options struct {
	Spec Spec
	// User is the unprivileged account for the child ("" = nobody, "-" = keep
	// the agent's identity).
	User   string
	Logger *slog.Logger
	// Exe is the binary to re-execute (default: the running executable).
	Exe string
	// ExtraEnv is appended to the child's environment (tests).
	ExtraEnv []string
}

// Module is the agent module that supervises the decoy child.
type Module struct {
	o       Options
	pid     atomic.Int64
	dropped atomic.Bool
	ready   chan struct{}
	once    sync.Once
}

// New returns the module. It validates the listener set exactly as the
// in-process module would (scored ports are refused before anything binds).
func New(o Options) (*Module, error) {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if err := (decoys.Config{Listeners: o.Spec.Listeners, ScoredPorts: o.Spec.ScoredPorts, AllowEphemeral: o.Spec.AllowEphemeral}).Validate(); err != nil {
		return nil, err
	}
	return &Module{o: o, ready: make(chan struct{})}, nil
}

// Name implements agent.Module (the sandboxed module replaces "decoys").
func (*Module) Name() string { return "decoys" }

// Ready is closed once the child reported that it is serving.
func (m *Module) Ready() <-chan struct{} { return m.ready }

// PID is the child's process id (0 before it starts).
func (m *Module) PID() int { return int(m.pid.Load()) }

// Dropped reports whether the child was started with a credential drop.
func (m *Module) Dropped() bool { return m.dropped.Load() }

type wireMsg struct {
	Ready bool         `json:"ready,omitempty"`
	Err   string       `json:"err,omitempty"`
	Ev    *event.Event `json:"ev,omitempty"`
}

// Start implements agent.Module: bind, spawn, relay events until ctx ends or
// the child exits (which is a crash for the supervisor to restart).
func (m *Module) Start(ctx context.Context, emit agent.Emit) error {
	spec := m.o.Spec
	// 1. Bind in the privileged parent.
	var files []*os.File
	var lns []net.Listener
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
		for _, l := range lns {
			_ = l.Close()
		}
	}()
	for _, l := range spec.Listeners {
		ln, err := net.Listen("tcp", net.JoinHostPort(spec.Bind, strconv.Itoa(int(l.Port))))
		if err != nil {
			return fmt.Errorf("decoys: listen %s on %d: %w", l.Kind, l.Port, err)
		}
		lns = append(lns, ln)
		tl, ok := ln.(*net.TCPListener)
		if !ok {
			return errors.New("decoys: not a TCP listener")
		}
		f, err := tl.File()
		if err != nil {
			return err
		}
		files = append(files, f)
	}
	// 2. Credentials and process.
	attr, dropped, err := sysProcAttr(m.o.User)
	if err != nil {
		return err
	}
	spec.MustBeUnprivileged = dropped
	m.dropped.Store(dropped)
	exe := m.o.Exe
	if exe == "" {
		if exe, err = os.Executable(); err != nil {
			return err
		}
	}
	cmd := exec.Command(exe)
	cmd.Env = append([]string{ChildEnv + "=1"}, m.o.ExtraEnv...) // nothing inherited: no secrets, no PATH tricks
	cmd.ExtraFiles = files
	cmd.SysProcAttr = attr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var errBuf lockedBuf
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("decoys: start child: %w", err)
	}
	m.pid.Store(int64(cmd.Process.Pid))
	for _, f := range files { // the child has its copies
		_ = f.Close()
	}
	files = nil

	// The spec is one JSON line; the pipe then stays open as the child's
	// lifeline.
	raw, err := json.Marshal(spec)
	if err == nil && len(raw) > maxSpecBytes {
		err = errors.New("decoys: child configuration too large")
	}
	if err == nil {
		_, err = stdin.Write(append(raw, '\n'))
	}
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("decoys: configure child: %w", err)
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = stdin.Close() // child exits on EOF
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				_ = cmd.Process.Kill()
			}
		case <-done:
		}
	}()

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	var childErr string
	for sc.Scan() {
		var w wireMsg
		if json.Unmarshal(sc.Bytes(), &w) != nil {
			continue
		}
		switch {
		case w.Ready:
			m.once.Do(func() { close(m.ready) })
		case w.Err != "":
			childErr = w.Err
		case w.Ev != nil:
			_ = emit(*w.Ev)
		}
	}
	werr := cmd.Wait()
	close(done)
	if ctx.Err() != nil {
		return nil
	}
	msg := childErr
	if msg == "" {
		msg = errBuf.String()
	}
	return fmt.Errorf("decoys: child exited (%v): %s", werr, msg)
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.b.Len() < 4096 {
		l.b.Write(p)
	}
	return len(p), nil
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
