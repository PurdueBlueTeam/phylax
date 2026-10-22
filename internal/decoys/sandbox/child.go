package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/PurdueBlueTeam/phylax/internal/decoys"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/honeytokens"
)

// MaybeRunChild turns the process into the decoy child when ChildEnv is set,
// and returns otherwise. Call it first thing from an init or from main.
func MaybeRunChild() {
	if os.Getenv(ChildEnv) != "1" {
		return
	}
	os.Exit(RunChild(os.Stdin, os.Stdout, os.Stderr))
}

// RunChild is the child's main. Inherited sockets start at fd 3, in the order
// of Spec.Listeners. It returns the process exit code.
func RunChild(stdin io.Reader, stdout, stderr io.Writer) int {
	fail := func(format string, a ...any) int {
		msg := fmt.Sprintf(format, a...)
		fmt.Fprintln(stderr, msg)
		_ = writeMsg(stdout, nil, wireMsg{Err: msg})
		return 1
	}
	// First act: lose the ability to gain privilege. Then read the spec.
	nnpErr := noNewPrivs()
	br := bufio.NewReaderSize(stdin, 64<<10)
	line, err := readLine(br, maxSpecBytes)
	if err != nil {
		return fail("decoy child: read configuration: %v", err)
	}
	var spec Spec
	if err := json.Unmarshal(line, &spec); err != nil {
		return fail("decoy child: bad configuration: %v", err)
	}
	if nnpErr != nil && osIsLinux() {
		return fail("decoy child: no_new_privs: %v", nnpErr)
	}
	if spec.MustBeUnprivileged && os.Geteuid() == 0 {
		return fail("decoy child: refusing to run as root after a requested privilege drop")
	}
	reg := honeytokens.NewRegistry()
	for _, t := range spec.Tokens {
		if err := reg.Add(t); err != nil {
			return fail("decoy child: token: %v", err)
		}
	}
	cfg := decoys.Config{Host: spec.Host, Bind: spec.Bind, Listeners: spec.Listeners, ScoredPorts: spec.ScoredPorts,
		Tokens: reg, AllowEphemeral: spec.AllowEphemeral, Logger: slog.New(slog.NewTextHandler(stderr, nil)),
		Prebound: map[uint16]net.Listener{}}
	if spec.HostKeyPEM != "" {
		if cfg.HostKey, err = ssh.ParsePrivateKey([]byte(spec.HostKeyPEM)); err != nil {
			return fail("decoy child: host key: %v", err)
		}
	}
	for i, l := range spec.Listeners {
		f := os.NewFile(uintptr(3+i), "decoy-listener")
		ln, err := net.FileListener(f)
		_ = f.Close()
		if err != nil {
			return fail("decoy child: inherited socket %d: %v", 3+i, err)
		}
		cfg.Prebound[l.Port] = ln
	}
	m, err := decoys.New(cfg)
	if err != nil {
		return fail("decoy child: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Lifeline: the parent holds the write end of our stdin. EOF = parent gone.
	go func() {
		_, _ = io.Copy(io.Discard, br)
		cancel()
	}()
	var wmu sync.Mutex
	emit := func(e event.Event) error {
		err := writeMsg(stdout, &wmu, wireMsg{Ev: &e})
		if err != nil {
			cancel()
		}
		return err
	}
	go func() {
		select {
		case <-m.Ready():
			_ = writeMsg(stdout, &wmu, wireMsg{Ready: true})
		case <-ctx.Done():
		}
	}()
	if err := m.Start(ctx, emit); err != nil && !errors.Is(err, context.Canceled) {
		return fail("decoy child: %v", err)
	}
	return 0
}

func osIsLinux() bool { return noNewPrivsSupported }

func writeMsg(w io.Writer, mu *sync.Mutex, m wireMsg) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}
	_, err = w.Write(b)
	return err
}

func readLine(br *bufio.Reader, max int) ([]byte, error) {
	var out []byte
	for {
		chunk, isPrefix, err := br.ReadLine()
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		if len(out) > max {
			return nil, errors.New("line too long")
		}
		if !isPrefix {
			return out, nil
		}
	}
}
