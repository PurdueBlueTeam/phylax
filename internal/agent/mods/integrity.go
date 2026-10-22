package mods

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/integrity"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// KindLedgerMissing is emitted while the reference ledger cannot be loaded.
const KindLedgerMissing = "integrity.ledger_unavailable"

func init() {
	agent.RegisterFactory(agent.Factory{
		Name: "integrity",
		Section: func(c *plan.AgentConfig) (string, bool) {
			if c.Modules.Integrity == nil {
				return "", false
			}
			return fp(c.Modules.Integrity), true
		},
		Build: func(env agent.Env, c *plan.AgentConfig) (agent.ModuleSpec, error) {
			s := c.Modules.Integrity
			if len(env.PlanKey) != ed25519.PublicKeySize {
				return agent.ModuleSpec{}, unavailable("no plan key to verify the ledger signature")
			}
			return spec(&integrityModule{env: env, s: s}, s.RatePerSec, s.Burst), nil
		},
	})
}

// integrityModule runs the exec-time, pinned-service and sweep checks against
// the signed reference ledger. Until the ledger file is present and matches
// the hash in the signed config it reports itself degraded and retries.
type integrityModule struct {
	env agent.Env
	s   *plan.IntegritySettings

	// ledgerRetry overrides the ledger poll interval (tests).
	ledgerRetry time.Duration
}

func (*integrityModule) Name() string { return "integrity" }

func (m *integrityModule) ledgerPath() string {
	f := m.s.Ledger.File
	if f == "" {
		f = "ledger.plx"
	}
	return filepath.Join(m.env.StateDir, filepath.Base(f))
}

func (m *integrityModule) loadLedger() (*integrity.Ledger, error) {
	data, err := os.ReadFile(m.ledgerPath())
	if err != nil {
		return nil, err
	}
	if want := strings.ToLower(m.s.Ledger.SHA256); want != "" {
		h := sha256.Sum256(data)
		if hex.EncodeToString(h[:]) != want {
			return nil, errors.New("ledger file does not match the sha256 in the signed config")
		}
	}
	return integrity.Unmarshal(data, integrity.Ed25519Verifier{Key: m.env.PlanKey})
}

func (m *integrityModule) Start(ctx context.Context, emit agent.Emit) error {
	retry := m.ledgerRetry
	if retry <= 0 {
		retry = 30 * time.Second
	}
	var ledger *integrity.Ledger
	for first := true; ledger == nil; first = false {
		l, err := m.loadLedger()
		if err == nil {
			ledger = l
			break
		}
		if first {
			_ = emit(event.Event{Kind: KindLedgerMissing, Priority: event.PriorityHigh,
				Fields: map[string]any{"module": "integrity", "path": m.ledgerPath(), "error": err.Error()}})
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(retry):
		}
	}
	ck, err := integrity.New(integrity.Config{
		Agent:     m.env.Host,
		Judge:     ledger,
		Emit:      func(e event.Event) { _ = emit(e) },
		Verifier:  integrity.NewSystemVerifier(),
		Allowlist: nil,
	})
	if err != nil {
		return err
	}
	execs, unsub := m.env.Subscribe(1024)
	defer unsub()

	pinEvery := secs(m.s.PinIntervalSec, time.Minute)
	sweepEvery := secs(m.s.SweepIntervalSec, 15*time.Minute)
	pinT, sweepT := time.NewTicker(pinEvery), time.NewTicker(sweepEvery)
	defer pinT.Stop()
	defer sweepT.Stop()
	sweeps := 0
	m.checkPins(ctx, ck)
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-execs:
			if ev.Kind == "process_start" {
				_, _ = ck.HandleProcessStart(ctx, ev)
			}
		case <-pinT.C:
			m.checkPins(ctx, ck)
		case <-sweepT.C:
			sweeps++
			roots := m.s.SweepRoots
			// Every tenth sweep ignores the identity cache, so a rootkit that
			// forges dev/inode/ctime/size is eventually caught.
			_, _ = ck.Sweep(ctx, integrity.SweepOptions{Roots: roots, BytesPerSec: 32 << 20, FullRehash: sweeps%10 == 0})
		}
	}
}

// checkPins verifies every running process whose image is a pinned binary.
func (m *integrityModule) checkPins(ctx context.Context, ck *integrity.Checker) {
	if runtime.GOOS != "linux" || len(m.s.Pins) == 0 {
		return
	}
	byPath := map[string]plan.PinSettings{}
	for _, p := range m.s.Pins {
		byPath[p.Path] = p
	}
	exes, _ := filepath.Glob("/proc/[0-9]*/exe")
	for _, e := range exes {
		if ctx.Err() != nil {
			return
		}
		tgt, err := os.Readlink(e)
		if err != nil {
			continue
		}
		p, ok := byPath[strings.TrimSuffix(tgt, " (deleted)")]
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(strings.Split(strings.TrimPrefix(e, "/proc/"), "/")[0])
		if err != nil {
			continue
		}
		_, _ = ck.CheckPin(ctx, integrity.Pin{Service: p.Service, PID: pid, Path: p.Path, Process: p.Unit})
	}
}
