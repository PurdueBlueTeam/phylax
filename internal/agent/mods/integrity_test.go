package mods

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/integrity"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// The ledger is accepted only when it matches the hash pinned in the signed
// config and carries the plan key's signature; until then the module reports
// itself unavailable and keeps retrying.
func TestIntegrityLedgerLoading(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, rogue, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	l := integrity.NewLedger(integrity.Meta{Name: "test"})
	good, err := l.Marshal(integrity.Ed25519Signer{Key: priv})
	if err != nil {
		t.Fatal(err)
	}
	forged, _ := l.Marshal(integrity.Ed25519Signer{Key: rogue})
	sum := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

	m := &integrityModule{env: agent.Env{StateDir: dir, PlanKey: pub}, s: &plan.IntegritySettings{Ledger: plan.LedgerRef{SHA256: sum(good)}}}
	if _, err := m.loadLedger(); !os.IsNotExist(err) {
		t.Fatalf("missing ledger: %v", err)
	}
	path := filepath.Join(dir, "ledger.plx")
	os.WriteFile(path, forged, 0o600)
	if _, err := m.loadLedger(); err == nil {
		t.Fatal("a ledger that is not the one pinned was accepted")
	}
	m.s.Ledger.SHA256 = sum(forged)
	if _, err := m.loadLedger(); err == nil {
		t.Fatal("a ledger signed by another key was accepted")
	}
	m.s.Ledger.SHA256 = sum(good)
	os.WriteFile(path, good, 0o600)
	if _, err := m.loadLedger(); err != nil {
		t.Fatalf("good ledger: %v", err)
	}
}

// Start reports the missing ledger once and keeps waiting until stopped.
func TestIntegrityWaitsForLedger(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	m := &integrityModule{env: agent.Env{StateDir: t.TempDir(), PlanKey: pub}, s: &plan.IntegritySettings{}, ledgerRetry: 10 * time.Millisecond}
	var evs []event.Event
	got := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- m.Start(ctx, func(e event.Event) error { evs = append(evs, e); got <- struct{}{}; return nil })
	}()
	<-got
	time.Sleep(60 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Kind != KindLedgerMissing {
		t.Fatalf("events: %+v", evs)
	}
}
