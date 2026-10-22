package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// loadPlanKey reads the plan-signing key, generating it on first run. The file
// is written atomically with mode 0600 and a looser mode on an existing file
// is refused (on Windows the directory ACL is what protects it).
func loadPlanKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := atomicfile.WriteFile(path, pemBytes, 0o600); err != nil {
			return nil, fmt.Errorf("write plan key: %w", err)
		}
		return priv, nil
	}
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("plan key %s has mode %o: must not be accessible by group or others", path, fi.Mode().Perm())
		}
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("plan key %s: not PEM", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("plan key %s: %w", path, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("plan key %s: not Ed25519", path)
	}
	return priv, nil
}

// storeSeq allocates per-host step sequence numbers from the store, durably.
type storeSeq struct{ st *store.Store }

func (s storeSeq) Next(host string, _ uint64) (uint64, error) {
	return s.st.NextStepSeq(context.Background(), host)
}

var _ plan.SeqAllocator = storeSeq{}

// registryCatalog adapts the action registry to the plan engine's catalog.
// Locks are the static (parameter-independent) named locks; parameter-dependent
// ones (per file, per service) are taken by the agent's executor.
type registryCatalog struct{ reg *actions.Registry }

var staticLocks = map[string]bool{actions.LockAccounts: true, actions.LockFirewall: true,
	actions.LockSSHD: true, actions.LockPackages: true, actions.LockAudit: true}

func (r registryCatalog) Action(name string) (plan.ActionSpec, bool) {
	a, err := r.reg.Get(name)
	if err != nil {
		return plan.ActionSpec{}, false
	}
	spec := a.Spec()
	var locks []string
	for _, l := range a.Locks(actions.Params{}) {
		if staticLocks[l] {
			locks = append(locks, l)
		}
	}
	return plan.ActionSpec{Name: spec.Name, Risk: plan.Risk(spec.Risk), Locks: locks,
		ValidateParams: func(m map[string]any) error { _, err := spec.Validate(m); return err }}, true
}

// ctlSeq allocates the per-host control sequence from the store, durably. It is
// a counter separate from the step sequence.
type ctlSeq struct{ st *store.Store }

func (s ctlSeq) Next(host string, _ uint64) (uint64, error) {
	return s.st.NextStepSeq(context.Background(), "control/"+host)
}

var _ plan.SeqAllocator = ctlSeq{}
