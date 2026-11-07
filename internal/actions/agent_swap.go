package actions

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/deadman"
	"github.com/PurdueBlueTeam/phylax/internal/svcinstall"
)

// The agent.* family, part 2 (design: Lifecycle, binary replacement): replacing
// the agent binary and renaming its service go through one detached swap
// helper, because the agent is dead while the swap happens and cannot run its
// own rollback. The helper restarts the service and reverts if no controller
// ack arrives within 30 s; the action's rollback kind is the no-op below.
func init() {
	Register(func() []Action { return []Action{agentReplaceBinary{}, agentRename{}} })
	// The swap helper owns the revert (the agent is dead while it runs), so the
	// dead-man entry for these actions has nothing left to undo.
	RegisterUndo(kindAgentNoop, func(context.Context, *Env, deadman.Entry) error { return nil })
}

const (
	kindAgentNoop = "agent.noop"
	// maxBinaryBytes bounds the binary replace_binary hashes and accepts.
	maxBinaryBytes = 64 << 20
	// swapWaitSec is the helper's window for the new agent's first ack.
	swapWaitSec = 30
)

// binarySigningDomain separates a binary signature from every other plan-key
// signature (steps and controls have their own domains).
const binarySigningDomain = "phylax-binary\x00"

// BinarySigningBytes is what agent.replace_binary's Ed25519 signature covers:
// the domain separator followed by the raw sha256 of the new binary.
func BinarySigningBytes(sum [sha256.Size]byte) []byte {
	return append([]byte(binarySigningDomain), sum[:]...)
}

// binaryDigest hashes the binary at path (bounded).
func binaryDigest(path string) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	st, err := os.Stat(path)
	if err != nil {
		return sum, err
	}
	if !st.Mode().IsRegular() {
		return sum, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Size() > maxBinaryBytes {
		return sum, fmt.Errorf("%s is larger than %d bytes", path, maxBinaryBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return sum, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxBinaryBytes+1)); err != nil {
		return sum, err
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// verifyBinary checks the digest and the plan-key signature of the new binary.
func verifyBinary(path string, key ed25519.PublicKey, shaHex, sigB64 string) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("agent.replace_binary: no plan-signing key on this host")
	}
	want, err := hex.DecodeString(shaHex)
	if err != nil || len(want) != sha256.Size {
		return errors.New("agent.replace_binary: sha256 must be 64 hex characters")
	}
	sum, err := binaryDigest(path)
	if err != nil {
		return fmt.Errorf("agent.replace_binary: %w", err)
	}
	if string(want) != string(sum[:]) {
		return fmt.Errorf("agent.replace_binary: %s does not match sha256", path)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("agent.replace_binary: sig must be a base64 Ed25519 signature")
	}
	if !ed25519.Verify(key, BinarySigningBytes(sum), sig) {
		return errors.New("agent.replace_binary: signature does not verify with the plan key")
	}
	return nil
}

// startSwap writes the swap plan and hands it to the detached helper.
func startSwap(env *Env, p svcinstall.SwapPlan) error {
	path, err := agentPath(env, "swap.json")
	if err != nil {
		return err
	}
	if env.StartSwap == nil {
		return errors.New("actions: no swap helper on this host")
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := atomicfile.WriteFile(path, raw, 0o600); err != nil {
		return err
	}
	return env.StartSwap(path)
}

// runningBinary is this process's binary path.
func runningBinary() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("agent: cannot locate the running binary: %w", err)
	}
	return exe, nil
}

// agentReplaceBinary swaps the running agent for a signed binary. Lockout
// class: the dead-man window applies, and the helper reverts after 30 s
// without a controller ack.
type agentReplaceBinary struct{}

func (agentReplaceBinary) Spec() Spec {
	return Spec{Name: "agent.replace_binary", Risk: RiskLockout,
		Doc: "replace the agent binary with a file signed by the plan key and restart the agent (reverts if it does not reconnect)",
		Params: []ParamSpec{
			{Name: "path", Type: Path, Required: true},
			{Name: "sha256", Type: String, Required: true, Max: 64},
			{Name: "sig", Type: String, Required: true, Max: 128},
		}}
}

func (agentReplaceBinary) Locks(Params) []string  { return nil }
func (agentReplaceBinary) Touches(Params) []Touch { return nil }

func (agentReplaceBinary) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	path := p.Str("path")
	if err := verifyBinary(path, env.PlanKey, p.Str("sha256"), p.Str("sig")); err != nil {
		return Plan{}, err
	}
	exe, err := runningBinary()
	if err != nil {
		return Plan{}, err
	}
	return Plan{Diff: fmt.Sprintf("binary: %s -> %s (sha256 %s)", exe, path, p.Str("sha256")),
		Notes: []string{"the swap helper restarts the service and reverts after 30 s without a controller ack"}}, nil
}

func (agentReplaceBinary) Capture(context.Context, *Env, Params) (Rollback, error) {
	return Rollback{Kind: kindAgentNoop}, nil
}

func (agentReplaceBinary) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	// Re-verify: the file is what it was at Plan time, not something swapped in
	// between.
	if err := verifyBinary(p.Str("path"), env.PlanKey, p.Str("sha256"), p.Str("sig")); err != nil {
		return nil, err
	}
	exe, err := runningBinary()
	if err != nil {
		return nil, err
	}
	return nil, startSwap(env, svcinstall.SwapPlan{Kind: "replace_binary", Service: env.ServiceName,
		OldBinary: exe, NewBinary: p.Str("path"), StateDir: env.AgentRoot, WaitSec: swapWaitSec})
}

// Verify is the controller's own heartbeat check for the node: the agent cannot
// verify a swap it does not survive.
func (agentReplaceBinary) Verify(context.Context, *Env, Params) error { return nil }

// agentRename reinstalls the service under the names derived from a secret
// (design D-8: randomised names). Lockout class, same 30 s revert.
type agentRename struct{}

func (agentRename) Spec() Spec {
	return Spec{Name: "agent.rename", Risk: RiskLockout,
		Doc: "reinstall the agent service under the names derived from a hex secret (reverts if it does not reconnect)",
		Params: []ParamSpec{
			{Name: "secret", Type: String, Required: true, Max: 128, Secret: true, Check: func(v any) error {
				_, err := renameSecret(v.(string))
				return err
			}},
		}}
}

func (agentRename) Locks(Params) []string  { return nil }
func (agentRename) Touches(Params) []Touch { return nil }

// renameSecret decodes the hex secret (at least 8 bytes).
func renameSecret(s string) ([]byte, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.New("secret must be hex")
	}
	if len(raw) < 8 {
		return nil, errors.New("secret must be at least 8 bytes of hex")
	}
	return raw, nil
}

func (agentRename) names(p Params) (svcinstall.Names, error) {
	raw, err := renameSecret(p.Str("secret"))
	if err != nil {
		return svcinstall.Names{}, err
	}
	return svcinstall.DeriveNames(raw), nil
}

func (a agentRename) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	names, err := a.names(p)
	if err != nil {
		return Plan{}, err
	}
	if env.ServiceName == "" {
		return Plan{}, errors.New("agent.rename: the current service name is unknown")
	}
	return Plan{Diff: fmt.Sprintf("service: %s -> %s (binary %s)", env.ServiceName, names.Service, names.Binary),
		Notes: []string{"the swap helper restarts under the new name and reverts after 30 s without a controller ack"}}, nil
}

func (agentRename) Capture(context.Context, *Env, Params) (Rollback, error) {
	return Rollback{Kind: kindAgentNoop}, nil
}

func (a agentRename) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	names, err := a.names(p)
	if err != nil {
		return nil, err
	}
	if env.ServiceName == "" {
		return nil, errors.New("agent.rename: the current service name is unknown")
	}
	exe, err := runningBinary()
	if err != nil {
		return nil, err
	}
	name := names.Binary
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	// shortcut: rename changes the service and file names but not the install
	// directory or the state directory (so the identity and spool survive);
	// upgrade when the design needs the randomised directory too.
	dst := env.Resolve(filepath.Join(filepath.Dir(exe), name))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return nil, err
	}
	if err := copyBinary(exe, dst); err != nil {
		return nil, err
	}
	return nil, startSwap(env, svcinstall.SwapPlan{Kind: "rename", Service: env.ServiceName, NewBinary: dst,
		NewService: names.Service, StateDir: env.AgentRoot, WaitSec: swapWaitSec,
		Args: []string{"agent", "run", "--state-dir", env.AgentRoot, "--service-name", names.Service}})
}

func (agentRename) Verify(context.Context, *Env, Params) error { return nil }

// copyBinary copies src to dst as an executable, atomically.
func copyBinary(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return atomicfile.Write(dst, 0o755, func(w io.Writer) error { _, err := io.Copy(w, in); return err })
}
