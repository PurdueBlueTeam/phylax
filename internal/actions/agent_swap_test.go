package actions

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/svcinstall"
)

// signBinary returns the hex sha256 of data and the base64 plan-key signature
// over it, in the form agent.replace_binary's params carry.
func signBinary(t *testing.T, key ed25519.PrivateKey, data []byte) (string, string) {
	t.Helper()
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), base64.StdEncoding.EncodeToString(ed25519.Sign(key, BinarySigningBytes(sum)))
}

func newSwapFixture(t *testing.T) (*fixture, *svcinstall.SwapPlan, *bool) {
	t.Helper()
	f := agentEnv(t)
	var got svcinstall.SwapPlan
	called := false
	f.env.StartSwap = func(path string) error {
		called = true
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return json.Unmarshal(raw, &got)
	}
	return f, &got, &called
}

func TestReplaceBinaryRejectsBadSignature(t *testing.T) {
	f, _, called := newSwapFixture(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.env.PlanKey = pub
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "phylax.new")
	data := []byte("NEW-BINARY")
	if err := os.WriteFile(bin, data, 0o755); err != nil {
		t.Fatal(err)
	}
	sha, sig := signBinary(t, other, data) // a key the agent does not hold
	cases := map[string]map[string]any{
		"signer is not the plan key": {"path": bin, "sha256": sha, "sig": sig},
		"digest does not match":      {"path": bin, "sha256": strings.Repeat("00", sha256.Size), "sig": sig},
		"signature is not base64":    {"path": bin, "sha256": sha, "sig": "not-base64!"},
		"signature is too short":     {"path": bin, "sha256": sha, "sig": base64.StdEncoding.EncodeToString([]byte("short"))},
	}
	for name, params := range cases {
		if _, err := f.run(t, "agent.replace_binary", params); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if *called {
		t.Fatal("the helper was started for a rejected plan")
	}
	if _, err := os.Stat(filepath.Join(f.env.AgentRoot, "swap.json")); !os.IsNotExist(err) {
		t.Fatal("a rejected plan wrote a swap file")
	}
}

func TestReplaceBinaryStartsDetachedHelper(t *testing.T) {
	f, got, called := newSwapFixture(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.env.PlanKey = pub
	bin := filepath.Join(t.TempDir(), "phylax.new")
	data := []byte("NEW-BINARY")
	if err := os.WriteFile(bin, data, 0o755); err != nil {
		t.Fatal(err)
	}
	sha, sig := signBinary(t, priv, data)
	if _, err := f.run(t, "agent.replace_binary", map[string]any{"path": bin, "sha256": sha, "sig": sig}); err != nil {
		t.Fatal(err)
	}
	if !*called {
		t.Fatal("the swap helper was not started")
	}
	if got.Kind != "replace_binary" || got.NewBinary != bin || got.WaitSec != 30 {
		t.Fatalf("swap plan %+v", *got)
	}
	if got.OldBinary == "" || got.StateDir != f.env.AgentRoot {
		t.Fatalf("swap plan %+v", *got)
	}
}

func TestRenameUsesDerivedNames(t *testing.T) {
	f, got, called := newSwapFixture(t)
	f.env.ServiceName = "old-svc"
	const secret = "00112233445566778899"
	if _, err := f.run(t, "agent.rename", map[string]any{"secret": secret}); err != nil {
		t.Fatal(err)
	}
	if !*called {
		t.Fatal("the swap helper was not started")
	}
	raw, err := hex.DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	want := svcinstall.DeriveNames(raw)
	if got.Kind != "rename" || got.Service != "old-svc" || got.NewService != want.Service {
		t.Fatalf("swap plan %+v, want service %q", *got, want.Service)
	}
	if !strings.HasSuffix(got.NewBinary, want.Binary) {
		t.Fatalf("new binary %q, want the derived file name %q", got.NewBinary, want.Binary)
	}
	if got.StateDir != f.env.AgentRoot || len(got.Args) == 0 {
		t.Fatalf("swap plan %+v", *got)
	}
}

func TestRenameRejectsBadSecret(t *testing.T) {
	f, _, called := newSwapFixture(t)
	for _, bad := range []string{"", "zz", "0011"} {
		if _, err := f.run(t, "agent.rename", map[string]any{"secret": bad}); err == nil {
			t.Errorf("accepted secret %q", bad)
		}
	}
	if *called {
		t.Fatal("the helper was started for a rejected plan")
	}
}
