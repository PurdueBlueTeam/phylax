package controller

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

const makeObserveScript = "../../tools/invitational/make-observe-manifest.sh"

func requireSh(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("make-observe-manifest.sh needs a POSIX shell")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not found")
	}
}

// makeObserve runs the generator and returns its combined output.
func makeObserve(t *testing.T, args ...string) string {
	t.Helper()
	requireSh(t)
	cmd := exec.Command("sh", append([]string{makeObserveScript}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make-observe-manifest %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// The generated manifest keeps decoys, turns canary probes off and leaves
// every module's act switch off.
func TestObserveManifest(t *testing.T) {
	obs := filepath.Join(t.TempDir(), "obs")
	out := makeObserve(t, "../../manifest/2027", obs)
	if want := "observe manifest: " + obs; !strings.Contains(out, want) {
		t.Fatalf("output %q does not contain %q", out, want)
	}

	in, err := LoadConfigInputs(Config{ManifestPath: obs, RulesPath: "../../rules"})
	if err != nil {
		t.Fatal(err)
	}
	src, err := manifest.LoadDir("../../manifest/2027", manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}

	for name := range src.Hosts {
		h, ok := in.Manifest.Hosts[name]
		if !ok {
			t.Fatalf("host %s missing from the generated manifest", name)
		}
		cfg, _, err := BuildAgentConfig(in, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if cfg.Modules.Detect == nil || cfg.Modules.Detect.ActEnabled {
			t.Errorf("%s: detect must be present and act off", name)
		}
		if h.IsWindows() {
			if cfg.Modules.Winevt == nil {
				t.Errorf("%s: winevt module missing", name)
			}
		} else {
			if cfg.Modules.Net == nil {
				t.Errorf("%s: net module missing", name)
			} else if len(cfg.Modules.Net.Canaries) != 0 {
				t.Errorf("%s: canaries still probed: %v", name, cfg.Modules.Net.Canaries)
			}
		}
		if src.Hosts[name].HasRole(manifest.RoleDecoys) {
			if !h.HasRole(manifest.RoleDecoys) {
				t.Errorf("%s: decoys role dropped by default", name)
			}
			if cfg.Modules.Deception == nil {
				t.Errorf("%s: decoys role kept but deception settings are nil", name)
			}
		}
	}

	// The source manifest does probe canaries, so the check above proves the
	// generator changed something rather than the manifest lacking canaries.
	srcIn, err := LoadConfigInputs(Config{ManifestPath: "../../manifest/2027", RulesPath: "../../rules"})
	if err != nil {
		t.Fatal(err)
	}
	srcCfg, _, err := BuildAgentConfig(srcIn, "rocky-ecom")
	if err != nil {
		t.Fatal(err)
	}
	if srcCfg.Modules.Net == nil || len(srcCfg.Modules.Net.Canaries) == 0 {
		t.Fatal("source manifest has no canaries; cannot prove the generator removed them")
	}
}

// --no-decoys drops decoys.yml and the role from every host.
func TestObserveManifestNoDecoys(t *testing.T) {
	obs := filepath.Join(t.TempDir(), "obs")
	makeObserve(t, "../../manifest/2027", obs, "--no-decoys")

	if _, err := os.Stat(filepath.Join(obs, "decoys.yml")); !os.IsNotExist(err) {
		t.Fatalf("decoys.yml still exists: %v", err)
	}
	in, err := LoadConfigInputs(Config{ManifestPath: obs, RulesPath: "../../rules"})
	if err != nil {
		t.Fatal(err)
	}
	for name, h := range in.Manifest.Hosts {
		if h.HasRole(manifest.RoleDecoys) {
			t.Errorf("%s: decoys role still present", name)
		}
		cfg, _, err := BuildAgentConfig(in, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if cfg.Modules.Deception != nil {
			t.Errorf("%s: deception settings present without the decoys role", name)
		}
		if cfg.Modules.Detect == nil || cfg.Modules.Detect.ActEnabled {
			t.Errorf("%s: detect must be present and act off", name)
		}
		if !h.IsWindows() && (cfg.Modules.Net == nil || len(cfg.Modules.Net.Canaries) != 0) {
			t.Errorf("%s: canaries still probed", name)
		}
	}
}

func TestObserveManifestRefusesNonEmptyDest(t *testing.T) {
	requireSh(t)
	dst := filepath.Join(t.TempDir(), "obs")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(dst, "keep.txt")
	if err := os.WriteFile(keep, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("sh", makeObserveScript, "../../manifest/2027", dst)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("script accepted a non-empty destination: %s", out)
	}
	if !strings.Contains(strings.ToLower(string(out)), "non-empty") {
		t.Fatalf("refusal message does not say non-empty: %s", out)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("existing destination file removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "policy.yml")); !os.IsNotExist(err) {
		t.Fatalf("script copied into a non-empty destination")
	}
}
