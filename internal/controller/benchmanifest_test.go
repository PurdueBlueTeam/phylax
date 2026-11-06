package controller

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/enroll"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

const benchManifestScript = "../../tools/bench/make-bench-manifest.sh"

// runBenchManifest runs the generator and returns its combined output and
// error; the script needs a POSIX shell.
func runBenchManifest(t *testing.T, args ...string) (string, error) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("make-bench-manifest.sh needs a POSIX shell")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not found")
	}
	cmd := exec.Command("sh", append([]string{benchManifestScript}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// makeBenchManifest runs the generator and fails the test on error.
func makeBenchManifest(t *testing.T, args ...string) string {
	t.Helper()
	out, err := runBenchManifest(t, args...)
	if err != nil {
		t.Fatalf("make-bench-manifest %v: %v\n%s", args, err, out)
	}
	return out
}

// The generated manifest is a loadable copy with N bench hosts, a config that
// does no host work and bundles the controller accepts.
func TestBenchManifest(t *testing.T) {
	src := "../../manifest/2027"
	dst := filepath.Join(t.TempDir(), "m")
	out := makeBenchManifest(t, src, dst, "30")
	if want := "bench manifest: " + dst + " (30 hosts)"; !strings.Contains(out, want) {
		t.Fatalf("output %q does not contain %q", out, want)
	}

	srcM, err := manifest.LoadDir(src, manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.LoadDir(dst, manifest.Options{})
	if err != nil {
		t.Fatalf("generated manifest: %v", err)
	}
	if len(m.Hosts) != len(srcM.Hosts)+30 {
		t.Fatalf("hosts = %d, want %d (the source's %d plus 30)", len(m.Hosts), len(srcM.Hosts)+30, len(srcM.Hosts))
	}
	for _, name := range []string{"bench-001", "bench-030"} {
		h, ok := m.Hosts[name]
		if !ok {
			t.Fatalf("host %s missing from the generated manifest", name)
		}
		if h.Segment != "lan" || h.IsWindows() || len(h.Roles) != 0 || h.IP == "dhcp" {
			t.Fatalf("%s = %+v, want a lan debian host with no roles and a fixed ip", name, h)
		}
	}
	// Addresses stay unique even past the first /24 (i=240 wraps the last octet).
	byIP := map[string]string{}
	for name, h := range m.Hosts {
		if h.IP == "dhcp" {
			continue
		}
		if other, ok := byIP[h.IP]; ok {
			t.Fatalf("%s and %s share ip %s", other, name, h.IP)
		}
		byIP[h.IP] = name
	}

	// A bench host gets a config with no host work in it: no rules, no
	// deception, no service map, web roots, binaries or pins, and act off.
	// shortcut: design-s renders the segment's canary probes and nflog groups
	// into every Linux host, so those two are excluded here; they cost a
	// synthetic agent nothing because the load run registers its own module
	// list and no factories. Upgrade if BuildAgentConfig learns per-host
	// module blocks (manifest.Host.Modules is already modelled).
	in, err := LoadConfigInputs(Config{ManifestPath: dst})
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, err := BuildAgentConfig(in, "bench-001")
	if err != nil {
		t.Fatalf("bench-001: %v", err)
	}
	if cfg.Roles == nil || len(cfg.Roles) != 0 {
		t.Errorf("bench-001 roles = %v, want none", cfg.Roles)
	}
	if cfg.Modules.Detect != nil {
		t.Errorf("bench-001 detect block present: %+v", cfg.Modules.Detect)
	}
	if cfg.Modules.Deception != nil {
		t.Errorf("bench-001 deception block present: %+v", cfg.Modules.Deception)
	}
	if cfg.Modules.Winevt != nil {
		t.Errorf("bench-001 winevt block present on a debian host: %+v", cfg.Modules.Winevt)
	}
	if b := cfg.Modules.Net; b != nil {
		if b.ActEnabled || len(b.Services) != 0 {
			t.Errorf("bench-001 net block is not inert: %+v", b)
		}
	}
	if b := cfg.Modules.Audit; b != nil {
		if b.ActEnabled || len(b.WebRoots) != 0 || len(b.ServiceBinaries) != 0 || len(b.ExtraWatches) != 0 {
			t.Errorf("bench-001 audit block is not inert: %+v", b)
		}
	}
	if b := cfg.Modules.Integrity; b != nil {
		if b.ActEnabled || len(b.Pins) != 0 {
			t.Errorf("bench-001 integrity block is not inert: %+v", b)
		}
	}
	if b := cfg.Modules.Health; b == nil || b.ActEnabled {
		t.Errorf("bench-001 health block = %+v, want present and act off", b)
	}
	// A scored host does get content, so the checks above prove the generator
	// produced a bench host rather than an inert config for every host.
	email, _, err := BuildAgentConfig(in, "ubuntu-email")
	if err != nil {
		t.Fatal(err)
	}
	if email.Modules.Net == nil || len(email.Modules.Net.Services) == 0 {
		t.Fatalf("ubuntu-email has no service map; cannot prove the bench config is inert")
	}

	// The controller accepts the bench hosts (they are in its manifest).
	ccfg := Config{DataDir: t.TempDir()}
	if err := ccfg.Validate(); err != nil {
		t.Fatal(err)
	}
	c, err := New(context.Background(), ccfg, Options{
		HostKnown: func(h string) bool { _, ok := m.Hosts[h]; return ok },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	dir := filepath.Join(t.TempDir(), "bundles")
	if err := c.Enroller().WriteBundles(dir, []string{"bench-001", "bench-030"}, enroll.BundleOptions{Controllers: []string{"127.0.0.1:7443"}}); err != nil {
		t.Fatalf("bundles for bench hosts: %v", err)
	}
	for _, name := range []string{"bench-001", "bench-030"} {
		b, err := os.ReadFile(filepath.Join(dir, name+".json"))
		if err != nil {
			t.Fatalf("bundle for %s: %v", name, err)
		}
		var body struct {
			Host string `json:"host"`
		}
		if err := json.Unmarshal(b, &body); err != nil {
			t.Fatalf("bundle for %s: %v", name, err)
		}
		if body.Host != name {
			t.Fatalf("bundle for %s carries host %q", name, body.Host)
		}
	}
	// Proof that the hosts are known because the manifest lists them.
	if err := c.Enroller().WriteBundles(filepath.Join(t.TempDir(), "b"), []string{"bench-031"}, enroll.BundleOptions{Controllers: []string{"127.0.0.1:7443"}}); err == nil {
		t.Fatal("a bundle for the absent host bench-031 was written")
	}
}

// The generator refuses a destination it would edit and an N out of range,
// and leaves the destination untouched.
func TestBenchManifestRefusals(t *testing.T) {
	src := "../../manifest/2027"
	base := t.TempDir()

	t.Run("non-empty dst", func(t *testing.T) {
		dst := filepath.Join(base, "full")
		if err := os.MkdirAll(dst, 0o755); err != nil {
			t.Fatal(err)
		}
		keep := filepath.Join(dst, "keep")
		if err := os.WriteFile(keep, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := runBenchManifest(t, src, dst, "3"); err == nil {
			t.Fatalf("non-empty DST accepted: %s", out)
		}
		if b, err := os.ReadFile(keep); err != nil || string(b) != "x" {
			t.Fatalf("non-empty DST was touched: %q, %v", b, err)
		}
		if _, err := os.Stat(filepath.Join(dst, "hosts.yml")); !os.IsNotExist(err) {
			t.Fatalf("non-empty DST gained a manifest: %v", err)
		}
	})

	for _, n := range []string{"0", "501", "-1", "ten"} {
		t.Run("n "+n, func(t *testing.T) {
			dst := filepath.Join(base, "n"+strings.ReplaceAll(n, "-", "neg"))
			if out, err := runBenchManifest(t, src, dst, n); err == nil {
				t.Fatalf("N %s accepted: %s", n, out)
			}
			if _, err := os.Stat(dst); !os.IsNotExist(err) {
				t.Fatalf("refused N %s left DST behind: %v", n, err)
			}
		})
	}
}
