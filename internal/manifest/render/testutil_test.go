package render

import (
	"flag"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

var update = flag.Bool("update", false, "rewrite golden files")

var refs = map[string]string{
	"2027":        "../../../manifest/2027",
	"two-segment": "../../../manifest/two-segment",
}

func loadRef(t *testing.T, name string) *manifest.Manifest {
	t.Helper()
	m, err := manifest.LoadDir(refs[name], manifest.Options{})
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return m
}

// golden compares got against testdata/golden/<path>, or rewrites it with -update.
func golden(t *testing.T, path, got string) {
	t.Helper()
	full := filepath.Join("testdata", "golden", path)
	if *update {
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(full)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/manifest/render -update)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from golden (run with -update to accept):\n--- want\n%s\n--- got\n%s", path, want, got)
	}
}

// nftChecker validates rulesets with `nft -c -f`. It uses the local nft when
// that works (needs CAP_NET_ADMIN or root); otherwise, when PHYLAX_NFT_DOCKER=1,
// a throwaway alpine container with NET_ADMIN; otherwise it reports why the
// check cannot run.
type nftChecker struct {
	run    func(path string) ([]byte, error)
	reason string // set when unavailable
}

func newNFTChecker(t *testing.T) nftChecker {
	t.Helper()
	dir := t.TempDir()
	probe := filepath.Join(dir, "probe.nft")
	if err := os.WriteFile(probe, []byte("table inet phylax_probe {\n\tchain c { type filter hook input priority 0; policy accept; }\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var why []string
	if nft, err := exec.LookPath("nft"); err == nil {
		if out, err := exec.Command(nft, "-c", "-f", probe).CombinedOutput(); err == nil {
			return nftChecker{run: func(p string) ([]byte, error) { return exec.Command(nft, "-c", "-f", p).CombinedOutput() }}
		} else {
			why = append(why, "local nft cannot run -c without privileges: "+strings.TrimSpace(string(out)))
		}
	} else {
		why = append(why, "nft not installed")
	}
	if os.Getenv("PHYLAX_NFT_DOCKER") == "1" {
		if _, err := exec.LookPath("docker"); err == nil {
			// One container is started per file; the alpine image must be present or pullable.
			return nftChecker{run: func(p string) ([]byte, error) {
				abs, _ := filepath.Abs(p)
				return exec.Command("docker", "run", "--rm", "--cap-add", "NET_ADMIN", "-v", abs+":/r.nft:ro", "alpine:3",
					"sh", "-c", "apk add -q nftables >/dev/null 2>&1 && nft -c -f /r.nft").CombinedOutput()
			}}
		}
		why = append(why, "PHYLAX_NFT_DOCKER=1 but docker is not installed")
	} else {
		why = append(why, "set PHYLAX_NFT_DOCKER=1 to validate in a NET_ADMIN container")
	}
	return nftChecker{reason: strings.Join(why, "; ")}
}

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
