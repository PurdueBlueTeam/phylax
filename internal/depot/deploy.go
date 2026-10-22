package depot

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/integrity"
)

func writeFile(path string, data []byte, perm fs.FileMode) error {
	return atomicfile.WriteExactMode(path, data, perm)
}

// HiddenDir derives a per-event hidden directory under base from a secret
// (D-8: obscurity is a cheap extra layer, not a boundary). The same secret
// gives the same path, so the controller and operators can recompute it.
func HiddenDir(base, secret string) string {
	if base == "" {
		base = DefaultBase()
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("phylax-depot-dir"))
	return filepath.Join(base, "."+hex.EncodeToString(mac.Sum(nil))[:10])
}

// DefaultBase is where hidden depot directories are made.
func DefaultBase() string {
	if runtime.GOOS == "windows" {
		return os.Getenv("ProgramData")
	}
	return "/var/tmp"
}

// Deployed is a depot directory on a host: <dir>/depot.json (signed manifest)
// and <dir>/bin/<tool>.
type Deployed struct {
	Dir          string
	M            *Manifest
	GOOS, GOARCH string
	raw          []byte
}

// BinDir is the only directory on the sanitised PATH.
func (d *Deployed) BinDir() string { return filepath.Join(d.Dir, "bin") }

// Report says what a deployment did.
type Report struct {
	Deployed []string
	Missing  []string // in the manifest but not in the store (not yet fetched)
}

// Deploy copies the platform's tools from the store into dir with restrictive
// permissions (dir 0700, tools 0500), verifying each blob's hash on the way,
// and creates applet symlinks for multi-call binaries. raw is the signed
// manifest, written next to the tools so the host copy can be re-verified.
func Deploy(st Store, m *Manifest, raw []byte, dir, goos, goarch string) (Report, error) {
	var rep Report
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		return rep, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return rep, err
	}
	if err := os.Chmod(bin, 0o700); err != nil {
		return rep, err
	}
	for _, e := range m.For(goos, goarch) {
		if e.SHA256 == "" || !st.Has(e.SHA256) {
			rep.Missing = append(rep.Missing, e.Name)
			continue
		}
		b, err := st.ReadVerified(e.SHA256)
		if err != nil {
			return rep, fmt.Errorf("deploy %s: %w", e.Name, err)
		}
		if e.Size > 0 && int64(len(b)) != e.Size {
			return rep, fmt.Errorf("deploy %s: size %d, manifest says %d", e.Name, len(b), e.Size)
		}
		if err := writeFile(filepath.Join(bin, e.File()), b, 0o500); err != nil {
			return rep, fmt.Errorf("deploy %s: %w", e.Name, err)
		}
		rep.Deployed = append(rep.Deployed, e.Name)
	}
	if runtime.GOOS != "windows" {
		have := map[string]bool{}
		for _, e := range m.For(goos, goarch) {
			have[e.File()] = true
		}
		for _, e := range m.For(goos, goarch) {
			for _, a := range e.Provides {
				if have[a] {
					continue
				}
				l := filepath.Join(bin, a)
				if cur, err := os.Readlink(l); err == nil && cur == e.File() {
					continue
				}
				os.Remove(l)
				if err := os.Symlink(e.File(), l); err != nil {
					return rep, err
				}
				have[a] = true
			}
		}
	}
	if err := writeFile(filepath.Join(dir, "depot.json"), raw, 0o600); err != nil {
		return rep, err
	}
	sort.Strings(rep.Deployed)
	return rep, nil
}

// OpenDeployed loads and signature-checks the manifest in a deployed directory.
func OpenDeployed(dir string, v integrity.Verifier) (*Deployed, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "depot.json"))
	if err != nil {
		return nil, err
	}
	m, err := Parse(raw, v)
	if err != nil {
		return nil, err
	}
	return &Deployed{Dir: dir, M: m, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, raw: raw}, nil
}

// Problem is one verification failure.
type Problem struct {
	Tool, Path, What string
}

func (p Problem) String() string { return fmt.Sprintf("%s: %s (%s)", p.Tool, p.What, p.Path) }

// readTool reads a deployed tool and checks it against the manifest. The
// returned bytes are what was hashed, so callers can execute exactly those.
func (d *Deployed) readTool(e Entry) ([]byte, error) {
	p := filepath.Join(d.BinDir(), e.File())
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%s is group or world writable", p)
	}
	if e.SHA256 == "" {
		return nil, fmt.Errorf("%s has no pinned hash", e.Name)
	}
	if fi.Size() > MaxToolSize {
		return nil, fmt.Errorf("%s is too large", p)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != e.SHA256 {
		return nil, fmt.Errorf("%s: hash %x does not match the manifest", p, sum[:8])
	}
	return b, nil
}

// Verify checks every tool of the platform, and reports files in bin/ that the
// manifest does not account for (a planted binary or applet symlink).
func (d *Deployed) Verify() []Problem {
	var out []Problem
	known := map[string]bool{}
	for _, e := range d.M.For(d.GOOS, d.GOARCH) {
		known[e.File()] = true
		if _, err := d.readTool(e); err != nil {
			out = append(out, Problem{e.Name, filepath.Join(d.BinDir(), e.File()), err.Error()})
		}
	}
	for _, e := range d.M.For(d.GOOS, d.GOARCH) {
		for _, a := range e.Provides {
			if known[a] {
				continue
			}
			p := filepath.Join(d.BinDir(), a)
			if runtime.GOOS == "windows" {
				continue
			}
			if tgt, err := os.Readlink(p); err != nil || tgt != e.File() {
				out = append(out, Problem{a, p, "applet link missing or redirected"})
			}
			known[a] = true
		}
	}
	ents, err := os.ReadDir(d.BinDir())
	if err != nil {
		return append(out, Problem{"", d.BinDir(), err.Error()})
	}
	for _, de := range ents {
		if !known[de.Name()] {
			out = append(out, Problem{de.Name(), filepath.Join(d.BinDir(), de.Name()), "not in the manifest"})
		}
	}
	return out
}
