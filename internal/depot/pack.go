package depot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/integrity"
)

// SpecTool is one line of the build spec (depot/tools.json): an Entry without
// its hash and size, plus the file in the build output directory.
type SpecTool struct {
	Entry
	File string `json:"file,omitempty"` // path under the source dir; empty for FetchAtInit pins
}

// Spec is the input of Pack.
type Spec struct {
	Tools []SpecTool `json:"tools"`
}

// LoadSpec reads a spec file.
func LoadSpec(path string) (*Spec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Spec
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("depot: spec %s: %w", path, err)
	}
	return &s, nil
}

// Pack hashes each tool's file under srcDir, stores it in the store, and
// writes the signed manifest to the store. Tools whose file is absent from
// srcDir are an error unless they are fetch-at-init pins (their hash may be filled in later).
func Pack(spec *Spec, srcDir string, st Store, sg integrity.Signer, now time.Time) (*Manifest, error) {
	m := &Manifest{Format: formatVersion, Created: now.UTC().Format(time.RFC3339)}
	for _, t := range spec.Tools {
		e := t.Entry
		if t.File == "" {
			if !e.FetchAtInit {
				return nil, fmt.Errorf("depot: tool %q has no file and is not a fetch-at-init tool", e.Name)
			}
			m.Tools = append(m.Tools, e)
			continue
		}
		p := filepath.Join(srcDir, filepath.FromSlash(t.File))
		sum, size, err := st.PutFile(p)
		if err != nil {
			return nil, fmt.Errorf("depot: tool %q: %w", e.Name, err)
		}
		e.SHA256, e.Size = sum, size
		m.Tools = append(m.Tools, e)
	}
	data, err := Sign(m, sg)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(st.Dir, 0o700); err != nil {
		return nil, err
	}
	if err := writeFile(st.ManifestPath(), data, 0o644); err != nil {
		return nil, err
	}
	return m, nil
}
