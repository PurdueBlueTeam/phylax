package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
)

// overridesFile is the on-disk shape of overrides.yml.
type overridesFile struct {
	Overrides Overrides `yaml:"overrides"`
}

// overridesMu serialises read-modify-write cycles inside one controller.
var overridesMu sync.Mutex

// AppendOverrides reads dir/overrides.yml (absent: empty), applies fn,
// validates, writes atomically and keeps mode 0600. On any error the file is
// unchanged.
//
// shortcut: AppendOverrides rewrites the file from the struct, so comments in
// overrides.yml are lost; upgrade to a yaml.Node round trip if operators
// hand-edit it.
func AppendOverrides(dir string, fn func(*Overrides) error) error {
	overridesMu.Lock()
	defer overridesMu.Unlock()

	ov, err := readOverrides(os.DirFS(dir))
	if err != nil {
		return err
	}
	if err := fn(&ov); err != nil {
		return err
	}
	var errs ErrorList
	validateOverrides(ov, &errs)
	if err := errs.Err(); err != nil {
		return err
	}
	buf, err := yaml.Marshal(overridesFile{Overrides: ov})
	if err != nil {
		return fmt.Errorf("overrides.yml: %w", err)
	}
	return atomicfile.Write(filepath.Join(dir, FileOverrides), 0o600, func(w io.Writer) error {
		_, err := w.Write(buf)
		return err
	})
}

// readOverrides reads dir/overrides.yml strictly without expanding `{{ }}`
// templates: a write path must keep untouched content byte-for-byte as it read
// it, and Load expands on the way in.
func readOverrides(fsys fs.FS) (Overrides, error) {
	n, ok, err := readNode(fsys, FileOverrides)
	if err != nil || !ok {
		return Overrides{}, err
	}
	raw, err := yaml.Marshal(n)
	if err != nil {
		return Overrides{}, fmt.Errorf("%s: %w", FileOverrides, err)
	}
	var f overridesFile
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return Overrides{}, fmt.Errorf("%s: %w", FileOverrides, err)
	}
	return f.Overrides, nil
}
