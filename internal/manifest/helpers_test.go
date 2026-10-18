package manifest

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)
var refDir = "../../manifest"

func readRef(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(refDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func listFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}
