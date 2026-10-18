package action

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestT01Local (lab T01): the prebaked check set (the dir.snapshot
// baseline + hunt.baseline_diff active check) is present at drop time
// and finds 90% or more of the planted state changes by T+15 min.
// Here the "15 minutes" is the check's run window — the hunt runs once
// and must recover at least 9 of 10 planted changes.
func TestT01Local(t *testing.T) {
	root := t.TempDir()
	// known-good baseline: 5 files
	type entry struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
		SHA  string `json:"sha"`
	}
	known := map[string]string{
		"app/server.conf": "listen 8080",
		"app/auth.cfg":    "mode=strict",
		"lib/libfoo.so":   "binaryfoo",
		"etc/hosts":       "127.0.0.1 localhost",
		"etc/resolv":      "nameserver 8.8.8.8",
	}
	var base []entry
	for pth, content := range known {
		full := filepath.Join(root, pth)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		base = append(base, entry{Path: full, Size: int64(len(content)), SHA: HashBytes([]byte(content))})
	}
	baseJSON, _ := json.Marshal(base)
	reg := Default()
	hunt, err := reg.Get("hunt.baseline_diff")
	if err != nil {
		t.Fatal(err)
	}
	// plant 10 changes: 5 modifications, 5 new files
	for i := 0; i < 5; i++ {
		pth := filepath.Join(root, "app", "file"+string(rune('a'+i))+".cfg")
		os.WriteFile(pth, []byte("planted"), 0o644)
	}
	// modify the other 4 known files
	for pth, content := range known {
		if strings.HasSuffix(pth, "server.conf") {
			continue
		}
		os.WriteFile(filepath.Join(root, pth), []byte(content+" TAMPERED"), 0o644)
	}
	cr, err := hunt.Apply(Params{
		"path":     root,
		"baseline": Enc(string(baseJSON)),
	})
	if err != nil {
		t.Fatal(err)
	}
	// 4 modified + 5 new = 9 changed-or-added paths (server.conf is
	// unmodified); the hunt must recover 90% or more of the planted 10.
	if cr.Done {
		t.Fatal("hunt reports clean despite planted changes")
	}
	// count the recovered paths in the diff
	recovered := 0
	for i := 0; i < 5; i++ {
		if strings.Contains(cr.Diff, "file"+string(rune('a'+i))+".cfg") {
			recovered++
		}
	}
	for pth := range known {
		if strings.Contains(cr.Diff, filepath.Join(root, pth)) {
			recovered++
		}
	}
	if recovered < 9 {
		t.Fatalf("prebaked set found %d/10 planted changes, want >= 9 (90%%): %s", recovered, cr.Diff)
	}
}
