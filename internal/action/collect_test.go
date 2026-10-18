package action

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectFiles(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "a.log")
	f2 := filepath.Join(dir, "b.log")
	if err := os.WriteFile(f1, []byte("alpha"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f2, []byte("beta beta"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "gone.log")

	old := evidenceDir
	evidenceDir = filepath.Join(dir, "evidence")
	t.Cleanup(func() { evidenceDir = old })

	a := collectFiles{}
	params := Params(map[string]any{"paths": []string{f1, f2, missing}, "label": "test"})
	r, err := a.Check(params)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Diff, "missing") {
		t.Fatalf("check should list missing, got %q", r.Diff)
	}
	r, err = a.Apply(params)
	if err != nil {
		t.Fatal(err)
	}
	var recs []map[string]any
	if err := json.Unmarshal(r.After, &recs); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("manifest has %d records, want 2", len(recs))
	}
	got, err := os.ReadFile(filepath.Join(evidenceDir, "test", strings.ReplaceAll(f1, "/", "_")))
	if err != nil || string(got) != "alpha" {
		t.Fatalf("stashed file: %q %v", got, err)
	}
}

func TestHuntBaselineDiff(t *testing.T) {
	dir := t.TempDir()
	a := dirSnapshot{}
	d1 := filepath.Join(dir, "a")
	d2 := filepath.Join(dir, "b")
	if err := os.WriteFile(d1, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d2, []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap, err := a.Apply(Params(map[string]any{"path": dir}))
	if err != nil || snap.Before == nil {
		t.Fatalf("snapshot: %+v %v", snap, err)
	}

	h := huntBaselineDiff{}
	// no drift
	r, err := h.Check(Params(map[string]any{"path": dir, "baseline": Enc(string(snap.Before))}))
	if err != nil || !r.Done {
		t.Fatalf("baseline match: %+v %v", r, err)
	}
	// drift: change a, remove b, add c
	if err := os.WriteFile(d1, []byte("one-one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(d2); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "c"), []byte("three"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err = h.Check(Params(map[string]any{"path": dir, "baseline": Enc(string(snap.Before))}))
	if err != nil || r.Done {
		t.Fatalf("expected drift, got %+v %v", r, err)
	}
	for _, want := range []string{"+1", "~1", "-1"} {
		if !strings.Contains(r.Diff, want) {
			t.Fatalf("diff %q missing %q", r.Diff, want)
		}
	}
}

func TestCollectInventory(t *testing.T) {
	a := collectInventory{}
	r, err := a.Check(Params(nil))
	if err != nil || !r.Done {
		t.Fatalf("inventory: %+v %v", r, err)
	}
	var inv map[string]any
	if err := json.Unmarshal(r.After, &inv); err != nil {
		t.Fatalf("inventory JSON: %v", err)
	}
	if _, ok := inv["hostname"]; !ok {
		t.Fatalf("inventory missing hostname: %v", inv)
	}
}
