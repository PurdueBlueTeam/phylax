package scorer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRunWritesGroundTruth runs the simulator against a local HTTP server
// for two rounds and checks the ground-truth records: a matching check
// passes, a mismatching one fails with the expected hashes.
func TestRunWritesGroundTruth(t *testing.T) {
	dir := t.TempDir()
	expect := filepath.Join(dir, "index.html")
	if err := os.WriteFile(expect, []byte("<html>expected page</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wrong" {
			w.Write([]byte("different content"))
			return
		}
		w.Write([]byte("<html>expected page</html>"))
	}))
	defer ok.Close()

	out := filepath.Join(dir, "truth.jsonl")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg := Config{
		Checks: []Check{
			{ID: "home", Kind: "http", Target: ok.URL, ExpectFile: expect},
			{ID: "wrong", Kind: "http", Target: ok.URL, Path: "/wrong", ExpectFile: expect},
		},
		Interval: 50 * time.Millisecond,
		Out:      out,
	}
	// Two rounds: 2 checks x 2 = 4 records.
	done := make(chan int, 1)
	go func() { n, _ := Run(ctx, cfg); done <- n }()
	// Let it run ~300ms, then cancel: expect 4-8 records (>= 2 rounds).
	time.Sleep(300 * time.Millisecond)
	cancel()
	n := <-done
	if n < 4 {
		t.Fatalf("only %d checks written, want >= 4", n)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]*Truth{}
	for _, line := range splitLines(data) {
		var tr Truth
		if err := json.Unmarshal(line, &tr); err != nil {
			t.Fatalf("bad truth line %q: %v", line, err)
		}
		records[tr.Check] = &tr // last record per check
	}
	if home := records["home"]; home == nil || !home.Pass {
		t.Errorf("home check should pass: %+v", home)
	}
	if wrong := records["wrong"]; wrong == nil || wrong.Pass {
		t.Errorf("wrong check should fail: %+v", wrong)
	} else if wrong.ExpectSHA256 == "" || wrong.GotSHA256 == "" || wrong.ExpectSHA256 == wrong.GotSHA256 {
		t.Errorf("wrong check must record differing hashes: %+v", wrong)
	}
	if fp := records["home"].ClientFp; fp == "" {
		t.Error("client fingerprint must be recorded")
	}
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			if i > start {
				out = append(out, b[start:i])
			}
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}
