package controller

import (
	"os"
	"testing"
)

func readFile(p string) (string, error) { b, err := os.ReadFile(p); return string(b), err }
func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}
