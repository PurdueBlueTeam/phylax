package bootstrapfile_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/bootstrapfile"
	"github.com/PurdueBlueTeam/phylax/internal/link"
)

const planKey = "abababababababababababababababababababababababababababababababab"

// saveRaw saves a bootstrap file with one field Rewrite does not know.
func saveRaw(t *testing.T, dir string) (string, []byte) {
	t.Helper()
	b := &agent.Bundle{
		Controllers:   []string{"10.0.0.1:7443"},
		ControllerPin: link.Pin{1}.String(),
		Host:          "h1",
		Token:         "tok-123",
		Roles:         []string{"capture", "decoys"},
		PlanKey:       planKey,
		Safe:          true,
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	// Insert an unknown field (json.Unmarshal ignores it, Rewrite must keep it).
	body := append(data[:len(data)-1], []byte(",\n  \"unknown_field\": {\"keep\": true}\n}")...)
	path := filepath.Join(dir, "bootstrap.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, body
}

func TestRewriteKeepsEverythingElse(t *testing.T) {
	dir := t.TempDir()
	path, _ := saveRaw(t, dir)
	before, err := agent.ParseBundle(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrapfile.Rewrite(path, []string{"10.1.1.1:7443", "10.1.1.2:7443"}, ""); err != nil {
		t.Fatal(err)
	}
	raw := mustRead(t, path)
	after, err := agent.ParseBundle(raw)
	if err != nil {
		t.Fatalf("rewritten bundle does not parse: %v\n%s", err, raw)
	}
	if len(after.Controllers) != 2 || after.Controllers[0] != "10.1.1.1:7443" || after.Controllers[1] != "10.1.1.2:7443" {
		t.Fatalf("Controllers = %v", after.Controllers)
	}
	if after.ControllerPin != before.ControllerPin {
		t.Errorf("pin changed: %q -> %q", before.ControllerPin, after.ControllerPin)
	}
	if after.Host != before.Host || after.Token != before.Token || after.PlanKey != before.PlanKey || after.Safe != before.Safe {
		t.Errorf("known fields changed: %+v -> %+v", before, after)
	}
	if strings.Join(after.Roles, ",") != strings.Join(before.Roles, ",") {
		t.Errorf("Roles = %v, want %v", after.Roles, before.Roles)
	}
	if !strings.Contains(string(raw), `"unknown_field"`) || !strings.Contains(string(raw), `"keep": true`) {
		t.Errorf("the unknown field was lost:\n%s", raw)
	}

	// An explicit pin replaces the old one and nothing else.
	pin := link.Pin{7}.String()
	if err := bootstrapfile.Rewrite(path, []string{"10.1.1.3:7443"}, pin); err != nil {
		t.Fatal(err)
	}
	after, err = agent.ParseBundle(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	if after.ControllerPin != pin {
		t.Fatalf("ControllerPin = %q, want %q", after.ControllerPin, pin)
	}
}

func TestRewriteRejectsBadInput(t *testing.T) {
	tests := []struct {
		name        string
		controllers []string
		pin         string
	}{
		{"nonsense", []string{"nonsense"}, ""},
		{"no port", []string{"10.0.0.1"}, ""},
		{"empty list", nil, ""},
		{"bad pin", []string{"10.0.0.1:7443"}, "nothex"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path, before := saveRaw(t, dir)
			if err := bootstrapfile.Rewrite(path, tc.controllers, tc.pin); err == nil {
				t.Fatal("Rewrite accepted bad input")
			}
			if got := mustRead(t, path); !bytes.Equal(got, before) {
				t.Fatalf("a rejected rewrite changed the file:\n%s", got)
			}
		})
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
