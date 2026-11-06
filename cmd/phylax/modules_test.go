package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/module"
)

func TestModulesCommand(t *testing.T) {
	var out bytes.Buffer
	if err := runModules([]string{"-json"}, &out); err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Name     string          `json:"name"`
		Status   string          `json:"status"`
		Manifest module.Manifest `json:"manifest"`
	}
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	status := map[string]string{}
	for _, r := range rows {
		status[r.Name] = r.Status
		if r.Status == "contract" && r.Manifest.Name != r.Name {
			t.Errorf("%s: status contract but manifest names %q", r.Name, r.Manifest.Name)
		}
	}
	for name, want := range map[string]string{
		"health":   "contract",
		"suricata": "contract",
		"audit":    "pre-contract",
	} {
		if got := status[name]; got != want {
			t.Errorf("%s: status %q, want %q", name, got, want)
		}
	}

	// The human form prints one line per module with the same status.
	out.Reset()
	if err := runModules(nil, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != len(rows) {
		t.Fatalf("%d lines for %d modules:\n%s", len(lines), len(rows), out.String())
	}
	var sawHealth, sawSuricata, sawAudit bool
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) != 6 {
			t.Fatalf("line %q has %d fields, want name sides os default emits status", l, len(f))
		}
		switch f[0] {
		case "health":
			sawHealth = f[1] == "agent" && f[2] == "-" && f[3] == "true" && f[4] == "2" && f[5] == "contract"
		case "suricata":
			sawSuricata = f[1] == "controller" && f[4] == "6" && f[5] == "contract"
		case "audit":
			sawAudit = f[5] == "pre-contract"
		}
	}
	if !sawHealth || !sawSuricata || !sawAudit {
		t.Errorf("text output wrong (health %v, suricata %v, audit %v):\n%s", sawHealth, sawSuricata, sawAudit, out.String())
	}
}
