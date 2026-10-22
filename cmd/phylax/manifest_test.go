package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const ref2027 = "../../manifest/2027"

func run(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var o, e bytes.Buffer
	err = runManifest(args, &o, &e)
	return o.String(), e.String(), err
}

func TestManifestRegistered(t *testing.T) {
	if _, ok := commands["manifest"]; !ok {
		t.Fatal("manifest subcommand not registered")
	}
}

func TestManifestLoad(t *testing.T) {
	out, _, err := run(t, "load", "--dir", ref2027)
	if err != nil || !strings.Contains(out, "ok (team 1)") {
		t.Fatalf("out=%q err=%v", out, err)
	}
	out, _, err = run(t, "--dir", ref2027, "load", "--json", "--team", "5")
	if err == nil {
		// flags before the subcommand are not supported: the subcommand comes first.
		t.Fatalf("flags before the subcommand must be rejected, got %q", out)
	}
	out, _, err = run(t, "load", "--dir", ref2027, "--json", "--team", "5")
	if err != nil {
		t.Fatal(err)
	}
	var s loadSummary
	if err := json.Unmarshal([]byte(out), &s); err != nil || s.Team != 5 || s.Hosts != 8 || s.Scored == 0 {
		t.Fatalf("summary = %+v err=%v", s, err)
	}
}

func TestManifestLoadFailsOnBadDir(t *testing.T) {
	if _, _, err := run(t, "load", "--dir", t.TempDir()); err == nil {
		t.Fatal("empty dir must fail")
	}
}

func TestManifestLintCleanReference(t *testing.T) {
	for _, dir := range []string{ref2027, "../../manifest/two-segment"} {
		out, _, err := run(t, "lint", "--dir", dir)
		if err != nil {
			t.Fatalf("%s: %v\n%s", dir, err, out)
		}
		if !strings.Contains(out, "0 error(s)") {
			t.Errorf("%s: %s", dir, out)
		}
	}
	out, _, err := run(t, "lint", "--dir", ref2027, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var rep lintReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil || !rep.OK || rep.Errors != 0 {
		t.Fatalf("rep = %+v err=%v", rep, err)
	}
	if rep.Findings == nil {
		t.Error("findings must be an array, never null")
	}
}

// copyManifest copies the 2027 reference into a temp dir with hosts.yml edited.
func copyManifest(t *testing.T, edit func(string) string) string {
	t.Helper()
	dst := t.TempDir()
	ents, err := os.ReadDir(ref2027)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(ref2027, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if e.Name() == "hosts.yml" {
			b = []byte(edit(string(b)))
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func TestManifestLintExitsNonZeroOnErrors(t *testing.T) {
	dir := copyManifest(t, func(s string) string {
		// mssql loses domain_member: a Windows host next to the DC using domain auth.
		out := strings.Replace(s, "roles: [capture, decoys], domain_member: ad, default_credentials: host.default }\n  ubuntu-wkst", "roles: [capture, decoys], default_credentials: host.default }\n  ubuntu-wkst", 1)
		if out == s {
			t.Fatal("test edit did not apply")
		}
		return out
	})
	out, _, err := run(t, "lint", "--dir", dir)
	if err == nil {
		t.Fatalf("lint must fail:\n%s", out)
	}
	if !strings.Contains(out, "AD001") || !strings.Contains(out, "mssql") {
		t.Errorf("human output lacks the finding:\n%s", out)
	}
	out, _, err = run(t, "lint", "--dir", dir, "--json")
	if err == nil {
		t.Fatal("json lint must also fail")
	}
	var rep lintReport
	if jerr := json.Unmarshal([]byte(out), &rep); jerr != nil {
		t.Fatalf("json output must be valid even on failure: %v\n%s", jerr, out)
	}
	if rep.OK || rep.Errors != 1 || rep.Findings[0].ID != "AD001" {
		t.Errorf("rep = %+v", rep)
	}
}

func TestManifestRender(t *testing.T) {
	out, _, err := run(t, "render", "ubuntu-email", "--format", "nft", "--dir", ref2027)
	if err != nil || !strings.Contains(out, "table inet phylax") || !strings.Contains(out, "50000-50199") {
		t.Fatalf("nft: err=%v\n%s", err, out)
	}
	out, _, err = run(t, "render", "--dir", ref2027, "--format", "windows", "mssql")
	if err != nil {
		t.Fatal(err)
	}
	var wp struct {
		Host  string `json:"host"`
		Rules []struct {
			Group string `json:"group"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(out), &wp); err != nil || wp.Host != "mssql" {
		t.Fatalf("windows: %v\n%s", err, out)
	}
	domain := 0
	for _, r := range wp.Rules {
		if r.Group == "Phylax Domain" {
			domain++
		}
	}
	if domain != 2 {
		t.Errorf("domain rules = %d", domain)
	}
	for _, tc := range []struct{ format, dev, want string }{{"palo", "palo1", `"device": "palo1"`}, {"vyos", "vyos1", `"device": "vyos1"`}} {
		out, _, err = run(t, "render", tc.dev, "--format", tc.format, "--dir", ref2027)
		if err != nil || !strings.Contains(out, tc.want) {
			t.Errorf("%s: err=%v\n%s", tc.format, err, out)
		}
	}
}

func TestManifestRenderErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no format":      {"render", "mssql", "--dir", ref2027},
		"bad format":     {"render", "mssql", "--format", "iptables", "--dir", ref2027},
		"unknown host":   {"render", "nope", "--format", "nft", "--dir", ref2027},
		"nft on windows": {"render", "mssql", "--format", "nft", "--dir", ref2027},
		"windows on nix": {"render", "ubuntu-email", "--format", "windows", "--dir", ref2027},
		"palo non-dev":   {"render", "mssql", "--format", "palo", "--dir", ref2027},
		"no host":        {"render", "--format", "nft", "--dir", ref2027},
		"two hosts":      {"render", "a", "b", "--format", "nft", "--dir", ref2027},
		"unknown sub":    {"frobnicate"},
		"no sub":         {},
		"bad flag":       {"lint", "--nope"},
		"lint with arg":  {"lint", "extra", "--dir", ref2027},
	} {
		if _, _, err := run(t, args...); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
