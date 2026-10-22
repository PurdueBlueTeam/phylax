package detect

import (
	"path/filepath"
	"testing"
)

const rulesDir = "../../rules"

func TestCorpusInlineTests(t *testing.T) {
	rs, err := LoadDir(rulesDir, LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rules) == 0 {
		t.Fatal("no rules loaded")
	}
	for _, r := range rs.RunTests() {
		if r.Err != nil {
			t.Errorf("%s / %s: %v", r.Rule, r.Test, r.Err)
		}
	}
	t.Logf("%d active rules", len(rs.Rules))
}

// Pending rules must still parse and validate; their tests are not run because
// the producers do not exist yet.
func TestPendingRulesParse(t *testing.T) {
	// Pending rules reference the shared profiles, so load them together.
	all, err := LoadDir(rulesDir, LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = all
	rs, err := loadDirs([]string{rulesDir, filepath.Join(rulesDir, "pending")}, LoadOptions{AllowUntested: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs.Rules {
		if filepath.Base(filepath.Dir(r.File)) == "pending" && r.Needs == "" {
			t.Errorf("pending rule %s must say what producer it needs (needs:)", r.ID)
		}
	}
	t.Logf("%d rules including pending", len(rs.Rules))
}
