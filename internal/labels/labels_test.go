package labels

import "testing"

// TestClassify: us/scorer/other with us winning over scorer (a platform
// address is never re-labeled), and empty addresses never match.
func TestClassify(t *testing.T) {
	m := New([]string{"10.0.0.1", "127.0.0.1"})
	cases := []struct {
		ip, want string
	}{
		{"10.0.0.1", "us"},
		{"127.0.0.1", "us"},
		{"10.5.5.5", "other"},
		{"", "other"},
	}
	for _, c := range cases {
		if got := m.Classify(c.ip); got != c.want {
			t.Fatalf("Classify(%q) = %q, want %q", c.ip, got, c.want)
		}
	}
	// learned scorer
	m.SetScorerSources([]string{"10.5.5.5"})
	if got := m.Classify("10.5.5.5"); got != "scorer" {
		t.Fatalf("scorer not learned: %q", got)
	}
	// us wins over scorer
	m.AddUS("10.5.5.5")
	if got := m.Classify("10.5.5.5"); got != "us" {
		t.Fatalf("us must win over scorer: %q", got)
	}
	// SetScorerSources replaces, not appends
	m.SetScorerSources(nil)
	if got := m.Classify("10.5.5.6"); got != "other" {
		t.Fatalf("stale scorer source: %q", got)
	}
}

// TestRedTag: attack-like sources stay tagged; red is a sub-tag of other,
// not a label of its own.
func TestRedTag(t *testing.T) {
	m := New(nil)
	m.MarkRed("203.0.113.7")
	if !m.IsRed("203.0.113.7") {
		t.Fatal("MarkRed not effective")
	}
	if got := m.Classify("203.0.113.7"); got != "other" {
		t.Fatalf("red must classify as other, got %q", got)
	}
	// a red-tagged source that later becomes a declared platform
	// address is still never the scorer; the red tag stays but the
	// label is us (docs: us wins).
	m.AddUS("203.0.113.7")
	if got := m.Classify("203.0.113.7"); got != "us" {
		t.Fatalf("us must win: %q", got)
	}
	if got := m.RedSources(); len(got) != 1 || got[0] != "203.0.113.7" {
		t.Fatalf("RedSources: %v", got)
	}
	// empty never tags
	m.MarkRed("")
	if got := m.RedSources(); len(got) != 1 {
		t.Fatalf("empty tag: %v", got)
	}
}

// TestScorerSources lists learned sources sorted.
func TestScorerSources(t *testing.T) {
	m := New(nil)
	m.SetScorerSources([]string{"b", "a", "b"})
	got := m.ScorerSources()
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("ScorerSources: %v", got)
	}
}
