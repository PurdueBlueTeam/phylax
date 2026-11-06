package plan

import "testing"

func TestStepSignatureCoversClass(t *testing.T) {
	f := newFixture(t)
	s := f.issue(t, "fw_shadow", IssueOpts{})
	if s.Class != ClassAuto {
		t.Fatalf("class %q", s.Class)
	}
	if err := f.ver.Verify(s); err != nil {
		t.Fatal(err)
	}
	s.Class = ClassClick
	if err := f.ver.Verify(s); err == nil {
		t.Fatal("class change not detected")
	}
}
