package plan

import "testing"

func TestNodeExpiresAfterValidates(t *testing.T) {
	t.Skip("unimplemented: W1 Task 22a")
	ok := Node{ID: "a", Action: "file.write", Target: "h1", ExpiresAfterSec: 1800}
	if err := validateNode(ok); err != nil {
		t.Fatal(err)
	}
	for i, n := range []Node{
		{ID: "a", Action: "file.write", Target: "h1", ExpiresAfterSec: 30},
		{ID: "a", Action: "file.write", Target: "h1", ExpiresAfterSec: 90000},
		{ID: "g", Gate: true, ExpiresAfterSec: 600},
		{ID: "a", Action: "file.write", Target: "h1", ExpiresAfterSec: -1},
	} {
		if validateNode(n) == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestStepSignatureCoversExpiry(t *testing.T) {
	t.Skip("unimplemented: W1 Task 22a")
	f := newFixture(t)
	s := f.issue(t, "fw_shadow", IssueOpts{})
	if s.ExpiresAfterSec != 1800 {
		t.Fatalf("expiry %d", s.ExpiresAfterSec)
	}
	if err := f.ver.Verify(s); err != nil {
		t.Fatal(err)
	}
	s.ExpiresAfterSec = 60
	if err := f.ver.Verify(s); err == nil {
		t.Fatal("expiry change not detected")
	}
}
