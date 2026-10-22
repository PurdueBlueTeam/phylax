package scorer

import (
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/creds"
)

func goodPW(t *testing.T, user string) string {
	t.Helper()
	s, err := creds.NewGenerator().Generate(creds.Scored, user)
	if err != nil {
		t.Fatal(err)
	}
	return s.Reveal()
}

func TestCSVGenerateAndPortalRoundTrip(t *testing.T) {
	p := CSVPolicy{}
	es := []CSVEntry{
		{"/creds/linux.csv", "alice", goodPW(t, "alice")},
		{"/creds/ad.csv", "Bob", goodPW(t, "Bob")},
		{"/creds/linux.csv", "carol", goodPW(t, "carol")},
	}
	blocks, err := p.GenerateCSV(es)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 2 || blocks[0].Path != "/creds/ad.csv" || blocks[1].Count != 2 {
		t.Fatalf("blocks: %+v", blocks)
	}
	for _, b := range blocks {
		for _, l := range b.Lines {
			if !strings.Contains(l, ",") || l != strings.TrimSpace(l) || strings.Contains(l, " ") {
				t.Fatalf("bad line %q", l)
			}
		}
		if strings.HasSuffix(b.Text, "\n") || strings.HasPrefix(b.Text, "\n") {
			t.Fatal("stray newline")
		}
	}
	// Case-exact usernames survive.
	if got := PortalParse(blocks[0].Text); got[0].Username != "Bob" {
		t.Fatalf("%+v", got)
	}
}

func TestCSVRejections(t *testing.T) {
	ok := goodPW(t, "u")
	for name, e := range map[string]CSVEntry{
		"empty path":       {"", "u", ok},
		"empty user":       {"/c", "", ok},
		"empty password":   {"/c", "u", ""},
		"user comma":       {"/c", "a,b", ok},
		"user leading sp":  {"/c", " a", ok},
		"user newline":     {"/c", "a\nb", ok},
		"user quoted":      {"/c", `"bob"`, ok},
		"pass comma":       {"/c", "u", ok[:15] + ","},
		"pass space":       {"/c", "u", ok[:15] + " x"},
		"pass quoted":      {"/c", "u", `"` + ok[1:15] + `"`},
		"pass squote pair": {"/c", "u", `'` + ok[1:15] + `'`},
		"pass too short":   {"/c", "u", "Ab1"},
	} {
		if _, err := (CSVPolicy{}).GenerateCSV([]CSVEntry{e}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := (CSVPolicy{}).GenerateCSV([]CSVEntry{{"/c", "u", ok}, {"/c", "u", goodPW(t, "u")}}); err == nil {
		t.Error("duplicate username accepted")
	}
	p := CSVPolicy{KnownPaths: map[string]bool{"/creds/linux.csv": true}}
	if _, err := p.GenerateCSV([]CSVEntry{{"Linux Users", "u", ok}}); err == nil {
		t.Error("display name accepted as path")
	}
}

func TestPortalParseQuirks(t *testing.T) {
	// Documents why the rules exist: these are what the portal does.
	got := PortalParse("alice, secret\nbob\n\n  \ncarol,\"x\"\ndan,a,b")
	want := []PortalPair{{"alice", " secret"}, {"bob", ""}, {"carol", "x"}, {"dan", "a,b"}}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%d: %+v != %+v", i, got[i], want[i])
		}
	}
}

func TestVerifyReply(t *testing.T) {
	b := CSVBlock{Count: 3}
	if err := b.VerifyReply(PCRReply{Count: 3}); err != nil {
		t.Fatal(err)
	}
	if b.VerifyReply(PCRReply{Count: 2, Skipped: []string{"x"}}) == nil || b.VerifyReply(PCRReply{Count: 2}) == nil || b.VerifyReply(PCRReply{Count: 3, Skipped: []string{"x"}}) == nil {
		t.Fatal("mismatch accepted")
	}
}
