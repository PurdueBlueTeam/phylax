package integrity

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

const testRules = `
// comment
rule Chisel : tunnel c2 {
  meta:
    author = "t"
  strings:
    $a = "chisel-server" ascii
    $b = "SSH-chisel-v" nocase
    $c = { 48 8B ?? 24 ?? 5A }
  condition:
    $a and ($b or $c)
}
rule WideOnly {
  strings: $w = "evil" wide
  condition: any of them
}
rule ThreeOf {
  strings: $x = "one" $y = "two" $z = "three"
  condition: 2 of them
}
rule PE {
  strings: $m = "MZ-marker"
  condition: uint16(0) == 0x5A4D and $m and filesize < 1KB
}
rule NotRule {
  strings: $n = "benign"
  condition: not $n
}
rule Regexy {
  strings: $r = /ab+c/
  condition: $r
}
`

func names(ms []RuleMatch) string {
	var n []string
	for _, m := range ms {
		n = append(n, m.Rule)
	}
	return strings.Join(n, ",")
}

func TestMatcherBasics(t *testing.T) {
	m, err := ParseRules(testRules)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Rules) != 5 || len(m.Skipped) != 1 || m.Skipped[0].Name != "Regexy" {
		t.Fatalf("rules=%d skipped=%+v", len(m.Rules), m.Skipped)
	}
	ctx := context.Background()
	scan := func(b []byte) string {
		ms, err := m.ScanBytes(ctx, "t", b)
		if err != nil {
			t.Fatal(err)
		}
		return names(ms)
	}
	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte("xx chisel-server yy ssh-CHISEL-v1"), "Chisel,NotRule"},
		{[]byte("chisel-server only"), "NotRule"},
		{[]byte("chisel-server \x48\x8b\x11\x24\x99\x5a"), "Chisel,NotRule"},
		{[]byte("e\x00v\x00i\x00l\x00"), "WideOnly,NotRule"},
		{[]byte("evil"), "NotRule"},
		{[]byte("one and three"), "ThreeOf,NotRule"},
		{[]byte("one only"), "NotRule"},
		{[]byte("MZ-marker"), "PE,NotRule"},
		{[]byte("benign"), ""},
	}
	for _, c := range cases {
		if got := scan(c.in); got != c.want {
			t.Errorf("%q: got %q want %q", c.in, got, c.want)
		}
	}
	// PE rule needs the MZ header and respects filesize.
	if got := scan(append([]byte("MZ"), []byte("-marker")...)); !strings.Contains(got, "PE") {
		t.Errorf("PE: %q", got)
	}
	big := append([]byte("MZ-marker"), make([]byte, 4096)...)
	if got := scan(big); strings.Contains(got, "PE") {
		t.Errorf("filesize ignored: %q", got)
	}
}

func TestMatcherSpansChunkBoundaryOnce(t *testing.T) {
	m, _ := ParseRules(`rule R { strings: $a = "NEEDLE-ACROSS" condition: $a }`)
	data := make([]byte, 3<<20)
	copy(data[(1<<20)-5:], "NEEDLE-ACROSS") // straddles the first 1 MiB chunk edge
	copy(data[2<<20:], "NEEDLE-ACROSS")
	ms, err := m.ScanBytes(context.Background(), "x", data)
	if err != nil || len(ms) != 1 {
		t.Fatalf("%v %v", err, ms)
	}
	s := ms[0].Strings[0]
	if s.Count != 2 || s.Offset != (1<<20)-5 {
		t.Fatalf("count=%d offset=%d (boundary match missed or double counted)", s.Count, s.Offset)
	}
}

func TestParseRulesErrors(t *testing.T) {
	for _, bad := range []string{
		`rule A { strings: $a = "x" condition: $b }`,
		`rule A { strings: $a = "x" condition: }`,
		`rule A { strings: $a = "unterminated condition: $a }`,
		`rule A { condition: ( true }`,
	} {
		if _, err := ParseRules(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestLoadCorpusDirAndStubs(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.yar"), []byte(testRules), 0o644)
	os.WriteFile(filepath.Join(dir, "ignored.txt"), []byte("rule X {"), 0o644)
	m, err := LoadCorpusDir(dir)
	if err != nil || len(m.Rules) != 5 || len(m.Skipped) != 1 {
		t.Fatalf("%v %+v", err, m)
	}
	if _, err := BundledC2Corpus(); err != ErrCorpusNotBundled {
		t.Fatal(err)
	}
	var s Scanner = ExternalScanner{}
	if _, err := s.ScanFile(context.Background(), "x"); err != ErrYaraXUnavailable {
		t.Fatal(err)
	}
}

func TestYaraScheduleDedupByInode(t *testing.T) {
	m, _ := ParseRules(`rule Implant : c2 { strings: $a = "sliver-beacon" condition: $a }`)
	dir := t.TempDir()
	bad, good := filepath.Join(dir, "bad"), filepath.Join(dir, "good")
	os.WriteFile(bad, []byte("xx sliver-beacon xx"), 0o644)
	os.WriteFile(good, []byte("hello"), 0o644)
	var mu sync.Mutex
	var evs []event.Event
	y := &YaraSchedule{Scanner: GoScanner{M: m}, Agent: "a", Pause: time.Millisecond,
		Files: func() []string { return []string{bad, good} },
		Emit:  func(e event.Event) { mu.Lock(); evs = append(evs, e); mu.Unlock() }}
	n, err := y.RunOnce(context.Background())
	if err != nil || n != 1 || len(evs) != 1 || evs[0].Kind != YaraEventKind || evs[0].Fields["rule"] != "Implant" || evs[0].Fields["target"] != bad {
		t.Fatalf("%v %d %+v", err, n, evs)
	}
	// Unchanged inodes are not rescanned (so no repeat), a rewritten file is.
	if n, _ := y.RunOnce(context.Background()); n != 0 {
		t.Fatalf("rescanned unchanged inode: %d", n)
	}
	os.WriteFile(good, []byte("now sliver-beacon!"), 0o644)
	if n, _ := y.RunOnce(context.Background()); n != 1 {
		t.Fatalf("changed file not rescanned: %d", n)
	}
}
