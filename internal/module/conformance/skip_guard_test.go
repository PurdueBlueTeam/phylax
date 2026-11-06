package conformance

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// This file holds the CI drift guards: the design's numbers must match the
// registry and the suite, and a skipped test must say why (Known bug 11).

// TestSkipsCarryReason (Known bug 11): every t.Skip/t.Skipf call under
// internal/ and cmd/ carries a non-empty string reason, and every
// t.SkipNow() has a shortcut: or other comment on the line above. A bare skip
// fails the build instead of silently passing.
func TestSkipsCarryReason(t *testing.T) {
	bad := findBareSkips(t, "../../..")
	if len(bad) > 0 {
		t.Fatalf("t.Skip without a reason (Known bug 11):\n%s", strings.Join(bad, "\n"))
	}
}

// TestSkipGuardCatchesBareSkips keeps the guard honest: a bare skip, an empty
// reason and an uncommented SkipNow are each reported.
func TestSkipGuardCatchesBareSkips(t *testing.T) {
	root := t.TempDir()
	src := `package x

import "testing"

func TestBare(t *testing.T) {
	t.Skip()
}

func TestEmpty(t *testing.T) {
	t.Skip("")
}

func TestOK(t *testing.T) {
	t.Skip("needs root")
}

func TestNow(t *testing.T) {
	t.SkipNow()
}

func TestNowCommented(t *testing.T) {
	// shortcut: nothing to run here.
	t.SkipNow()
}
`
	dir := filepath.Join(root, "internal", "x")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "x_test.go")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	bad := findBareSkips(t, root)
	if len(bad) != 3 {
		t.Fatalf("want 3 offenders, got %d: %v", len(bad), bad)
	}
	for _, want := range []string{"x_test.go:6", "x_test.go:10", "x_test.go:18 (SkipNow"} {
		found := false
		for _, b := range bad {
			found = found || strings.HasSuffix(b, want) || strings.Contains(b, want)
		}
		if !found {
			t.Errorf("offender %q not reported: %v", want, bad)
		}
	}
}

// findBareSkips walks root/internal and root/cmd, parses every *_test.go and
// returns "file:line" for each skip without a reason.
func findBareSkips(t *testing.T, root string) []string {
	t.Helper()
	var bad []string
	for _, top := range []string{"internal", "cmd"} {
		dir := filepath.Join(root, top)
		if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(d.Name(), "_test.go") {
				return nil
			}
			src, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, p, src, 0)
			if err != nil {
				return err
			}
			lines := strings.Split(string(src), "\n")
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				line := fset.Position(call.Pos()).Line
				switch sel.Sel.Name {
				case "Skip", "Skipf":
					if !skipHasReason(call.Args) {
						bad = append(bad, fmt.Sprintf("%s:%d", p, line))
					}
				case "SkipNow":
					if !commentedAbove(lines, line) {
						bad = append(bad, fmt.Sprintf("%s:%d (SkipNow without a shortcut: or reason comment above)", p, line))
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(bad)
	return bad
}

// skipHasReason reports whether the first argument is a non-empty string.
//
// shortcut: a reason held in a variable or a const is accepted without
// evaluation, only literals are checked; upgrade to go/types constant folding
// if a skip reason is ever computed.
func skipHasReason(args []ast.Expr) bool {
	if len(args) == 0 {
		return false
	}
	lit, ok := args[0].(*ast.BasicLit)
	if !ok {
		return true
	}
	if lit.Kind != token.STRING {
		return false
	}
	s, err := strconv.Unquote(lit.Value)
	return err == nil && strings.TrimSpace(s) != ""
}

// commentedAbove reports whether the line above line (1-based) is a comment.
func commentedAbove(lines []string, line int) bool {
	if line < 2 || line-2 >= len(lines) {
		return false
	}
	s := strings.TrimSpace(lines[line-2])
	return strings.HasPrefix(s, "//") || strings.HasPrefix(s, "/*")
}

var (
	kindCountsRe = regexp.MustCompile(`There are (\d+) kinds: (\d+) common kinds, (\d+) core kinds and (\d+) module kinds`)
	checkCountRe = regexp.MustCompile(`All ([a-z]+) checks`)
	numberWords  = map[string]int{"one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
		"six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11,
		"twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16}
)

// TestKindCounts (M1): the three numbers in the Event kinds prose of the
// design equal the kinds the table declares, and the T46 row's count equals
// the checks this suite runs. A drift fails CI.
func TestKindCounts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "phylax_design.md"))
	if err != nil {
		t.Fatal(err)
	}
	design := string(raw)
	rows := parseKindTable(t)
	got := map[string]int{"total": len(rows)}
	for _, row := range rows {
		got[row.class]++
	}
	m := kindCountsRe.FindStringSubmatch(design)
	if m == nil {
		t.Fatal(`the Event kinds prose ("There are N kinds: 8 common kinds, ...") is gone from phylax_design.md`)
	}
	want := map[string]int{"total": atoi(t, m[1]), "common": atoi(t, m[2]), "core": atoi(t, m[3]), "module": atoi(t, m[4])}
	for _, class := range []string{"total", "common", "core", "module"} {
		if got[class] != want[class] {
			t.Errorf("the design says %d %s kinds, the table has %d", want[class], class, got[class])
		}
	}

	names := checkNames()
	row := t46Row(t, design)
	m = checkCountRe.FindStringSubmatch(row)
	if m == nil {
		t.Fatalf("the T46 row no longer says \"All <n> checks\": %q", row)
	}
	n, ok := numberWords[m[1]]
	if !ok {
		t.Fatalf("T46's count %q is not a number word this test knows", m[1])
	}
	if n != len(names) {
		t.Errorf("T46 says all %s checks (%d); the suite runs %d: %v", m[1], n, len(names), names)
	}
}

// t46Row returns the design's T46 row from the test list table.
func t46Row(t *testing.T, design string) string {
	t.Helper()
	for _, line := range strings.Split(design, "\n") {
		if strings.HasPrefix(line, "| T46 |") {
			return line
		}
	}
	t.Fatal("the T46 row is gone from phylax_design.md")
	return ""
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("%q is not a number: %v", s, err)
	}
	return n
}

// checkNames returns every conformance check the suite runs: both check lists
// plus the static import check.
func checkNames() []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for _, ch := range agentChecks {
		add(ch.name)
	}
	for _, ch := range controllerChecks {
		add(ch.name)
	}
	add("imports") // TestNoSiblingImports
	sort.Strings(out)
	return out
}
