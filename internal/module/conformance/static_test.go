package conformance

import (
	"fmt"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestNoSiblingImports(t *testing.T) {
	t.Skip("unimplemented: W1 Task 37")
	// for every contract module: go list -deps contains no other module's package
	// and nothing under internal/ outside CoreImports, AllowedLibraries and its own tree.
}

func TestKindTable(t *testing.T) {
	t.Skip("unimplemented: W1 Task 37")
	// parse the design's Event kinds table and compare it with event.Declared()
	// and every module's Emits and Consumes.
}

func TestPreContractShrinks(t *testing.T) {
	t.Skip("unimplemented: W1 Task 37")
	// every module without a manifest is in PreContract; a pre-contract name
	// that now has a manifest fails.
}

func TestConformanceTestPresent(t *testing.T) {
	t.Skip("unimplemented: W1 Task 37")
	// every contract module package has a _test.go calling conformance.Agent or Controller.
}

func TestLibrariesStateless(t *testing.T) {
	t.Skip("unimplemented: W1 Task 37")
	// every AllowedLibraries package that exists has no registry init and no
	// package-level mutable state.
}

func TestImportCheckCatchesSibling(t *testing.T) {
	t.Skip("unimplemented: W1 Task 37")
	// testdata/sibling/a.go is "package x" importing ".../internal/integrity"; checkFileImports("depot", "testdata/sibling/a.go")
	// must return an error naming internal/integrity; testdata/ok/a.go importing internal/signing and internal/sockets returns nil
}

func TestImportCheckRejectsEnroll(t *testing.T) {
	// testdata/enroll/a.go is "package x" importing "github.com/PurdueBlueTeam/phylax/internal/enroll"
	if err := checkFileImports("depot", "testdata/enroll/a.go"); err == nil || !strings.Contains(err.Error(), "internal/enroll") {
		t.Fatalf("a module importing internal/enroll must fail the import check: %v", err)
	}
}

// checkFileImports rejects a module file that imports another module, any
// internal package outside the core and allowed libraries, and internal/enroll.
func checkFileImports(module, path string) error {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		return err
	}
	const core = "github.com/PurdueBlueTeam/phylax/internal/"
	own := ModulePackages[module]
	if own == "" {
		own = core + module
	}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return fmt.Errorf("%s: bad import path %s", path, imp.Path.Value)
		}
		if p == core+"enroll" || strings.HasPrefix(p, core+"enroll/") {
			return fmt.Errorf("%s: a module may not import %s", path, p)
		}
		if !strings.HasPrefix(p, core) || p == own || strings.HasPrefix(p, own+"/") {
			continue
		}
		if slices.Contains(CoreImports, p) || slices.Contains(AllowedLibraries, p) {
			continue
		}
		return fmt.Errorf("%s: a module may not import %s", path, p)
	}
	return nil
}
