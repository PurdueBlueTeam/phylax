package conformance

import "testing"

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
