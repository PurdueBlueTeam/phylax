package conformance

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	_ "github.com/PurdueBlueTeam/phylax/internal/module/all"
)

const (
	repoRoot  = "../../.."
	modPrefix = "github.com/PurdueBlueTeam/phylax"
)

// TestNoSiblingImports (check 8, bug 15 guard): a contract module imports only
// core packages, the allowed libraries and its own package tree; its agent
// registration file obeys the same rule.
func TestNoSiblingImports(t *testing.T) {
	for _, m := range contractModules(t) {
		m := m
		t.Run(m.name, func(t *testing.T) {
			if isCorePackage(m.pkg) {
				// health is a core module (it lives in internal/agent): the
				// module-package import rule does not apply to core packages.
				return
			}
			deps, err := packageDeps(m.pkg)
			if err != nil {
				t.Fatal(err)
			}
			for _, dep := range deps {
				if dep == m.pkg || strings.HasPrefix(dep, m.pkg+"/") {
					continue
				}
				if dep == modPrefix+"/internal/enroll" || strings.HasPrefix(dep, modPrefix+"/internal/enroll/") {
					t.Errorf("%s imports internal/enroll", m.name)
					continue
				}
				if mayImport(dep) {
					continue
				}
				t.Errorf("%s: %s is not a core package or an allowed library", m.name, dep)
			}
			files, _ := filepath.Glob(filepath.Join(repoRoot, "internal", "agent", "mods", m.name+"*.go"))
			for _, f := range files {
				if err := checkFileImports(m.name, f); err != nil {
					t.Error(err)
				}
			}
		})
	}
}

// TestKindTable (T46) compares the design's Event kinds table with the
// declared kinds and every contract module's Emits and Consumes.
func TestKindTable(t *testing.T) {
	rows := parseKindTable(t)
	contract := contractModules(t)
	contractNames := make(map[string]bool, len(contract))
	for _, m := range contract {
		contractNames[m.name] = true
	}
	moduleNames := make(map[string]bool, len(ModulePackages))
	for name := range ModulePackages {
		moduleNames[name] = true
	}
	for _, name := range PreContract {
		moduleNames[name] = true
	}

	declared := map[string]event.Type{}
	for _, ty := range event.Declared() {
		if isTestKind(ty.Kind) {
			continue
		}
		declared[ty.Kind] = ty
		row, ok := rows[ty.Kind]
		if !ok {
			t.Errorf("declared kind %s has no row in the design's table", ty.Kind)
			continue
		}
		if row.schema != ty.Schema {
			t.Errorf("%s: table schema %d, declared %d", ty.Kind, row.schema, ty.Schema)
		}
		if row.alert != ty.Alert {
			t.Errorf("%s: table alert %v, declared %v", ty.Kind, row.alert, ty.Alert)
		}
		if want := kindClass(ty.Kind); row.class != want {
			t.Errorf("%s: table class %q, want %q", ty.Kind, row.class, want)
		}
	}
	for _, row := range rows {
		if row.class == "common" || row.class == "core" {
			if _, ok := declared[row.kind]; !ok {
				t.Errorf("%s row: a common/core kind must be declared", row.kind)
			}
		}
		for _, name := range row.emitters {
			if contractNames[name] {
				if _, ok := declared[row.kind]; !ok {
					t.Errorf("%s row: emitted by contract module %s but not declared", row.kind, name)
				}
			}
		}
	}
	for _, m := range contract {
		for _, ty := range m.emits {
			row, ok := rows[ty.Kind]
			if !ok {
				t.Errorf("%s: emits %s, which has no table row", m.name, ty.Kind)
				continue
			}
			if !contains(row.emitters, m.name) {
				t.Errorf("%s: emits %s, but the table does not name it as emitter", m.name, ty.Kind)
			}
		}
		for _, kind := range m.consumes {
			if _, ok := rows[kind]; !ok {
				t.Errorf("%s: consumes %s, which has no table row", m.name, kind)
			}
		}
	}
}

// TestPreContractShrinks: every registered module without a manifest is on the
// pre-contract list, and no listed name may have gained a manifest.
func TestPreContractShrinks(t *testing.T) {
	pre := map[string]bool{}
	for _, name := range PreContract {
		pre[name] = true
	}
	hasManifest := map[string]bool{}
	for _, f := range agent.Registered() {
		hasManifest[f.Name] = f.Manifest.Name != ""
	}
	for _, m := range module.Registered() {
		name := m.Manifest().Name
		if hasManifest[name] {
			t.Errorf("module %s is registered twice, once with and once without a manifest", name)
		}
		hasManifest[name] = true
	}
	for name, manifest := range hasManifest {
		if !manifest && !pre[name] {
			t.Errorf("%s has no manifest and is not in PreContract", name)
		}
		if manifest && pre[name] {
			t.Errorf("%s has a manifest now: remove it from PreContract", name)
		}
	}
}

// TestConformanceTestPresent: every contract module ships its own conformance
// test.
func TestConformanceTestPresent(t *testing.T) {
	for _, m := range contractModules(t) {
		dir := filepath.Join(repoRoot, relPath(m.pkg))
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Errorf("%s: %v", m.name, err)
			continue
		}
		found := false
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Errorf("%s: %v", m.name, err)
				continue
			}
			body := string(raw)
			if strings.Contains(body, "conformance.Agent(") || strings.Contains(body, "conformance.Controller(") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: no conformance test in %s", m.name, dir)
		}
	}
}

// TestLibrariesStateless: an allowed library registers nothing and keeps no
// package-level state that is reassigned outside init.
//
// shortcut: the state check is syntactic (a reassigned map, slice or pointer
// variable); upgrade to go/analysis if a library hides state behind a
// constructor.
func TestLibrariesStateless(t *testing.T) {
	for _, lib := range AllowedLibraries {
		for _, dir := range goPackages(filepath.Join(repoRoot, relPath(lib))) {
			files, err := parseDir(dir)
			if err != nil {
				t.Errorf("%s: %v", dir, err)
				continue
			}
			mutable := map[string]bool{}
			for _, f := range files {
				for _, d := range f.file.Decls {
					gen, ok := d.(*ast.GenDecl)
					if !ok || gen.Tok != token.VAR {
						continue
					}
					for _, spec := range gen.Specs {
						vs := spec.(*ast.ValueSpec)
						for i, name := range vs.Names {
							if name.Name == "_" {
								continue
							}
							if vs.Type != nil && mutableType(vs.Type) {
								mutable[name.Name] = true
							} else if i < len(vs.Values) && mutableValue(vs.Values[i]) {
								mutable[name.Name] = true
							}
						}
					}
				}
			}
			for _, f := range files {
				ast.Inspect(f.file, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.AssignStmt:
						for _, l := range x.Lhs {
							if id, ok := l.(*ast.Ident); ok && x.Tok != token.DEFINE && mutable[id.Name] {
								t.Errorf("%s: package-level %s is assigned in %s", dir, id.Name, x.Tok)
							}
						}
					case *ast.IncDecStmt:
						if id, ok := x.X.(*ast.Ident); ok && mutable[id.Name] {
							t.Errorf("%s: package-level %s is changed", dir, id.Name)
						}
					case *ast.FuncDecl:
						if x.Name.Name != "init" {
							return true
						}
						ast.Inspect(x.Body, func(n ast.Node) bool {
							call, ok := n.(*ast.CallExpr)
							if !ok {
								return true
							}
							fn := ""
							switch f := call.Fun.(type) {
							case *ast.Ident:
								fn = f.Name
							case *ast.SelectorExpr:
								fn = f.Sel.Name
							}
							switch fn {
							case "Register", "Declare", "RegisterFactory":
								t.Errorf("%s: init calls %s", dir, fn)
							}
							return true
						})
					}
					return true
				})
			}
		}
	}
}

// TestCoreImportsHasPlans keeps the root plans package (Host plan templates)
// importable by a module. It lives here because the list does.
func TestCoreImportsHasPlans(t *testing.T) {
	if !contains(CoreImports, "github.com/PurdueBlueTeam/phylax/plans") {
		t.Fatal("plans package missing from CoreImports")
	}
}

func TestImportCheckCatchesSibling(t *testing.T) {
	if err := checkFileImports("depot", "testdata/sibling/a.go"); err == nil || !strings.Contains(err.Error(), "internal/integrity") {
		t.Fatalf("a module importing a sibling module must fail the import check: %v", err)
	}
	if err := checkFileImports("depot", "testdata/ok/a.go"); err != nil {
		t.Fatalf("core packages and allowed libraries must pass: %v", err)
	}
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
	own := ModulePackages[module]
	if own == "" {
		own = modPrefix + "/internal/" + module
	}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return fmt.Errorf("%s: bad import path %s", path, imp.Path.Value)
		}
		if p == own || strings.HasPrefix(p, own+"/") {
			continue
		}
		if p == modPrefix+"/internal/enroll" || strings.HasPrefix(p, modPrefix+"/internal/enroll/") {
			return fmt.Errorf("%s: a module may not import %s", path, p)
		}
		if !strings.HasPrefix(p, modPrefix) {
			continue // standard library or a dependency
		}
		if mayImport(p) {
			continue
		}
		return fmt.Errorf("%s: a module may not import %s", path, p)
	}
	return nil
}

// mayImport reports a repo package a module may import: core, an allowed
// library (with its subpackages) or a non-internal package such as plans.
func mayImport(p string) bool {
	if !strings.HasPrefix(p, modPrefix) {
		return true
	}
	for _, c := range CoreImports {
		if p == c || strings.HasPrefix(p, c+"/") {
			return true
		}
	}
	for _, l := range AllowedLibraries {
		if p == l || strings.HasPrefix(p, l+"/") {
			return true
		}
	}
	return !strings.HasPrefix(p, modPrefix+"/internal/")
}

func isCorePackage(pkg string) bool {
	for _, c := range CoreImports {
		if pkg == c {
			return true
		}
	}
	return false
}

// packageDeps runs go list over the package and returns every import path it
// pulls in.
func packageDeps(pkg string) ([]string, error) {
	rel := relPath(pkg)
	cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./"+rel+"/...")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("go list %s: %v\n%s", pkg, err, out)
	}
	var deps []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			deps = append(deps, line)
		}
	}
	return deps, nil
}

func relPath(pkg string) string {
	return strings.TrimPrefix(pkg, modPrefix+"/")
}

// contractModule is one module on the contract: a registered agent factory or
// controller module with a manifest, not on the pre-contract list.
type contractModule struct {
	name     string
	pkg      string
	emits    []event.Type
	consumes []string
}

func contractModules(t *testing.T) []contractModule {
	t.Helper()
	pre := map[string]bool{}
	for _, name := range PreContract {
		pre[name] = true
	}
	byName := map[string]contractModule{}
	add := func(name string, emits []event.Type, consumes []string) {
		if pre[name] {
			return
		}
		pkg := ModulePackages[name]
		if pkg == "" {
			t.Errorf("%s is on the contract but has no entry in ModulePackages", name)
			return
		}
		byName[name] = contractModule{name: name, pkg: pkg, emits: emits, consumes: consumes}
	}
	for _, f := range agent.Registered() {
		if f.Manifest.Name == "" {
			continue
		}
		add(f.Name, f.Manifest.Emits, f.Manifest.Consumes)
	}
	for _, m := range module.Registered() {
		man := m.Manifest()
		add(man.Name, man.Emits, man.Consumes)
	}
	out := make([]contractModule, 0, len(byName))
	for _, m := range byName {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// testKindPrefixes are the fixture kinds the suite's own tests declare.
var testKindPrefixes = []string{"ttest.", "ctltest.", "regtest."}

func isTestKind(kind string) bool {
	for _, p := range testKindPrefixes {
		if strings.HasPrefix(kind, p) {
			return true
		}
	}
	return false
}

var (
	commonKinds = []string{"process_start", "process_exit", "file_change", "conn", "listener", "auth_event", "dns_query", "telemetry_gap"}
	coreKinds   = []string{
		"agent.start", "agent.health", "agent.step", "agent.step_result", "agent.step_refused",
		"evidence.blob", "agent.config_applied", "agent.config_rejected", "agent.control_refused",
		"agent.module_crash", "controller.fact", "agent.deadman_fired", "agent.deadman_recovered",
		"agent.deadman_recovery_error", "agent.enrolled", "agent.reenrolled", "agent.silent",
		"agent.resumed", "spool.gap", "enroll.refused", "enroll.hash_mismatch", "enroll.no_show",
		"controller.locked", "store.quota", "enroll.key_mismatch", "enroll.key_reuse",
		"plan.step_timeout", "plan.bad_result", "plan.deadman_fired", "plan.rollback_failed",
		"plan.restore_failed", "plan.confirm_failed", "plan.auto_halted",
	}
)

func kindClass(kind string) string {
	if contains(commonKinds, kind) {
		return "common"
	}
	if contains(coreKinds, kind) {
		return "core"
	}
	return "module"
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// kindRow is one row of the design's Event kinds table.
type kindRow struct {
	kind     string
	class    string
	schema   int
	alert    bool
	emitters []string
}

var designKindRe = regexp.MustCompile("`([a-z_][a-z0-9_.]*)`")

// parseKindTable reads the Event kinds table of phylax_design.md: the rows
// between the "| Kind | Class |" header and the next blank line.
func parseKindTable(t *testing.T) map[string]kindRow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, "phylax_design.md"))
	if err != nil {
		t.Fatal(err)
	}
	moduleNames := map[string]bool{}
	for name := range ModulePackages {
		moduleNames[name] = true
	}
	rows := map[string]kindRow{}
	inTable := false
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "| Kind | Class |") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		if !strings.HasPrefix(line, "|") {
			break
		}
		cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		if len(cells) < 6 {
			t.Fatalf("event kinds row has %d cells: %q", len(cells), line)
		}
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if strings.HasPrefix(cells[0], "---") {
			continue // the separator row
		}
		kind := strings.Trim(cells[0], "`")
		schema, err := strconv.Atoi(cells[2])
		if err != nil {
			t.Fatalf("%s: schema %q is not a number", kind, cells[2])
		}
		row := kindRow{kind: kind, class: cells[1], schema: schema, alert: cells[3] == "yes"}
		for _, m := range designKindRe.FindAllStringSubmatch(cells[4], -1) {
			if moduleNames[m[1]] {
				row.emitters = append(row.emitters, m[1])
			}
		}
		rows[kind] = row
	}
	if len(rows) == 0 {
		t.Fatal("event kinds table not found in phylax_design.md")
	}
	return rows
}

// parsedFile is one parsed Go source file.
type parsedFile struct {
	path string
	file *ast.File
}

// goPackages returns the package directories under dir that hold Go files: dir
// itself, or (for an umbrella such as internal/parsers) its subpackages.
func goPackages(dir string) []string {
	if hasGoFiles(dir) {
		return []string{dir}
	}
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if p != dir && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if p != dir && hasGoFiles(p) {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func hasGoFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
			return true
		}
	}
	return false
}

func parseDir(dir string) ([]parsedFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	var out []parsedFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, parsedFile{path: p, file: f})
	}
	return out, nil
}

// mutableType reports a map, slice or pointer type.
func mutableType(e ast.Expr) bool {
	switch e.(type) {
	case *ast.MapType, *ast.ArrayType, *ast.StarExpr:
		return true
	}
	return false
}

// mutableValue reports a package-level initialiser that yields mutable state.
func mutableValue(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.CompositeLit:
		return mutableType(x.Type)
	case *ast.UnaryExpr:
		return x.Op == token.AND
	case *ast.CallExpr:
		if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "make" && len(x.Args) > 0 {
			return mutableType(x.Args[0])
		}
	}
	return false
}
