package probe

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestProbeHasNoSchedulerOrGlobals enforces the shared-library property the
// design and the module contract rely on: this package is stateless protocol
// code. A goroutine of its own (a scheduler) or a package-level lock, map or
// timer would make it stateful, so the source is checked directly: no `go`
// statement anywhere (Sweep runs probes one after another with a gap) and no
// package-level var of a synchronisation or timing type.
func TestProbeHasNoSchedulerOrGlobals(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checked++
		ast.Inspect(f, func(n ast.Node) bool {
			if g, ok := n.(*ast.GoStmt); ok {
				t.Errorf("%s:%d: `go` statement: the probe library runs probes sequentially",
					name, fset.Position(g.Pos()).Line)
			}
			return true
		})
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, s := range gd.Specs {
				vs, ok := s.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if typ := statefulType(vs.Type); typ != "" {
					t.Errorf("%s:%d: package-level %s: the probe library keeps no state",
						name, fset.Position(vs.Pos()).Line, typ)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no non-test files checked: the package moved?")
	}
}

// statefulType names the forbidden type of a package-level var, or "".
func statefulType(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.StarExpr:
		return statefulType(e.X)
	case *ast.ChanType:
		return "chan"
	case *ast.SelectorExpr:
		pkg, ok := e.X.(*ast.Ident)
		if !ok {
			return ""
		}
		switch typ := pkg.Name + "." + e.Sel.Name; typ {
		case "sync.Mutex", "sync.Map", "time.Ticker", "time.Timer":
			return typ
		}
	}
	return ""
}

func TestTypesListsEighteen(t *testing.T) {
	if n := len(Types()); n != 18 {
		t.Fatalf("%d", n)
	}
}
