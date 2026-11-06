package ui

import (
	"context"
	"html/template"
	"net/http"
)

// Registrar is what a module uses to add pages, actions, tiles and grid
// columns to the operator UI.
type Registrar interface {
	Page(route, title string, h http.Handler) // GET /m/<module>/<route>
	Tile(name string, render func(ctx context.Context) (template.HTML, error))
	GridColumn(step string, cell func(ctx context.Context, host string) Cell)
	Action(name string, h http.Handler) // POST /m/<module>/action/<name>
}

// Cell is one grid column value.
type Cell struct {
	State  string // verified | pending | failed | drifted | n/a | manual
	Detail string
	Link   string
}

type discard struct{}

func (discard) Page(string, string, http.Handler)                         {}
func (discard) Tile(string, func(context.Context) (template.HTML, error)) {}
func (discard) GridColumn(string, func(context.Context, string) Cell)     {}
func (discard) Action(string, http.Handler)                               {}

// Discard registers nothing (UI off).
var Discard Registrar = discard{}

// TileView is one rendered module tile.
type TileView struct {
	Module, Name string
	HTML         template.HTML
	Err          string
}

// GridColumnView is one module grid column.
type GridColumnView struct {
	Module, Step string
	Cell         func(ctx context.Context, host string) Cell
}

// PageLink is one module page link.
type PageLink struct{ Module, Route, Title string }

// ModuleRow is one module's health on the Platform page (ui does not import module).
type ModuleRow struct {
	Agent, Module, State, Detail string
	Gaps                         []string
	PreContract                  bool
}

// Registrar returns the module's registrar.
func (s *Server) Registrar(module string, enabled func() bool) Registrar {
	panic("unimplemented: W1 Task 10")
}

// Tiles returns every enabled module tile.
func (s *Server) Tiles(ctx context.Context) []TileView { panic("unimplemented: W1 Task 10") }

// GridColumns returns every enabled module grid column.
func (s *Server) GridColumns() []GridColumnView { panic("unimplemented: W1 Task 10") }

// ModulePages returns every enabled module page link.
func (s *Server) ModulePages() []PageLink { panic("unimplemented: W1 Task 10") }
