package ui

import (
	"context"
	"html/template"
	"net/http"
	"regexp"
	"strings"
)

// Registrar is what a module uses to add pages, actions, tiles and grid
// columns to the operator UI.
//
// Registration happens before the server serves: the mux and the view slices
// are not written while requests run.
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

// Naming rules. A module or action name is one path segment; a route may have
// a few. Anything else is a programming error, so it panics.
var (
	moduleNameRe = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	routeRe      = regexp.MustCompile(`^[a-z0-9_/-]{1,64}$`)
)

// Registrar returns the module's registrar.
func (s *Server) Registrar(module string, enabled func() bool) Registrar {
	if !moduleNameRe.MatchString(module) {
		panic("ui: bad module name " + module)
	}
	if enabled == nil {
		enabled = func() bool { return true }
	}
	return &moduleRegistrar{s: s, module: module, enabled: enabled}
}

type moduleRegistrar struct {
	s       *Server
	module  string
	enabled func() bool
}

// gate makes a handler serve 404 while the module is disabled. The route
// stays registered, so enablement can change without a restart.
func (r *moduleRegistrar) gate(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !r.enabled() {
			http.NotFound(w, req)
			return
		}
		h.ServeHTTP(w, req)
	})
}

func (r *moduleRegistrar) Page(route, title string, h http.Handler) {
	if !routeRe.MatchString(route) || strings.Contains(route, "..") {
		panic("ui: bad module route " + route)
	}
	r.s.Handle("GET /m/"+r.module+"/"+route, r.gate(h))
	r.s.regMu.Lock()
	r.s.modPages = append(r.s.modPages, modPage{module: r.module, route: route, title: title, enabled: r.enabled})
	r.s.regMu.Unlock()
}

func (r *moduleRegistrar) Action(name string, h http.Handler) {
	if !moduleNameRe.MatchString(name) {
		panic("ui: bad module action name " + name)
	}
	r.s.Handle("POST /m/"+r.module+"/action/"+name, r.gate(h))
}

func (r *moduleRegistrar) Tile(name string, render func(ctx context.Context) (template.HTML, error)) {
	if !moduleNameRe.MatchString(name) || render == nil {
		panic("ui: bad module tile " + name)
	}
	r.s.regMu.Lock()
	r.s.modTiles = append(r.s.modTiles, modTile{module: r.module, name: name, render: render, enabled: r.enabled})
	r.s.regMu.Unlock()
}

func (r *moduleRegistrar) GridColumn(step string, cell func(ctx context.Context, host string) Cell) {
	if step == "" || cell == nil {
		panic("ui: bad module grid column " + step)
	}
	r.s.regMu.Lock()
	r.s.modGrids = append(r.s.modGrids, modGrid{module: r.module, step: step, cell: cell, enabled: r.enabled})
	r.s.regMu.Unlock()
}

// Tiles returns every enabled module tile, in registration order. A tile whose
// render fails carries the error text instead of HTML; the page still renders.
func (s *Server) Tiles(ctx context.Context) []TileView {
	s.regMu.Lock()
	regs := append([]modTile(nil), s.modTiles...)
	s.regMu.Unlock()
	out := make([]TileView, 0, len(regs))
	for _, t := range regs {
		if !t.enabled() {
			continue
		}
		v := TileView{Module: t.module, Name: t.name}
		html, err := t.render(ctx)
		if err != nil {
			v.Err = err.Error()
		} else {
			v.HTML = html
		}
		out = append(out, v)
	}
	return out
}

// GridColumns returns every enabled module grid column.
func (s *Server) GridColumns() []GridColumnView {
	s.regMu.Lock()
	defer s.regMu.Unlock()
	out := make([]GridColumnView, 0, len(s.modGrids))
	for _, g := range s.modGrids {
		if g.enabled() {
			out = append(out, GridColumnView{Module: g.module, Step: g.step, Cell: g.cell})
		}
	}
	return out
}

// ModulePages returns every enabled module page link.
func (s *Server) ModulePages() []PageLink {
	s.regMu.Lock()
	defer s.regMu.Unlock()
	out := make([]PageLink, 0, len(s.modPages))
	for _, p := range s.modPages {
		if p.enabled() {
			out = append(out, PageLink{Module: p.module, Route: p.route, Title: p.title})
		}
	}
	return out
}

// The registration records the views are built from.
type modTile struct {
	module, name string
	render       func(ctx context.Context) (template.HTML, error)
	enabled      func() bool
}

type modGrid struct {
	module, step string
	cell         func(ctx context.Context, host string) Cell
	enabled      func() bool
}

type modPage struct {
	module, route, title string
	enabled              func() bool
}
