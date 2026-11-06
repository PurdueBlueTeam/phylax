package ui

import (
	"context"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"testing"
)

func TestRegistrarPage(t *testing.T) {
	t.Skip("unimplemented: W1 Task 10")
	e := newEnv(t, nil)
	on := true
	r := e.s.Registrar("demo", func() bool { return on })
	r.Page("x", "Demo", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "hi") }))
	anon := &client{e: e}
	if w := anon.do("GET", "/m/demo/x", nil, nil); w.Code == 200 {
		t.Fatal("unauthenticated page served")
	}
	c, _ := e.loggedIn()
	if w := c.do("GET", "/m/demo/x", nil, nil); w.Code != 200 || w.Body.String() != "hi" {
		t.Fatalf("page: %d %q", w.Code, w.Body)
	}
	on = false
	if w := c.do("GET", "/m/demo/x", nil, nil); w.Code != 404 {
		t.Fatalf("disabled page: %d", w.Code)
	}
}

func TestRegistrarActionNeedsCSRF(t *testing.T) {
	t.Skip("unimplemented: W1 Task 10")
	e := newEnv(t, nil)
	r := e.s.Registrar("demo", func() bool { return true })
	r.Action("go", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	c, tok := e.loggedIn()
	if w := c.do("POST", "/m/demo/action/go", url.Values{}, nil); w.Code != 403 {
		t.Fatalf("no csrf: %d", w.Code)
	}
	if w := c.do("POST", "/m/demo/action/go", url.Values{"csrf_token": {tok}}, nil); w.Code != 204 {
		t.Fatalf("with csrf: %d", w.Code)
	}
}

func TestRegistrarTiles(t *testing.T) {
	t.Skip("unimplemented: W1 Task 10")
	e := newEnv(t, nil)
	on := true
	r := e.s.Registrar("demo", func() bool { return on })
	r.Tile("t", func(context.Context) (template.HTML, error) { return "<b>ok</b>", nil })
	r.Tile("bad", func(context.Context) (template.HTML, error) { return "", errors.New("boom") })
	tv := e.s.Tiles(context.Background())
	if len(tv) != 2 {
		t.Fatalf("%+v", tv)
	}
	seen := map[string]TileView{}
	for _, v := range tv {
		seen[v.Name] = v
	}
	if seen["t"].HTML != "<b>ok</b>" || seen["bad"].Err != "boom" {
		t.Fatalf("%+v", seen)
	}
	on = false
	if len(e.s.Tiles(context.Background())) != 0 {
		t.Fatal("disabled module tile shown")
	}
}

func TestRegistrarRejectsBadRoute(t *testing.T) {
	t.Skip("unimplemented: W1 Task 10")
	e := newEnv(t, nil)
	defer func() {
		if recover() == nil {
			t.Fatal("bad route accepted")
		}
	}()
	e.s.Registrar("demo", func() bool { return true }).Page("../x", "x", http.NotFoundHandler())
}
