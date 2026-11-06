package ui

import (
	"net/url"
	"strings"
	"testing"
)

func TestProposalsPage(t *testing.T) {
	e, f := opsEnv(t)
	c, tok := e.loggedIn()
	w := c.do("GET", "/proposals", nil, nil)
	if w.Code != 200 {
		t.Fatalf("GET /proposals: %d\n%s", w.Code, w.Body)
	}
	body := w.Body.String()
	if strings.Contains(body, "<script>x</script>") || !strings.Contains(body, "&lt;script&gt;x&lt;/script&gt;") {
		t.Fatalf("proposal title not escaped:\n%s", body)
	}
	w = c.do("POST", "/proposals/1/accept", url.Values{"csrf_token": {tok}}, nil)
	if w.Code != 303 || w.Header().Get("Location") != "/proposals" {
		t.Fatalf("accept: %d %q\n%s", w.Code, w.Header().Get("Location"), w.Body)
	}
	if got := f.called(); !strings.Contains(got, "acceptproposal:1:admin") {
		t.Fatalf("accept not attributed to the operator: %q", got)
	}
	w = c.do("POST", "/proposals/1/dismiss", url.Values{"csrf_token": {tok}}, nil)
	if w.Code != 303 || w.Header().Get("Location") != "/proposals" {
		t.Fatalf("dismiss: %d %q", w.Code, w.Header().Get("Location"))
	}
	if got := f.called(); !strings.Contains(got, "dismissproposal:1:admin") {
		t.Fatalf("dismiss not attributed to the operator: %q", got)
	}
}
