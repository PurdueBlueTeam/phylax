package ui

import (
	"context"
	"strings"
	"testing"
)

// healthFake is a fakeOps that also serves the health page.
type healthFake struct{ *fakeOps }

func (healthFake) Health(context.Context) (HealthView, error) {
	return HealthView{Platform: []KV{{Key: "Version", Value: "test"}}}, nil
}
func (healthFake) Audit(context.Context, AuditQuery) (AuditPageView, error) {
	return AuditPageView{}, nil
}

func TestHealthPageModuleTable(t *testing.T) {
	f := &fakeOps{modules: []ModuleRow{
		{Agent: "h1", Module: "audit", State: "degraded", Detail: "rule load failed",
			Gaps: []string{"<b>x</b>: y"}, PreContract: true},
		{Agent: "controller", Module: "suricata", State: "unavailable", Detail: "the pcap run is not built"},
	}}
	e := newEnv(t, func(c *Config) { c.Ops = healthFake{f} })
	c, _ := e.loggedIn()
	w := c.do("GET", "/health", nil, nil)
	if w.Code != 200 {
		t.Fatalf("GET /health: %d\n%s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{"audit", "rule load failed", "&lt;b&gt;x&lt;/b&gt;: y", "<td>pre-contract</td>", "<td>contract</td>", "suricata"} {
		if !strings.Contains(body, want) {
			t.Errorf("health page lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<b>x</b>") {
		t.Error("a gap was rendered unescaped")
	}
}
