package ui

import "testing"

func TestHealthPageModuleTable(t *testing.T) {
	t.Skip("unimplemented: W1 Task 40")
	// Ops fake returning rows {Agent: "h1", Module: "audit", State: "degraded", Gaps: ["<b>x</b>: y"], PreContract: true}
	// logged-in GET /health -> 200; body contains "audit", "pre-contract", and the gap text escaped (&lt;b&gt;)
}
