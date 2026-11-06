package ui

import "testing"

func TestProposalsPage(t *testing.T) {
	t.Skip("unimplemented: W1 Task 25")
	// Ops fake returning one open proposal titled "<script>x</script>": GET /proposals is 200 and the title is escaped
	// POST /proposals/1/accept with CSRF calls Ops.AcceptProposal(1, <operator>) and redirects
}
