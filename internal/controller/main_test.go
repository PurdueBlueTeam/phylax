package controller

import (
	"os"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/ui"
)

// TestMain lowers the operator UI's password hashing cost so the tests do not
// spend time on the production argon2id profile.
func TestMain(m *testing.M) {
	uiArgon2 = ui.Argon2Params{Time: 1, Memory: 8, Threads: 1}
	os.Exit(m.Run())
}
