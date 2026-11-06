package conformance

import (
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
)

// ControllerCase is one controller module under test.
type ControllerCase struct {
	Module module.ControllerModule
	Config string        // YAML of modules/<name>.yml with the default settings
	Seed   []event.Event // fixture store contents for analysers (check 11)
	Now    time.Time
}

// Controller runs the controller-side conformance checks.
func Controller(t *testing.T, c ControllerCase) { panic("unimplemented: W1 Task 36") }

func runControllerChecks(c ControllerCase) map[string]error {
	panic("unimplemented: W1 Task 36")
}
