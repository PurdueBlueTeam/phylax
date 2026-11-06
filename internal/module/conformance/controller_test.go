package conformance

import (
	"testing"
	"time"
)

func TestControllerCheck11CatchesNondeterminism(t *testing.T) {
	t.Skip("unimplemented: W1 Task 36")
	c := ControllerCase{Module: randomAnalyserModule(), Config: "enabled: true\n", Now: time.Unix(1e9, 0)}
	if errs := runControllerChecks(c); errs["analysers"] == nil {
		t.Fatal("nondeterministic analyser not detected")
	}
}

func TestControllerCheck9CatchesLooseConfig(t *testing.T) {
	t.Skip("unimplemented: W1 Task 36")
	c := ControllerCase{Module: ignoresConfigErrorModule(), Config: "enabled: true\n", Now: time.Unix(1e9, 0)}
	if errs := runControllerChecks(c); errs["config_decode"] == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestControllerChecksPass(t *testing.T) {
	t.Skip("unimplemented: W1 Task 36")
	Controller(t, ControllerCase{Module: goodControllerModule(), Config: "enabled: true\n", Now: time.Unix(1e9, 0)})
}
