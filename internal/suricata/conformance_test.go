package suricata

import (
	"io"
	"os"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module/conformance"
)

func mustOpen(t *testing.T, path string) io.Reader {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestSuricataConformance(t *testing.T) {
	conformance.Controller(t, conformance.ControllerCase{Module: &Module{}, Config: "enabled: true\n", Now: time.Unix(1e9, 0)})
}

func TestReadEVEEmitsDeclaredKinds(t *testing.T) {
	evs, _, err := ReadEVE(mustOpen(t, "testdata/eve.json"), false)
	if err != nil || len(evs) == 0 {
		t.Fatal(err)
	}
	for _, e := range evs {
		if e.Agent != "" {
			t.Fatalf("reader must not set the agent: %q", e.Agent)
		}
		if err := event.Validate(e); err != nil {
			t.Fatalf("%s: %v", e.Kind, err)
		}
	}
}

func TestReadZeekKinds(t *testing.T) {
	evs, _, _ := ReadZeek(mustOpen(t, "testdata/conn.log"), KindZeekConn)
	if len(evs) == 0 || evs[0].Kind != "suricata.zeek_conn" {
		t.Fatalf("%v", evs)
	}
}
