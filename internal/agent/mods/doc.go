// Package mods registers the agent's production modules (net, audit, winevt,
// integrity, detect) as factories of the agent's module registry. Import it
// for its side effect; the agent then starts, stops and reconfigures them from
// the signed config the controller generates from the manifest.
//
// The sensor packages import internal/agent (for Module and Emit), so the
// agent cannot import them; this package sits above both.
package mods

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
)

// fp fingerprints a settings section by its JSON form.
func fp(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("unmarshalable:%v", err)
	}
	return string(b)
}

func spec(m agent.Module, rate float64, burst int) agent.ModuleSpec {
	return agent.ModuleSpec{Module: m, Rate: rate, Burst: burst}
}

func secs(n int, def time.Duration) time.Duration {
	if n > 0 {
		return time.Duration(n) * time.Second
	}
	return def
}

func unavailable(why string) error { return fmt.Errorf("%w: %s", agent.ErrUnavailable, why) }

// subSpec is spec for a module that subscribes to the agent event stream.
func subSpec(m agent.Module, rate float64, burst int) agent.ModuleSpec {
	sp := spec(m, rate, burst)
	sp.Subscriber = true
	return sp
}
