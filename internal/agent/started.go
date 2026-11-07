package agent

import (
	"encoding/json"
	"os"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/svcinstall"
)

// writeStarted records the first controller ack of this process in
// <state>/started.json, once per process. The swap helper of
// agent.replace_binary and agent.rename waits for an entry newer than its swap
// before it makes the swap durable, and reverts if none arrives in time.
func (a *Agent) writeStarted() {
	a.startedOnce.Do(func() {
		raw, err := json.Marshal(svcinstall.Started{PID: os.Getpid(), Time: time.Now().UTC()})
		if err != nil {
			return
		}
		if err := atomicfile.WriteFile(a.cfg.Layout.Started(), raw, 0o600); err != nil {
			a.log.Warn("could not record the first ack", "err", err)
		}
	})
}
