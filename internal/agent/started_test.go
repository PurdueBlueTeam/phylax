package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAgentWritesStartedAfterFirstAck(t *testing.T) {
	ctl := newFakeController(t, "started-host", "tok-1", 0)
	l := Layout{Root: t.TempDir()}
	writeBundle(t, l, ctl, "tok-1")
	start := time.Now().Add(-time.Second)
	startAgent(t, Config{Layout: l, Version: "9.9", HeartbeatInterval: 50 * time.Millisecond})
	var got struct {
		PID  int       `json:"pid"`
		Time time.Time `json:"time"`
	}
	eventually(t, 5*time.Second, "started.json after the first ack", func() bool {
		raw, err := os.ReadFile(filepath.Join(l.Root, "started.json"))
		if err != nil {
			return false
		}
		return json.Unmarshal(raw, &got) == nil
	})
	if got.PID != os.Getpid() {
		t.Fatalf("started.json pid %d, want %d", got.PID, os.Getpid())
	}
	if got.Time.Before(start) {
		t.Fatalf("started.json time %s is older than the test start", got.Time)
	}
}
