package action

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostExec(t *testing.T) {
	a := hostExec{}
	r, err := a.Apply(Params(map[string]any{"cmd": []string{"echo", "hello"}}))
	if err != nil || !r.Done {
		t.Fatalf("apply: %+v %v", r, err)
	}
	if !strings.Contains(string(r.After), "hello") {
		t.Fatalf("output %q", r.After)
	}
	// failing command surfaces the error with output
	_, err = a.Apply(Params(map[string]any{"cmd": []string{"sh", "-c", "echo boom >&2; exit 3"}}))
	if err == nil {
		t.Fatal("expected error for exit 3")
	}
	// missing cmd
	if _, err := a.Check(Params(nil)); err == nil {
		t.Fatal("expected error for empty cmd")
	}
}

func TestHealthCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()

	a := healthCheck{}
	r, err := a.Check(Params(map[string]any{"target": srv.URL, "expect_status": 204}))
	if err != nil || !r.Done {
		t.Fatalf("probe: %+v %v", r, err)
	}
	// wrong expectation → not done
	r, _ = a.Check(Params(map[string]any{"target": srv.URL, "expect_status": 200}))
	if r.Done {
		t.Fatal("expected mismatch")
	}
	// unreachable
	r, _ = a.Check(Params(map[string]any{"target": "http://127.0.0.1:1", "timeout": 1}))
	if r.Done {
		t.Fatal("expected unreachable")
	}
}

func TestAgentSafeMode(t *testing.T) {
	old := AgentStateDir
	AgentStateDir = t.TempDir()
	t.Cleanup(func() { AgentStateDir = old })

	a := agentSafeMode{}
	r, err := a.Check(Params(map[string]any{"on": true}))
	if err != nil || r.Done {
		t.Fatalf("expected diff, got %+v %v", r, err)
	}
	if _, err := a.Apply(Params(map[string]any{"on": true})); err != nil {
		t.Fatal(err)
	}
	if r, _ := a.Verify(Params(map[string]any{"on": true})); !r.Done {
		t.Fatal("verify")
	}
	// off
	if _, err := a.Apply(Params(map[string]any{"on": false})); err != nil {
		t.Fatal(err)
	}
	if r, _ := a.Check(Params(map[string]any{"on": true})); r.Done {
		t.Fatal("expected diff after turning off")
	}
}

func TestAgentConfigRoundTrip(t *testing.T) {
	old := AgentStateDir
	AgentStateDir = t.TempDir()
	t.Cleanup(func() { AgentStateDir = old })

	a := agentConfig{}
	r, err := a.Apply(Params(map[string]any{"key": "heartbeat_ms", "value": "15000"}))
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := a.Verify(Params(map[string]any{"key": "heartbeat_ms", "value": "15000"})); !r.Done {
		t.Fatal("verify")
	}
	// second key
	if _, err := a.Apply(Params(map[string]any{"key": "spool_mb", "value": "200"})); err != nil {
		t.Fatal(err)
	}
	// rollback the first change: restore the config as it was after apply 1
	if _, err := a.Rollback(Params(nil), r.Before); err != nil {
		t.Fatal(err)
	}
	if r, _ := a.Check(Params(map[string]any{"key": "spool_mb", "value": "200"})); r.Done {
		t.Fatal("spool_mb should be gone after rollback")
	}
}

func TestAgentSetController(t *testing.T) {
	old := AgentStateDir
	AgentStateDir = t.TempDir()
	t.Cleanup(func() { AgentStateDir = old })
	if err := os.WriteFile(filepath.Join(AgentStateDir, "bootstrap.json"),
		[]byte(`{"controller":"tcp://10.0.0.1:8443"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	a := agentSetController{}
	r, err := a.Check(Params(map[string]any{"address": "tcp://10.0.0.2:8443"}))
	if err != nil || r.Done {
		t.Fatalf("expected diff, got %+v %v", r, err)
	}
	if _, err := a.Apply(Params(map[string]any{"address": "tcp://10.0.0.2:8443"})); err != nil {
		t.Fatal(err)
	}
	if r, _ := a.Verify(Params(map[string]any{"address": "tcp://10.0.0.2:8443"})); !r.Done {
		t.Fatal("verify")
	}
	// rollback
	if _, err := a.Rollback(Params(nil), r.Before); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(AgentStateDir, "bootstrap.json"))
	if !strings.Contains(string(b), "10.0.0.1") {
		t.Fatalf("rollback: %s", b)
	}
}

func TestAgentReplaceBinary(t *testing.T) {
	old := AgentStateDir
	AgentStateDir = t.TempDir()
	t.Cleanup(func() { AgentStateDir = old })

	a := agentReplaceBinary{}
	// no staged binary → apply fails
	if _, err := a.Apply(Params(nil)); err == nil {
		t.Fatal("expected missing-binary error")
	}
	bin := []byte("ELF-fake-binary")
	if err := os.WriteFile(filepath.Join(AgentStateDir, "phylax.new"), bin, 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := a.Apply(Params(map[string]any{"sha256": fullSHA(bin)}))
	if err != nil || !r.Done {
		t.Fatalf("apply: %+v %v", r, err)
	}
	// wrong hash
	if _, err := a.Apply(Params(map[string]any{"sha256": strings.Repeat("0", 64)})); err == nil {
		t.Fatal("expected hash mismatch")
	}
	// rollback removes the staged binary
	if _, err := a.Rollback(Params(nil), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(AgentStateDir, "phylax.new")); !os.IsNotExist(err) {
		t.Fatal("staged binary should be removed")
	}
}
