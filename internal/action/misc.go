package action

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)
// ---- host.exec --------------------------------------------------------------------

// host.exec is the escape hatch: run an arbitrary command. It is always
// risk-class destructive and its plan node always requires explicit approval
// (enforced by the plan engine, not here).

type hostExec struct{}

func (hostExec) Name() string   { return "host.exec" }
func (hostExec) Risk() Risk     { return RiskDestructive }
func (hostExec) Locks() []string { return nil }

const execOutputCap = 64 * 1024

func (a hostExec) Check(p Params) (CheckResult, error) {
	cmd := p.GetList("cmd")
	if len(cmd) == 0 {
		return CheckResult{}, fmt.Errorf("host.exec: cmd required")
	}
	return CheckResult{Diff: fmt.Sprintf("run: %v (destructive, approval required)", cmd)}, nil
}
func (a hostExec) Apply(p Params) (CheckResult, error) {
	cmd := p.GetList("cmd")
	if len(cmd) == 0 {
		return CheckResult{}, fmt.Errorf("host.exec: cmd required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(p.GetInt("timeout", 30)) * time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	err := c.Run()
	detail := truncate(out.String(), execOutputCap)
	if ctx.Err() == context.DeadlineExceeded {
		return CheckResult{Diff: truncate(out.String(), execOutputCap)}, fmt.Errorf("host.exec: timeout after %ds", p.GetInt("timeout", 30))
	}
	if err != nil {
		return CheckResult{After: []byte(detail)}, fmt.Errorf("host.exec: %v\n%s", err, detail)
	}
	return CheckResult{Done: true, After: []byte(detail)}, nil
}
func (a hostExec) Verify(p Params) (CheckResult, error) {
	return CheckResult{Done: true, Diff: "no post-verify for host.exec"}, nil
}
func (a hostExec) Rollback(_ Params, _ []byte) (CheckResult, error) {
	return CheckResult{Done: true, Diff: "host.exec has no automatic rollback"}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + fmt.Sprintf("\n[truncated %d bytes]", len(s)-n)
}

// ---- health.check ------------------------------------------------------------------

// health.check probes a service endpoint. In a hardening plan it is the
// tripwire: if the check goes red, the plan's on_failure path rolls back.

type healthCheck struct{}

func (healthCheck) Name() string   { return "health.check" }
func (healthCheck) Risk() Risk     { return RiskNone }
func (healthCheck) Locks() []string { return nil }

func (a healthCheck) probe(p Params) (CheckResult, error) {
	target := p.Get("target", "")
	want := p.GetInt("expect_status", http.StatusOK)
	client := &http.Client{Timeout: time.Duration(p.GetInt("timeout", 5)) * time.Second}
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return CheckResult{Diff: fmt.Sprintf("bad target %s", target)}, nil
	}
	if method := p.Get("method", "GET"); method != "GET" {
		req.Method = method
	}
	resp, err := client.Do(req)
	if err != nil {
		return CheckResult{Diff: fmt.Sprintf("%s unreachable: %v", target, err)}, nil
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != want {
		return CheckResult{Diff: fmt.Sprintf("%s: status %d (want %d)", target, resp.StatusCode, want)}, nil
	}
	return CheckResult{Done: true, Diff: fmt.Sprintf("%s: %d", target, resp.StatusCode)}, nil
}

func (a healthCheck) Check(p Params) (CheckResult, error)   { return a.probe(p) }
func (a healthCheck) Apply(p Params) (CheckResult, error)   { return a.probe(p) }
func (a healthCheck) Verify(p Params) (CheckResult, error)  { return a.probe(p) }
func (a healthCheck) Rollback(_ Params, _ []byte) (CheckResult, error) {
	return CheckResult{Done: true}, nil
}

// ---- agent.* ------------------------------------------------------------------------

// AgentStateDir is where agent-local action state lives.
var AgentStateDir = "/var/lib/phylax/agent"

// agent.safe_mode toggles the agent's safe-mode flag. It persists across
// restarts (flag file) and is reported in heartbeats.

type agentSafeMode struct{}

func (agentSafeMode) Name() string   { return "agent.safe_mode" }
func (agentSafeMode) Risk() Risk     { return RiskService }
func (agentSafeMode) Locks() []string { return nil }

func safeModeFlagPath() string { return filepath.Join(AgentStateDir, "safe_mode") }

func (a agentSafeMode) Check(p Params) (CheckResult, error) {
	want := p.GetBool("on", true)
	cur := readBoolFlag(safeModeFlagPath())
	if cur == want {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Diff: fmt.Sprintf("safe mode %v -> %v", cur, want)}, nil
}
func (a agentSafeMode) Apply(p Params) (CheckResult, error) {
	want := p.GetBool("on", true)
	v := "0"
	if want {
		v = "1"
	}
	if err := os.MkdirAll(AgentStateDir, 0o700); err != nil {
		return CheckResult{}, err
	}
	if err := os.WriteFile(safeModeFlagPath(), []byte(v), 0o600); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Done: true, Diff: fmt.Sprintf("safe mode %v", want)}, nil
}
func (a agentSafeMode) Verify(p Params) (CheckResult, error) {
	if readBoolFlag(safeModeFlagPath()) != p.GetBool("on", true) {
		return CheckResult{Diff: "safe mode state mismatch"}, nil
	}
	return CheckResult{Done: true}, nil
}
func (a agentSafeMode) Rollback(_ Params, _ []byte) (CheckResult, error) {
	return CheckResult{Done: true}, nil
}

func readBoolFlag(path string) bool {
	b, err := os.ReadFile(path)
	return err == nil && string(b) == "1"
}

// agent.config sets a key in the agent's local config file.

type agentConfig struct{}

func (agentConfig) Name() string   { return "agent.config" }
func (agentConfig) Risk() Risk     { return RiskService }
func (agentConfig) Locks() []string { return nil }

func agentConfigPath() string { return filepath.Join(AgentStateDir, "config.json") }

func readAgentConfig() map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile(agentConfigPath())
	if err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func (a agentConfig) Check(p Params) (CheckResult, error) {
	key, value := p.Get("key", ""), p.Get("value", "")
	if cur, ok := readAgentConfig()[key]; ok && cur == value {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Diff: fmt.Sprintf("config %s = %s", key, value)}, nil
}
func (a agentConfig) Apply(p Params) (CheckResult, error) {
	key, value := p.Get("key", ""), p.Get("value", "")
	if err := os.MkdirAll(AgentStateDir, 0o700); err != nil {
		return CheckResult{}, err
	}
	m := readAgentConfig()
	before, _ := json.Marshal(m)
	m[key] = value
	after, _ := json.Marshal(m)
	if err := os.WriteFile(agentConfigPath(), after, 0o600); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Before: before, After: after}, nil
}
func (a agentConfig) Verify(p Params) (CheckResult, error) {
	if readAgentConfig()[p.Get("key", "")] != p.Get("value", "") {
		return CheckResult{Diff: "config value mismatch"}, nil
	}
	return CheckResult{Done: true}, nil
}
func (a agentConfig) Rollback(_ Params, before []byte) (CheckResult, error) {
	if len(before) == 0 {
		return CheckResult{Done: true}, nil
	}
	if err := os.WriteFile(agentConfigPath(), before, 0o600); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Done: true, Diff: "previous config restored"}, nil
}

// agent.set_controller records a new controller address in the agent's
// bundle. It takes effect on the next agent restart (the agent re-reads
// the bundle at boot); the plan node's diff says so.

type agentSetController struct{}

func (agentSetController) Name() string   { return "agent.set_controller" }
func (agentSetController) Risk() Risk     { return RiskLockout }
func (agentSetController) Locks() []string { return nil }

func agentBundlePath() string { return filepath.Join(AgentStateDir, "bootstrap.json") }

func (a agentSetController) Check(p Params) (CheckResult, error) {
	addr := p.Get("address", "")
	b, err := os.ReadFile(agentBundlePath())
	if err != nil {
		return CheckResult{Diff: fmt.Sprintf("set controller %s (bundle missing)", addr)}, nil
	}
	var bundle struct {
		Controller string `json:"controller"`
	}
	_ = json.Unmarshal(b, &bundle)
	if bundle.Controller == addr {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Diff: fmt.Sprintf("controller %s -> %s (takes effect on restart)", bundle.Controller, addr),
		Before: b}, nil
}
func (a agentSetController) Apply(p Params) (CheckResult, error) {
	addr := p.Get("address", "")
	b, err := os.ReadFile(agentBundlePath())
	if err != nil {
		return CheckResult{}, fmt.Errorf("bundle missing: %w", err)
	}
	var bundle map[string]any
	if err := json.Unmarshal(b, &bundle); err != nil {
		return CheckResult{}, err
	}
	before, _ := json.Marshal(bundle)
	bundle["controller"] = addr
	after, _ := json.Marshal(bundle)
	if err := os.WriteFile(agentBundlePath(), after, 0o600); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Before: before, After: after, Done: true,
		Diff: fmt.Sprintf("controller set to %s (takes effect on restart)", addr)}, nil
}
func (a agentSetController) Verify(p Params) (CheckResult, error) {
	b, err := os.ReadFile(agentBundlePath())
	if err != nil {
		return CheckResult{Diff: "bundle missing"}, nil
	}
	var bundle struct {
		Controller string `json:"controller"`
	}
	_ = json.Unmarshal(b, &bundle)
	if bundle.Controller != p.Get("address", "") {
		return CheckResult{Diff: "controller address mismatch"}, nil
	}
	return CheckResult{Done: true}, nil
}
func (a agentSetController) Rollback(_ Params, before []byte) (CheckResult, error) {
	if len(before) == 0 {
		return CheckResult{Done: true}, nil
	}
	if err := os.WriteFile(agentBundlePath(), before, 0o600); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Done: true, Diff: "previous controller address restored"}, nil
}

// agent.replace_binary stages a new agent binary and flags the running
// agent to swap on its next clean reconnect.

type agentReplaceBinary struct{}

func (agentReplaceBinary) Name() string   { return "agent.replace_binary" }
func (agentReplaceBinary) Risk() Risk     { return RiskLockout }
func (agentReplaceBinary) Locks() []string { return nil }

func stagedBinaryPath() string { return filepath.Join(AgentStateDir, "phylax.new") }

func (a agentReplaceBinary) Check(p Params) (CheckResult, error) {
	if _, err := os.Stat(stagedBinaryPath()); err == nil {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Diff: "stage new agent binary"}, nil
}
func (a agentReplaceBinary) Apply(p Params) (CheckResult, error) {
	// The binary arrives via the bulk-transfer path (TypFetch chunks) and
	// is written by the agent's fetch handler; this node verifies the
	// staged file's hash.
	want := p.Get("sha256", "")
	b, err := os.ReadFile(stagedBinaryPath())
	if err != nil {
		return CheckResult{}, fmt.Errorf("staged binary missing: %w", err)
	}
	if want != "" && fullSHA(b) != want {
		return CheckResult{}, fmt.Errorf("staged binary hash mismatch")
	}
	return CheckResult{Done: true, Diff: fmt.Sprintf("staged %d bytes", len(b))}, nil
}
func (a agentReplaceBinary) Verify(p Params) (CheckResult, error) {
	if _, err := os.Stat(stagedBinaryPath()); err != nil {
		return CheckResult{Diff: "staged binary missing"}, nil
	}
	return CheckResult{Done: true}, nil
}
func (a agentReplaceBinary) Rollback(_ Params, _ []byte) (CheckResult, error) {
	_ = os.Remove(stagedBinaryPath())
	return CheckResult{Done: true, Diff: "staged binary removed"}, nil
}

