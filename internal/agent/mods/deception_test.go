package mods

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/decoys"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func writeDeception(t *testing.T, body string) agent.Env {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, DeceptionFile), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return agent.Env{Host: "rocky-ecom", StateDir: dir}
}

func TestDecoyFactoryRefusesScoredAndDeclaredPorts(t *testing.T) {
	cfg := &plan.AgentConfig{Roles: []string{"decoys"}, Modules: plan.ModuleSettings{
		Net: &plan.NetSettings{Services: map[string]string{"tcp/80": "httpd", "tcp/3306": "mysql"}}}}
	// declared by the net module's service map
	_, err := buildDecoys(writeDeception(t, `{"listeners":[{"kind":"mysql","port":3306}]}`), cfg)
	if !errors.Is(err, decoys.ErrScoredPort) {
		t.Errorf("declared service port: err = %v", err)
	}
	// scored per the deception config
	_, err = buildDecoys(writeDeception(t, `{"listeners":[{"kind":"ssh","port":22}],"scored_ports":[22]}`), cfg)
	if !errors.Is(err, decoys.ErrScoredPort) {
		t.Errorf("scored port: err = %v", err)
	}
	if _, err := buildDecoys(writeDeception(t, `{"listeners":[{"kind":"redis","port":6390}],"scored_ports":[22]}`), cfg); err != nil {
		t.Errorf("clean config refused: %v", err)
	}
	// no config: unavailable, not a crash loop
	if _, err := buildDecoys(agent.Env{StateDir: t.TempDir()}, cfg); !errors.Is(err, agent.ErrUnavailable) {
		t.Errorf("missing config: err = %v", err)
	}
}

func TestDeceptionRoleGate(t *testing.T) {
	if hasDecoyRole(&plan.AgentConfig{Roles: []string{"capture"}}) || !hasDecoyRole(&plan.AgentConfig{Roles: []string{"capture", "decoys"}}) {
		t.Error("role gate wrong")
	}
}
