package mods

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func TestCaptureIsRoleGatedAndTakesScoredPortsFromTheSignedConfig(t *testing.T) {
	f := captureFactory
	plain := &plan.AgentConfig{Roles: []string{"decoys"}}
	if _, on := f.Section(plain); on {
		t.Fatal("capture runs without the capture role")
	}
	cfg := &plan.AgentConfig{Roles: []string{"capture"}, Modules: plan.ModuleSettings{Net: &plan.NetSettings{
		Services: map[string]string{"tcp/80": "web", "tcp/21": "ftp", "udp/53": "dns", "tcp/9999": "decoy-http"}}}}
	fp1, on := f.Section(cfg)
	if !on {
		t.Fatal("capture role did not enable the module")
	}
	cfg.Modules.Net.Services["tcp/443"] = "tls"
	if fp2, _ := f.Section(cfg); fp1 == fp2 {
		t.Fatal("a changed service map must replace the module")
	}
	if got := scoredPorts(cfg); len(got) != 5 || got[0] != 21 || got[4] != 9999 {
		t.Fatalf("scored ports %v", got)
	}
}

func TestCaptureBuild(t *testing.T) {
	f := captureFactory
	cfg := &plan.AgentConfig{Host: "web1", Roles: []string{"capture"}}
	dir := t.TempDir()
	env := agent.Env{Host: "web1", StateDir: dir}
	if runtime.GOOS != "linux" {
		if _, err := f.Build(env, cfg); !errors.Is(err, agent.ErrUnavailable) {
			t.Fatalf("non-linux build: %v", err)
		}
		return
	}
	sp, err := f.Build(env, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !sp.Subscriber || sp.Module.Name() != "capture" || sp.Rate == 0 {
		t.Fatalf("spec %+v", sp)
	}
	for name, body := range map[string]string{
		CaptureFile: `{"exclude":["not an endpoint"]}`, CaptureSealFile: "zz",
	} {
		d := t.TempDir()
		os.WriteFile(filepath.Join(d, name), []byte(body), 0o600)
		if _, err := f.Build(agent.Env{Host: "web1", StateDir: d}, cfg); err == nil {
			t.Errorf("bad %s accepted", name)
		}
	}
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, CaptureSealFile), []byte("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n"), 0o600)
	os.WriteFile(filepath.Join(d, CaptureFile), []byte(`{"interface":"lo","exclude":["10.0.0.5:8443"],"ring_mb":16}`), 0o600)
	if _, err := f.Build(agent.Env{Host: "web1", StateDir: d}, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestCaptureHeldMB(t *testing.T) {
	dir := t.TempDir()
	if got := CaptureHeldMB(&plan.AgentConfig{Roles: []string{"decoys"}}, dir); got != 0 {
		t.Errorf("without the capture role: %d MB, want 0", got)
	}
	if got := CaptureHeldMB(&plan.AgentConfig{Roles: []string{"capture"}}, dir); got != 512 {
		t.Errorf("capture defaults: %d MB, want 512", got)
	}
	if err := os.WriteFile(filepath.Join(dir, CaptureFile), []byte(`{"ring_mb":16,"hold_mb":8}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := CaptureHeldMB(&plan.AgentConfig{Roles: []string{"capture"}}, dir); got != 24 {
		t.Errorf("configured ring and hold: %d MB, want 24", got)
	}
	if err := os.WriteFile(filepath.Join(dir, CaptureFile), []byte(`{"ring_mb":16}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := CaptureHeldMB(&plan.AgentConfig{Roles: []string{"capture"}}, dir); got != 16+256 {
		t.Errorf("configured ring, default hold: %d MB, want %d", got, 16+256)
	}
	if err := os.WriteFile(filepath.Join(dir, CaptureFile), []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := CaptureHeldMB(&plan.AgentConfig{Roles: []string{"capture"}}, dir); got != 512 {
		t.Errorf("a broken capture file keeps the defaults: %d MB, want 512", got)
	}
}
