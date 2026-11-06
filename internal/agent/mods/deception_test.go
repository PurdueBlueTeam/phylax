package mods

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/decoys"
	"github.com/PurdueBlueTeam/phylax/internal/event"
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

func signedCfg(d *plan.DeceptionSettings) *plan.AgentConfig {
	d.Enabled = true
	return &plan.AgentConfig{Roles: []string{"decoys"}, Modules: plan.ModuleSettings{Deception: d}}
}

// The signed section is the configuration; the unsigned file is only the
// migration fallback and is ignored when a section exists.
func TestSignedDeceptionSectionWinsOverFile(t *testing.T) {
	env := writeDeception(t, `{"listeners":[{"kind":"redis","port":6390}]}`) // would be accepted
	cfg := signedCfg(&plan.DeceptionSettings{Listeners: []plan.DecoyListenerSettings{{Kind: "ssh", Port: 22}}, ScoredPorts: []uint16{22}})
	if _, err := buildDecoys(env, cfg); !errors.Is(err, decoys.ErrScoredPort) {
		t.Fatalf("the signed section was not used: %v", err)
	}
	// No section, no file: unavailable. No section, file: used (migration).
	if _, err := buildDecoys(agent.Env{StateDir: t.TempDir()}, &plan.AgentConfig{Roles: []string{"decoys"}}); !errors.Is(err, agent.ErrUnavailable) {
		t.Errorf("nothing configured: %v", err)
	}
	if _, err := buildDecoys(env, &plan.AgentConfig{Roles: []string{"decoys"}}); err != nil {
		t.Errorf("legacy fallback broke: %v", err)
	}
}

// The controller names the decoys' own ports in the net service map; that must
// not make the agent refuse them as "declared service" ports.
func TestDecoyOwnPortsAreNotDeclaredServices(t *testing.T) {
	cfg := signedCfg(&plan.DeceptionSettings{Listeners: []plan.DecoyListenerSettings{{Kind: "redis", Port: 6390}}})
	cfg.Modules.Net = &plan.NetSettings{Services: map[string]string{"tcp/6390": "decoy-redis", "tcp/80": "web"}}
	if got := declaredPorts(cfg); len(got) != 1 || got[0] != 80 {
		t.Fatalf("declared ports %v", got)
	}
	cfg.Modules.Net.Services["tcp/6390"] = "web" // a real service there: refused
	if _, err := buildDecoys(agent.Env{StateDir: t.TempDir()}, cfg); !errors.Is(err, decoys.ErrScoredPort) {
		t.Fatalf("err = %v", err)
	}
}

func TestSectionFingerprintFollowsTheTokens(t *testing.T) {
	a := signedCfg(&plan.DeceptionSettings{Tokens: []plan.HoneyToken{{ID: "ht-1", Host: "h", Kind: "db_cred"}}})
	b := signedCfg(&plan.DeceptionSettings{Tokens: []plan.HoneyToken{{ID: "ht-1", Host: "h", Kind: "db_cred"}, {ID: "ht-2", Host: "h", Kind: "db_cred"}}})
	fa, ok := decoysSection(a)
	fb, _ := decoysSection(b)
	if !ok || fa == fb {
		t.Error("a new token must restart the decoys")
	}
	if _, ok := decoysSection(&plan.AgentConfig{Roles: []string{"web"}}); ok {
		t.Error("decoys enabled without the role")
	}
}

// The factory's module, run for real: a child process serves, the signed
// token is recognised across the process boundary, the SSH host key persists
// in the state dir.
func TestSandboxedDecoysFromSignedConfig(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the sandboxed child is Linux only")
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	state := t.TempDir()
	cfg := signedCfg(&plan.DeceptionSettings{Bind: "127.0.0.1", SandboxUser: "-",
		Listeners: []plan.DecoyListenerSettings{{Kind: "redis", Port: port}, {Kind: "ssh", Port: port + 1}},
		Tokens:    []plan.HoneyToken{{ID: "ht-9", Host: "ubuntu-email", Kind: "db_cred", User: "svc_x1", Secret: "Maple!Vault42"}}})
	spec, err := buildDecoys(agent.Env{Host: "rocky-ecom", StateDir: state}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(state, "decoy_ssh_host_ed25519")); err != nil {
		t.Errorf("host key not persisted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan event.Event, 16)
	done := make(chan error, 1)
	go func() {
		done <- spec.Module.Start(ctx, func(e event.Event) error {
			select {
			case got <- e:
			default:
			}
			return nil
		})
	}()
	var c net.Conn
	for i := 0; i < 200 && c == nil; i++ {
		select {
		case err := <-done:
			// Surface why the child stopped instead of only "never listened".
			t.Fatalf("decoy module stopped before listening: %v", err)
		default:
		}
		if cc, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
			c = cc
		} else {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if c == nil {
		t.Fatal("decoy never listened")
	}
	fmt.Fprintf(c, "AUTH Maple!Vault42\r\n")
	c.Close()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case e := <-got:
			if e.Fields["honeytoken"] == "ht-9" && e.Fields["token_origin"] == "ubuntu-email" {
				cancel()
				<-done
				return
			}
		case <-deadline:
			t.Fatal("no honeytoken hit from the sandboxed decoy")
		}
	}
}
