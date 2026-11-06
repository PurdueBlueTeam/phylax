package mods

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
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

// freePorts reserves n distinct loopback ports and releases them. A port can
// be taken by another process before the decoy child binds it, so the caller
// must treat a bind failure as a lost race, not as a defect.
func freePorts(t *testing.T, n int) []uint16 {
	t.Helper()
	lns := make([]net.Listener, 0, n)
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		lns = append(lns, ln)
	}
	ports := make([]uint16, n)
	for i, ln := range lns {
		ports[i] = uint16(ln.Addr().(*net.TCPAddr).Port)
		ln.Close()
	}
	return ports
}

// runDecoySession runs the module until the signed token is used against the
// redis decoy. It returns the module's own error when it stopped first, so the
// caller can tell a port collision (retry) from a real failure.
func runDecoySession(t *testing.T, spec agent.ModuleSpec, port uint16) error {
	t.Helper()
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
	// The child reports when every listener is bound; a port that was taken
	// after the probe fails the parent's bind first and surfaces on done.
	rm, ok := spec.Module.(interface{ Ready() <-chan struct{} })
	if !ok {
		t.Fatalf("decoy module has no Ready: %T", spec.Module)
	}
	select {
	case <-rm.Ready():
	case err := <-done:
		if err == nil {
			return errors.New("decoy module stopped before serving")
		}
		return err
	case <-time.After(30 * time.Second):
		cancel()
		<-done
		return errors.New("decoy never became ready")
	}
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		cancel()
		<-done
		return fmt.Errorf("decoy never listened: %w", err)
	}
	fmt.Fprintf(c, "AUTH Maple!Vault42\r\n")
	c.Close()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case e := <-got:
			if e.Fields["honeytoken"] == "ht-9" && e.Fields["token_origin"] == "ubuntu-email" {
				cancel()
				if err := <-done; err != nil {
					return fmt.Errorf("decoy module stopped: %w", err)
				}
				return nil
			}
		case <-deadline:
			cancel()
			<-done
			return errors.New("no honeytoken hit from the sandboxed decoy")
		}
	}
}

// The factory's module, run for real: a child process serves, the signed
// token is recognised across the process boundary, the SSH host key persists
// in the state dir.
func TestSandboxedDecoysFromSignedConfig(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the sandboxed child is Linux only")
	}
	state := t.TempDir()
	// The ports are probed and released before the decoy child binds them, so a
	// parallel test can take one in between. That is a lost race, not a defect:
	// start again on a fresh pair, bounded.
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		ports := freePorts(t, 2)
		cfg := signedCfg(&plan.DeceptionSettings{Bind: "127.0.0.1", SandboxUser: "-",
			Listeners: []plan.DecoyListenerSettings{{Kind: "redis", Port: ports[0]}, {Kind: "ssh", Port: ports[1]}},
			Tokens:    []plan.HoneyToken{{ID: "ht-9", Host: "ubuntu-email", Kind: "db_cred", User: "svc_x1", Secret: "Maple!Vault42"}}})
		spec, err := buildDecoys(agent.Env{Host: "rocky-ecom", StateDir: state}, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(state, "decoy_ssh_host_ed25519")); err != nil {
			t.Errorf("host key not persisted: %v", err)
		}
		err = runDecoySession(t, spec, ports[0])
		if err == nil {
			return
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatal(err)
		}
		lastErr = err
	}
	t.Fatalf("decoy ports were taken on every attempt: %v", lastErr)
}
