package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/controller"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

// writeBundleFile writes a bootstrap file the agent's ParseBundle accepts.
func writeBundleFile(t *testing.T, path string, b agent.Bundle) {
	t.Helper()
	if b.Controllers == nil {
		b.Controllers = []string{"127.0.0.1:7443"}
	}
	b.ControllerPin = link.Pin{}.String()
	b.Host = "h1"
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAdoptBootstrapSafe(t *testing.T) {
	t.Run("safe", func(t *testing.T) {
		dir := t.TempDir()
		l := agent.Layout{Root: filepath.Join(dir, "state")}
		path := filepath.Join(dir, "h1.json")
		writeBundleFile(t, path, agent.Bundle{Safe: true})
		if err := adoptBootstrap(l, path); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(l.SafeModeFile()); err != nil {
			t.Fatalf("safe mode marker: %v", err)
		}
		sm, err := actions.NewSafeMode(l.SafeModeFile())
		if err != nil {
			t.Fatal(err)
		}
		if !sm.On() {
			t.Fatal("safe mode is off after adopting a safe bundle")
		}
		if _, err := os.Stat(l.Bootstrap()); err != nil {
			t.Fatalf("bootstrap not saved: %v", err)
		}
	})
	t.Run("not safe", func(t *testing.T) {
		dir := t.TempDir()
		l := agent.Layout{Root: filepath.Join(dir, "state")}
		path := filepath.Join(dir, "h1.json")
		writeBundleFile(t, path, agent.Bundle{})
		if err := adoptBootstrap(l, path); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(l.SafeModeFile()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("safe mode marker with safe=false: %v", err)
		}
		b, err := l.LoadBundle()
		if err != nil {
			t.Fatal(err)
		}
		if b.Safe {
			t.Fatal("saved bundle has Safe set")
		}
	})
}

func TestWriteBundlesForManifest(t *testing.T) {
	m, err := manifest.LoadDir(ref2027, manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := controller.Config{DataDir: t.TempDir()}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	c, err := controller.New(context.Background(), cfg, controller.Options{
		HostKnown: func(h string) bool { _, ok := m.Hosts[h]; return ok },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	dir := filepath.Join(t.TempDir(), "bundles")
	if err := writeBundles(c, m, dir, "172.20.240.5:7443", time.Hour, true); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != len(m.Hosts) || len(m.Hosts) != 8 {
		t.Fatalf("%d bundle files for %d manifest hosts, want 8", len(ents), len(m.Hosts))
	}
	seen := map[string]bool{}
	for _, e := range ents {
		host := strings.TrimSuffix(e.Name(), ".json")
		if _, ok := m.Hosts[host]; !ok {
			t.Fatalf("bundle for unknown host %q", host)
		}
		seen[host] = true
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		b, err := agent.ParseBundle(data)
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if b.Host != host {
			t.Errorf("%s: Host %q", e.Name(), b.Host)
		}
		if !b.Safe {
			t.Errorf("%s: Safe is false", e.Name())
		}
		if b.Token == "" {
			t.Errorf("%s: empty token", e.Name())
		}
		if len(b.Controllers) != 1 || b.Controllers[0] != "172.20.240.5:7443" {
			t.Errorf("%s: Controllers %v", e.Name(), b.Controllers)
		}
	}
	for h := range m.Hosts {
		if !seen[h] {
			t.Errorf("no bundle for manifest host %s", h)
		}
	}
}

func TestServeBundlesNeedsAdvertise(t *testing.T) {
	tmp := t.TempDir()
	err := commands["serve"].run(context.Background(), []string{"-data-dir", tmp, "-bundles", filepath.Join(tmp, "bundles")})
	if err == nil || !strings.Contains(err.Error(), "-advertise") {
		t.Fatalf("err = %v, want an error naming -advertise", err)
	}
}

func TestServeEnrollWindowFlags(t *testing.T) {
	tmp := t.TempDir()
	err := commands["serve"].run(context.Background(), []string{"-data-dir", filepath.Join(tmp, "data"), "-served-dir", filepath.Join(tmp, "web")})
	if err == nil || !strings.Contains(err.Error(), "-bundles") {
		t.Fatalf("err = %v, want an error naming -bundles", err)
	}

	// With both flags serve writes the bundles and starts the watch; the
	// window then withdraws them, which proves -enroll-window took effect.
	web := filepath.Join(tmp, "web")
	if err := os.MkdirAll(web, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(web, "phylax"), []byte("served binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(tmp, "controller.json")
	cfgJSON := fmt.Sprintf(`{"data_dir": %q, "manifest_path": %q, "ui_listen": "off", "agent_listen": "127.0.0.1:0"}`,
		filepath.Join(tmp, "ctl"), ref2027)
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	bundles := filepath.Join(tmp, "bundles")
	bundleCount := func() int {
		entries, err := os.ReadDir(bundles)
		if err != nil {
			return 0
		}
		n := 0
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".json") {
				n++
			}
		}
		return n
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- commands["serve"].run(ctx, []string{"-config", cfgPath, "-bundles", bundles,
			"-advertise", "172.20.240.5:7443", "-served-dir", web, "-enroll-window", "2s"})
	}()
	waitCount := func(want int, what string) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for bundleCount() != want {
			if time.Now().After(deadline) {
				t.Fatalf("bundles: %s did not happen (have %d)", what, bundleCount())
			}
			select {
			case err := <-done:
				t.Fatalf("serve stopped before %s: %v", what, err)
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	waitCount(8, "the 8 manifest host bundles")
	waitCount(0, "the enrollment window to withdraw every bundle")
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("serve: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not stop")
	}
}
