//go:build linux

package netmod

import (
	"context"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	dockerDeniedAddr = "192.0.2.1" // TEST-NET-1, never routed
	dockerDeniedPort = 9999
	dockerGroup      = 5
)

// TestDockerNFLog runs the real NFLOG path in a throwaway container: no
// --privileged, no host network, only CAP_NET_ADMIN added. The container installs an
// iptables NFLOG+DROP rule inside its own network namespace, then runs
// TestInContainerEgress from a static test binary. Enable with PHYLAX_NET_DOCKER=1.
func TestDockerNFLog(t *testing.T) {
	if os.Getenv("PHYLAX_NET_DOCKER") != "1" {
		t.Skip("set PHYLAX_NET_DOCKER=1 to run the Docker NFLOG test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "net.test")
	build := exec.Command("go", "test", "-c", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build test binary: %v\n%s", err, out)
	}
	script := `set -e
apk add -q --no-progress iptables >/dev/null
iptables -A OUTPUT -p tcp -d ` + dockerDeniedAddr + ` --dport ` + itoa(dockerDeniedPort) + ` -j NFLOG --nflog-group ` + itoa(dockerGroup) + ` --nflog-prefix phylax-deny
iptables -A OUTPUT -p tcp -d ` + dockerDeniedAddr + ` --dport ` + itoa(dockerDeniedPort) + ` -j DROP
exec /t/net.test -test.run '^TestInContainerEgress$' -test.v`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--cap-add", "NET_ADMIN",
		"-e", "PHYLAX_NET_INCONTAINER=1", "-e", "PHYLAX_NET_RECORD=/out/nflog.hex",
		"-v", dir+":/t:ro", "-v", dir+":/out", "alpine:3", "sh", "-c", script)
	out, err := cmd.CombinedOutput()
	t.Logf("container output:\n%s", out)
	if err != nil {
		t.Fatalf("container run failed: %v", err)
	}
	if !strings.Contains(string(out), "--- PASS: TestInContainerEgress") {
		t.Fatal("in-container test did not pass")
	}
	if rec := os.Getenv("PHYLAX_NET_RECORD_TO"); rec != "" {
		b, _ := os.ReadFile(filepath.Join(dir, "nflog.hex"))
		if err := os.WriteFile(rec, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestInContainerEgress is the in-container half; skipped everywhere else.
func TestInContainerEgress(t *testing.T) {
	if os.Getenv("PHYLAX_NET_INCONTAINER") != "1" {
		t.Skip("only runs inside the Docker harness (TestDockerNFLog)")
	}
	r, err := OpenNFLog([]uint16{dockerGroup}, 128)
	if err != nil {
		t.Fatalf("open nflog in container: %v", err)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pkts := make(chan NFLogPacket, 16)
	if rec := os.Getenv("PHYLAX_NET_RECORD"); rec != "" {
		var once sync.Once
		r.Raw = func(b []byte) {
			once.Do(func() { os.WriteFile(rec, []byte(hex.EncodeToString(b)+"\n"), 0o644) })
		}
	}
	go r.Run(ctx, func(p NFLogPacket) {
		select {
		case pkts <- p:
		default:
		}
	})

	eg := NewEgress(EgressConfig{CanaryTargets: []CanaryTarget{{Addr: mustAddr(dockerDeniedAddr), Port: dockerDeniedPort, Tag: "kali-9999"}}},
		SockDiag{}, &ProcFS{HashExe: true})

	// The denied attempt: a connect that never completes while the SYN retries.
	go func() {
		d := net.Dialer{Timeout: 15 * time.Second}
		c, err := d.DialContext(ctx, "tcp", dockerDeniedAddr+":"+itoa(dockerDeniedPort))
		if err == nil {
			c.Close()
		}
	}()

	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case p := <-pkts:
			if p.Prefix != "phylax-deny" || p.Group != dockerGroup {
				t.Fatalf("unexpected packet meta: %+v", p)
			}
			for _, e := range eg.Packet(time.Now(), p) {
				check(t, e.Fields)
				return
			}
		case <-tick.C:
			for _, e := range eg.Tick(time.Now()) {
				check(t, e.Fields)
				return
			}
		case <-ctx.Done():
			t.Fatal("no egress_denied event")
		}
	}
}

func check(t *testing.T, f map[string]any) {
	t.Helper()
	t.Logf("egress_denied: %v", f)
	exe, _ := os.Executable()
	if f["attributed"] != true || f["pid"] != os.Getpid() || f["exe"] != exe || f["exe_sha256"] == "" {
		t.Errorf("not attributed to this process: %v", f)
	}
	if f["raddr"] != dockerDeniedAddr || f["rport"] != dockerDeniedPort || f["proto"] != "tcp" || f["community_id"] == "" {
		t.Errorf("wrong destination: %v", f)
	}
	if f["tag"] != "canary" || f["canary_tag"] != "kali-9999" || f["prefix"] != "phylax-deny" {
		t.Errorf("tags: %v", f)
	}
}
