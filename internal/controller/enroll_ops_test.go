package controller

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/ui"
)

// TestAgentPortServesOnlyAgentsAndBootstrap is the agent-port half of T28: the
// listener speaks only the pinned agent protocol and the bootstrap handler.
// There is no operator surface here and no way to mint a token.
func TestAgentPortServesOnlyAgentsAndBootstrap(t *testing.T) {
	x := newCtl(t)
	tokPath := filepath.Join(x.cfg.DataDir, "tokens.json")
	before, beforeErr := os.ReadFile(tokPath)
	waitFor(t, 5*time.Second, "agent port", func() bool {
		c, err := net.Dial("tcp", x.addr)
		if err == nil {
			c.Close()
		}
		return err == nil
	})

	// A client with no certificate that asks for the agent protocol is refused
	// in the TLS handshake, before it can send a hello.
	conn, err := tls.Dial("tcp", x.addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13,
		NextProtos: []string{link.ALPNAgent}})
	if err == nil {
		// TLS 1.3 lets the client finish before the server's alert arrives; the
		// connection must still be unusable (the server rejected the empty
		// client certificate).
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write([]byte("hello"))
		buf := make([]byte, 1)
		if _, rerr := conn.Read(buf); rerr == nil {
			conn.Close()
			t.Fatal("the agent port accepted a connection without a client certificate")
		}
		conn.Close()
	}

	status := func(method, path string) int {
		t.Helper()
		c, err := tls.Dial("tcp", x.addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatalf("%s %s: dial: %v", method, path, err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(c, "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", method, path)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("%s %s: read: %v", method, path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/", http.StatusNotFound},
		{"GET", "/e", http.StatusNotFound},
		{"GET", "/b/not-a-token", http.StatusNotFound},
		{"POST", "/l/anything", http.StatusMethodNotAllowed},
		{"GET", "/l/anything", http.StatusNotFound}, // a bad token, not a page
	} {
		if got := status(c.method, c.path); got != c.want {
			t.Errorf("%s %s: %d, want %d", c.method, c.path, got, c.want)
		}
	}

	after, afterErr := os.ReadFile(tokPath)
	if (beforeErr == nil) != (afterErr == nil) || !bytes.Equal(before, after) {
		t.Fatal("the agent port changed tokens.json; it must never mint a token")
	}
}

// TestEnrollOpsListAndLine: the page's backend lists the manifest hosts and
// mints a line only for a manifest host with a known OS and an advertised
// controller address.
func TestEnrollOpsListAndLine(t *testing.T) {
	ctx := context.Background()
	rel := t.TempDir()
	for _, n := range []string{"phylax-linux-amd64", "phylax-windows-amd64.exe"} {
		if err := os.WriteFile(filepath.Join(rel, n), []byte("fake release"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	m := realManifest(t)
	cfg := Config{AgentListen: "127.0.0.1:0", DataDir: filepath.Join(t.TempDir(), "data"),
		ManifestPath: "../../manifest/2027", ReleaseDir: rel, Advertise: "ctl.example:7443"}
	c, err := New(ctx, cfg, Options{HostKnown: func(h string) bool { _, ok := m.Hosts[h]; return ok }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	o := &WebOps{c: c}

	rows, err := o.EnrollHosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]ui.EnrollRow{}
	for _, r := range rows {
		got[r.Host] = r
	}
	for host := range m.Hosts {
		r, ok := got[host]
		if !ok || r.State != "not_enrolled" || r.Connected {
			t.Errorf("host %s: %+v (present %v)", host, r, ok)
		}
	}
	if len(rows) != len(m.Hosts) {
		t.Fatalf("%d rows for %d manifest hosts", len(rows), len(m.Hosts))
	}

	line, err := o.EnrollLine(ctx, "rocky-ecom", "linux", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "curl -sk --pinnedpubkey ") || !strings.Contains(line, "https://ctl.example:7443/l/") {
		t.Fatalf("linux line %q", line)
	}
	wline, err := o.EnrollLine(ctx, "ad", "windows", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(wline, `powershell -c "`) || !strings.Contains(wline, "https://ctl.example:7443/w/") {
		t.Fatalf("windows line %q", wline)
	}
	if _, err := o.EnrollLine(ctx, "no-such-host", "linux", "admin"); !errors.Is(err, ui.ErrInvalid) {
		t.Fatalf("unknown host: %v", err)
	}
	if _, err := o.EnrollLine(ctx, "rocky-ecom", "plan9", "admin"); !errors.Is(err, ui.ErrInvalid) {
		t.Fatalf("unknown OS: %v", err)
	}
}
