package enroll

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	phyagent "github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/link"
)

type bootServer struct {
	addr string
}

// startBoot starts a real link server that dispatches bootstrap connections to
// h (nil means e.Bootstrap).
func startBoot(t *testing.T, e *Enroller, h link.Handler) *bootServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if h == nil {
		h = e.Bootstrap()
	}
	bs := &bootServer{addr: ln.Addr().String()}
	srv, err := link.NewServer(link.ServerOptions{
		Identity:  e.opt.Identity,
		Check:     func(link.Pin) error { return nil },
		Bootstrap: h,
	})
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("bootstrap server did not stop")
		}
	})
	return bs
}

func TestBootstrapRoutes(t *testing.T) {
	const host = "h1"
	f := newEnrollerWith(t, func(o *Options) { o.ReleaseDir = t.TempDir() })
	bin := []byte("#!/bin/sh\necho fake phylax linux binary\n")
	if err := os.WriteFile(filepath.Join(f.e.opt.ReleaseDir, "phylax-linux-amd64"), bin, 0o600); err != nil {
		t.Fatal(err)
	}
	tok, err := f.e.MintToken(host, 0)
	if err != nil {
		t.Fatal(err)
	}
	bs := startBoot(t, f.e, nil)
	client := bootClient()

	body, code := get(t, client, "https://"+bs.addr+"/b/"+tok+"/linux")
	if code != http.StatusOK || string(body) != string(bin) {
		t.Fatalf("GET linux = %d, %d bytes; want 200 and the file", code, len(body))
	}
	sum := sha256.Sum256(bin)
	script, code := get(t, client, "https://"+bs.addr+"/l/"+tok)
	if code != http.StatusOK {
		t.Fatalf("GET script = %d", code)
	}
	if !strings.Contains(string(script), hex.EncodeToString(sum[:])) {
		t.Fatalf("install script does not embed the binary sha256 %x", sum[:])
	}
	boot, code := get(t, client, "https://"+bs.addr+"/b/"+tok+"/boot")
	if code != http.StatusOK {
		t.Fatalf("GET boot = %d", code)
	}
	b, err := phyagent.ParseBundle(boot)
	if err != nil {
		t.Fatalf("boot JSON does not parse: %v\n%s", err, boot)
	}
	if b.Host != host || b.Token != tok {
		t.Fatalf("boot bundle = host %q token %q, want %q and the same token", b.Host, b.Token, host)
	}

	unknown, unknownCode := get(t, client, "https://"+bs.addr+"/l/no-such-token")
	usedTok, _ := f.e.MintToken(host, 0)
	if err := f.e.Tokens().Consume(usedTok, host, link.Pin{1}); err != nil {
		t.Fatal(err)
	}
	used, usedCode := get(t, client, "https://"+bs.addr+"/l/"+usedTok)
	if unknownCode != http.StatusNotFound || usedCode != http.StatusNotFound {
		t.Fatalf("unknown/used token codes = %d/%d, want 404/404", unknownCode, usedCode)
	}
	if string(unknown) != string(used) {
		t.Fatalf("unknown and used token bodies differ: %q vs %q", unknown, used)
	}

	req, _ := http.NewRequest(http.MethodPost, "https://"+bs.addr+"/l/"+tok, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /l = %d, want 405", resp.StatusCode)
	}
	sent, _ := io.ReadAll(resp.Body)
	if len(sent) != 0 {
		t.Fatalf("405 has a body %q", sent)
	}

	// An oversized header block is refused before a 200 is produced.
	raw, err := tls.Dial("tcp", bs.addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	pad := strings.Repeat("a", 9000)
	if _, err := io.WriteString(raw, "GET /l/"+tok+" HTTP/1.1\r\nHost: x\r\nX-Pad: "+pad+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(raw)
	if strings.Contains(string(out), " 200 ") {
		t.Fatalf("an over-8KiB header block got a 200:\n%s", out)
	}
}

func TestBootstrapRateLimitPerRemote(t *testing.T) {
	now := time.Now()
	f := newEnrollerWith(t, func(o *Options) {
		o.ReleaseDir = t.TempDir()
		o.Now = func() time.Time { return now }
	})
	writeReleases(t, f.e.opt.ReleaseDir)
	bs := startBoot(t, f.e, nil)
	client := bootClient()
	for i := 0; i < 21; i++ {
		_, code := get(t, client, "https://"+bs.addr+"/l/bad")
		if i < 20 && code != http.StatusNotFound {
			t.Fatalf("unknown-token request %d = %d, want 404", i+1, code)
		}
		if i == 20 && code != http.StatusTooManyRequests {
			t.Fatalf("21st unknown-token request = %d, want 429", code)
		}
	}
	tok, err := f.e.MintToken("h1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, code := get(t, client, "https://"+bs.addr+"/l/"+tok); code != http.StatusTooManyRequests {
		t.Fatalf("valid token inside the failure window = %d, want 429", code)
	}
	now = now.Add(time.Minute + time.Second)
	if _, code := get(t, client, "https://"+bs.addr+"/l/"+tok); code != http.StatusOK {
		t.Fatalf("valid token after the failure window = %d, want 200", code)
	}
}

func bootClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, MinVersion: tls.VersionTLS12,
		}},
	}
}

func get(t *testing.T, client *http.Client, url string) ([]byte, int) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s body: %v", url, err)
	}
	return body, resp.StatusCode
}
