package probe

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func fakeWinRMServer(t *testing.T, f *fakeWinRM) *httptest.Server {
	t.Helper()
	if f.ntlm == nil {
		f.ntlm = &ntlmServer{users: map[string]string{"admin": "pw"}, targetName: "WIN1"}
	}
	if f.authed == nil {
		f.authed = map[string]bool{}
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return srv
}

func openFakeWinRM(t *testing.T, f *fakeWinRM, user, pass string) (*WinRMShell, *httptest.Server) {
	t.Helper()
	srv := fakeWinRMServer(t, f)
	h, port := hostPort(t, srv.Listener.Addr().String())
	sh, err := OpenWinRM(context.Background(), WinRMConfig{Host: h, Port: port, User: user, Pass: pass})
	if err != nil {
		t.Fatalf("OpenWinRM: %v", err)
	}
	return sh, srv
}

func TestOpenWinRMRunsScript(t *testing.T) {
	f := &fakeWinRM{hostname: "WIN-TEST"}
	sh, _ := openFakeWinRM(t, f, "admin", "pw")
	defer sh.Close(context.Background())
	stdout, stderr, exit, err := sh.Run(context.Background(), "hostname")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stdout != "WIN-TEST\r\n" || stderr != "" || exit != 0 {
		t.Fatalf("Run = %q, %q, %d; want WIN-TEST\\r\\n, empty, 0", stdout, stderr, exit)
	}
	f.mu.Lock()
	cmd := f.cmd
	f.mu.Unlock()
	if cmd != "hostname" {
		t.Fatalf("the server decoded the script as %q, want hostname", cmd)
	}
}

func TestOpenWinRMBadPassword(t *testing.T) {
	f := &fakeWinRM{hostname: "WIN-TEST"}
	srv := fakeWinRMServer(t, f)
	h, port := hostPort(t, srv.Listener.Addr().String())
	_, err := OpenWinRM(context.Background(), WinRMConfig{Host: h, Port: port, User: "admin", Pass: "bad"})
	if !errors.Is(err, ErrWinRMAuth) {
		t.Fatalf("OpenWinRM with a bad password: err = %v, want ErrWinRMAuth", err)
	}
}

func TestWinRMRunNonZeroExit(t *testing.T) {
	f := &fakeWinRM{stdout: "partial", stderr: "boom", exit: 3}
	sh, _ := openFakeWinRM(t, f, "admin", "pw")
	defer sh.Close(context.Background())
	stdout, stderr, exit, err := sh.Run(context.Background(), "fail")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exit != 3 || stderr != "boom" || stdout != "partial" {
		t.Fatalf("Run = %q, %q, %d; want partial, boom, 3", stdout, stderr, exit)
	}
}

func TestWinRMOutputCapped(t *testing.T) {
	f := &fakeWinRM{stdout: strings.Repeat("x", 3<<20)}
	sh, _ := openFakeWinRM(t, f, "admin", "pw")
	defer sh.Close(context.Background())
	stdout, _, _, err := sh.Run(context.Background(), "big")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(stdout) != 1<<20 {
		t.Fatalf("stdout length = %d, want %d", len(stdout), 1<<20)
	}
}

func TestWinRMCloseDeletesShell(t *testing.T) {
	f := &fakeWinRM{hostname: "WIN-TEST"}
	sh, _ := openFakeWinRM(t, f, "admin", "pw")
	if err := sh.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	f.mu.Lock()
	deleted := append([]string(nil), f.deleted...)
	f.mu.Unlock()
	if len(deleted) != 1 || deleted[0] != "SHELL-1" {
		t.Fatalf("deleted shells = %v, want SHELL-1", deleted)
	}
}
