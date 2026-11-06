package enroll

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

// fakeWinRM is the network edge for the pusher: enough NTLM to let the real
// client authenticate, and a scripted shell responder. It is not the code
// under test.
type fakeWinRM struct {
	mu       sync.Mutex
	accept   bool // accept AUTHENTICATE; false is a wrong password
	hostname string
	scripts  []string
	stdout   string
	stderr   string
	exit     int
	authed   map[string]bool
	onScript func(string)
}

func (f *fakeWinRM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	auth := r.Header.Get("Authorization")
	if !f.authed[r.RemoteAddr] {
		if auth == "" {
			w.Header().Set("WWW-Authenticate", "Negotiate")
			w.Header().Add("WWW-Authenticate", "NTLM")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		raw, _ := base64.StdEncoding.DecodeString(strings.Fields(auth)[1])
		switch binary.LittleEndian.Uint32(raw[8:]) {
		case 1:
			w.Header().Set("WWW-Authenticate", "Negotiate "+base64.StdEncoding.EncodeToString(fakeNTLMChallenge()))
			w.WriteHeader(http.StatusUnauthorized)
			return
		case 3:
			if !f.accept {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			f.authed[r.RemoteAddr] = true
		}
	}
	w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
	switch fakeAction(body) {
	case "Create":
		io.WriteString(w, `<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SHELL-1</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>`)
	case "Command":
		if m := regexp.MustCompile(`-EncodedCommand</rsp:Arguments><rsp:Arguments>([^<]+)<`).FindSubmatch(body); m != nil {
			raw, _ := base64.StdEncoding.DecodeString(string(m[1]))
			script := fakeFromUTF16LE(raw)
			f.scripts = append(f.scripts, script)
			if f.onScript != nil {
				f.onScript(script)
			}
		}
		io.WriteString(w, `<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>CMD-1</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>`)
	case "Receive":
		out := f.stdout
		if n := len(f.scripts); n > 0 && strings.Contains(f.scripts[n-1], "COMPUTERNAME") {
			out = f.hostname + "\r\n"
		}
		se := ""
		if f.stderr != "" {
			se = `<rsp:Stream Name="stderr" CommandId="CMD-1">` + base64.StdEncoding.EncodeToString([]byte(f.stderr)) + `</rsp:Stream>`
		}
		io.WriteString(w, `<s:Envelope><s:Body><rsp:ReceiveResponse><rsp:Stream Name="stdout" CommandId="CMD-1">`+
			base64.StdEncoding.EncodeToString([]byte(out))+`</rsp:Stream>`+se+
			`<rsp:CommandState CommandId="CMD-1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>`+
			strconv.Itoa(f.exit)+`</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse></s:Body></s:Envelope>`)
	default:
		io.WriteString(w, `<s:Envelope><s:Body/></s:Envelope>`)
	}
}

func fakeAction(body []byte) string {
	m := regexp.MustCompile(`Action[^>]*>([^<]+)<`).FindSubmatch(body)
	if m == nil {
		return ""
	}
	s := string(m[1])
	return s[strings.LastIndex(s, "/")+1:]
}

// fakeNTLMChallenge is a minimal type-2 message the real client can answer:
// Unicode, no target or target-info bytes.
func fakeNTLMChallenge() []byte {
	out := make([]byte, 56)
	copy(out, []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(out[8:], 2)
	binary.LittleEndian.PutUint32(out[20:], 1) // NTLMSSP_NEGOTIATE_UNICODE
	copy(out[24:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	binary.LittleEndian.PutUint32(out[44:], 56)
	return out
}

func fakeFromUTF16LE(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	r := make([]rune, len(u))
	for i, c := range u {
		r[i] = rune(c)
	}
	return string(r)
}

func openFakeWinRM(t *testing.T, f *fakeWinRM) (string, int) {
	t.Helper()
	if f.authed == nil {
		f.authed = map[string]bool{}
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return host, n
}

func winRMTarget(addr string, port int) WinRMTarget {
	return WinRMTarget{
		Target: Target{Host: "h1", Addr: addr, User: "admin", Pass: vault.NewSecretString("pw"), Hostname: "h1"},
		Port:   port,
	}
}

func tokenFromWindowsScript(t *testing.T, script string) string {
	t.Helper()
	i := strings.Index(script, "/w/")
	if i < 0 {
		t.Fatalf("not a Windows install script: %q", script)
	}
	rest := script[i+len("/w/"):]
	j := strings.IndexAny(rest, " '\")")
	if j < 0 {
		j = len(rest)
	}
	return rest[:j]
}

func TestWinRMPushRunsInstallScript(t *testing.T) {
	f := newPushEnroller(t)
	var connected atomic.Bool
	srv := &fakeWinRM{accept: true, hostname: "h1"}
	srv.onScript = func(script string) {
		if strings.Contains(script, "/w/") {
			connected.Store(true)
		}
	}
	host, port := openFakeWinRM(t, srv)
	f.e.opt.Connected = func(h string) bool { return h == "h1" && connected.Load() }
	p := &WinRMPusher{Controller: "10.0.0.5:7443", Timeout: 5 * time.Second}
	if err := p.Push(context.Background(), f.e, winRMTarget(host, port)); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if !connected.Load() {
		t.Fatal("the fake never ran the install script")
	}
	srv.mu.Lock()
	scripts := append([]string(nil), srv.scripts...)
	srv.mu.Unlock()
	if len(scripts) != 2 {
		t.Fatalf("scripts = %q, want COMPUTERNAME then the one-liner script", scripts)
	}
	tok := tokenFromWindowsScript(t, scripts[1])
	if host, err := f.e.Tokens().Peek(tok); err != nil || host != "h1" {
		t.Fatalf("the install token: host %q, err %v; want the live h1 token", host, err)
	}
	if !strings.Contains(scripts[1], "https://10.0.0.5:7443/w/"+tok) {
		t.Fatalf("install script has no pinned download URL: %q", scripts[1])
	}
	sum := sha1.Sum(f.id.Cert.Certificate[0])
	thumb := strings.ToUpper(hex.EncodeToString(sum[:]))
	if !strings.Contains(scripts[1], thumb) {
		t.Fatalf("install script has no certificate thumbprint %s: %q", thumb, scripts[1])
	}
}

func TestWinRMPushHostnameMismatch(t *testing.T) {
	f := newPushEnroller(t)
	srv := &fakeWinRM{accept: true, hostname: "OTHER"}
	host, port := openFakeWinRM(t, srv)
	p := &WinRMPusher{Controller: "10.0.0.5:7443", Timeout: 5 * time.Second}
	err := p.Push(context.Background(), f.e, winRMTarget(host, port))
	var pe *PushError
	if !errors.As(err, &pe) || pe.Class != ClassHostname {
		t.Fatalf("err = %v, want class %s", err, ClassHostname)
	}
	srv.mu.Lock()
	n := len(srv.scripts)
	srv.mu.Unlock()
	if n != 1 {
		t.Fatalf("the mismatched host ran %d scripts, want only the hostname check", n)
	}
	if n := f.e.tokens.liveLocked(); n != 0 {
		t.Fatalf("a mismatched hostname minted %d token(s)", n)
	}
}

func TestWinRMPushClasses(t *testing.T) {
	t.Run("auth_refused", func(t *testing.T) {
		f := newPushEnroller(t)
		srv := &fakeWinRM{accept: false, hostname: "h1"}
		host, port := openFakeWinRM(t, srv)
		p := &WinRMPusher{Controller: "10.0.0.5:7443", Timeout: time.Second}
		err := p.Push(context.Background(), f.e, winRMTarget(host, port))
		var pe *PushError
		if !errors.As(err, &pe) || pe.Class != ClassAuth {
			t.Fatalf("err = %v, want class %s", err, ClassAuth)
		}
	})

	t.Run("winrm_unreachable", func(t *testing.T) {
		f := newPushEnroller(t)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		p := &WinRMPusher{Controller: "10.0.0.5:7443", Timeout: time.Second}
		err = p.Push(context.Background(), f.e, winRMTarget("127.0.0.1", port))
		var pe *PushError
		if !errors.As(err, &pe) || pe.Class != ClassWinRMUnreachable {
			t.Fatalf("err = %v, want class %s", err, ClassWinRMUnreachable)
		}
		if !strings.Contains(pe.Next(), "console one-liner") {
			t.Fatalf("next step = %q, want it to name the console one-liner", pe.Next())
		}
	})

	t.Run("no_heartbeat", func(t *testing.T) {
		f := newPushEnroller(t)
		srv := &fakeWinRM{accept: true, hostname: "h1"}
		host, port := openFakeWinRM(t, srv)
		f.e.opt.Connected = func(string) bool { return false }
		p := &WinRMPusher{Controller: "10.0.0.5:7443", Timeout: 200 * time.Millisecond}
		err := p.Push(context.Background(), f.e, winRMTarget(host, port))
		var pe *PushError
		if !errors.As(err, &pe) || pe.Class != ClassNoHeartbeat {
			t.Fatalf("err = %v, want class %s", err, ClassNoHeartbeat)
		}
	})
}
