package decoys

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/honeytokens"
)

type sink struct {
	mu sync.Mutex
	ev []event.Event
}

func (s *sink) emit(e event.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ev = append(s.ev, e)
	return nil
}

func (s *sink) all() []event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]event.Event(nil), s.ev...)
}

// find waits for an event satisfying pred.
func (s *sink) find(t *testing.T, what string, pred func(event.Event) bool) event.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range s.all() {
			if pred(e) {
				return e
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %s event; got %d events: %+v", what, len(s.all()), s.all())
	return event.Event{}
}

func stage(st string) func(event.Event) bool {
	return func(e event.Event) bool { return e.Fields["stage"] == st }
}

type harness struct {
	m   *Module
	s   *sink
	reg *honeytokens.Registry
}

func start(t *testing.T, mut func(*Config), kinds ...string) *harness {
	t.Helper()
	reg := honeytokens.NewRegistry()
	cfg := Config{Host: "web01", Bind: "127.0.0.1", AllowEphemeral: true, Tokens: reg,
		Delay: func() time.Duration { return 0 }, Logger: nil}
	for _, k := range kinds {
		cfg.Listeners = append(cfg.Listeners, Listener{Kind: k})
	}
	if mut != nil {
		mut(&cfg)
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{m: m, s: &sink{}, reg: reg}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Start(ctx, h.s.emit) }()
	select {
	case <-m.Ready():
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("not ready")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("module did not stop")
		}
	})
	return h
}

func (h *harness) dial(t *testing.T, kind string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", h.m.Addr(kind).String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}

func (h *harness) token(t *testing.T, tok honeytokens.Token) honeytokens.Token {
	t.Helper()
	if err := h.reg.Add(tok); err != nil {
		t.Fatal(err)
	}
	return tok
}

// ---- scoring safety ----

func TestRefusesScoredPort(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		{"scored ssh", Config{Listeners: []Listener{{KindSSH, 22}}, ScoredPorts: []uint16{22, 80}}, "scored port"},
		{"scored rdp", Config{Listeners: []Listener{{KindRDP, 3389}}, ScoredPorts: []uint16{3389}}, "scored port"},
		{"one of several", Config{Listeners: []Listener{{KindRedis, 6379}, {KindWinRM, 5985}}, ScoredPorts: []uint16{5985}}, "5985"},
		{"smb port", Config{Listeners: []Listener{{KindSMB, 445}}}, "445"},
		{"duplicate", Config{Listeners: []Listener{{KindRedis, 6379}, {KindMySQL, 6379}}}, "twice"},
		{"unknown kind", Config{Listeners: []Listener{{"gopher", 70}}}, "unknown"},
		{"no port", Config{Listeners: []Listener{{KindSSH, 0}}}, "needs a port"},
	} {
		_, err := New(tc.cfg)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", tc.name, err, tc.want)
		}
	}
	_, err := New(Config{Listeners: []Listener{{KindSSH, 22}}, ScoredPorts: []uint16{22}})
	if !errors.Is(err, ErrScoredPort) {
		t.Errorf("want ErrScoredPort, got %v", err)
	}
	if _, err := New(Config{Listeners: []Listener{{KindSSH, 2222}}, ScoredPorts: []uint16{22}}); err != nil {
		t.Errorf("unscored port refused: %v", err)
	}
}

// ---- SSH ----

func sshClient(t *testing.T, h *harness, user string, auth ...ssh.AuthMethod) (*ssh.Client, error) {
	t.Helper()
	return ssh.Dial("tcp", h.m.Addr(KindSSH).String(), &ssh.ClientConfig{User: user, Auth: auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
}

func TestSSHFakeShellRecordsAndNeverExecutes(t *testing.T) {
	h := start(t, func(c *Config) { c.AcceptAfter = 2 }, KindSSH)
	dir := t.TempDir()
	marker := filepath.Join(dir, "pwned")

	cl, err := sshClient(t, h, "root", ssh.RetryableAuthMethod(ssh.Password("hunter2"), 4))
	if err != nil {
		t.Fatalf("login after a few attempts should succeed: %v", err)
	}
	defer cl.Close()

	// exec request: answered by the fake shell, not run
	sess, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.Output("id; touch " + marker)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !strings.Contains(string(out), "uid=0") {
		t.Errorf("exec output = %q", out)
	}
	// interactive shell
	sess2, _ := cl.NewSession()
	in, _ := sess2.StdinPipe()
	outp, _ := sess2.StdoutPipe()
	if err := sess2.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	if err := sess2.Shell(); err != nil {
		t.Fatal(err)
	}
	io.WriteString(in, "whoami\r"+"echo x > "+marker+"\r"+"exit\r")
	b, _ := io.ReadAll(outp)
	if !strings.Contains(string(b), "root") {
		t.Errorf("shell output = %q", b)
	}
	sess2.Wait()
	cl.Close()

	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a command typed into the decoy created a real file: it executed")
	}
	end := h.s.find(t, "end", func(e event.Event) bool { return e.Fields["stage"] == StageEnd && e.Fields["protocol"] == KindSSH })
	if end.Kind != KindHit || end.Priority != event.PriorityCritical {
		t.Errorf("kind/priority = %s/%v", end.Kind, end.Priority)
	}
	cmds, _ := end.Fields["commands"].([]string)
	joined := strings.Join(cmds, "|")
	for _, want := range []string{"id; touch " + marker, "whoami", "echo x > " + marker} {
		if !strings.Contains(joined, want) {
			t.Errorf("commands %q missing %q", joined, want)
		}
	}
	creds, _ := end.Fields["credentials"].([]Cred)
	if len(creds) < 2 || creds[0].User != "root" || creds[0].Secret != "hunter2" {
		t.Errorf("credentials = %+v", creds)
	}
	if end.Fields["severity"] != SevHigh || end.Fields["source"] != "127.0.0.1" {
		t.Errorf("end fields = %+v", end.Fields)
	}
	h.s.find(t, "connect", stage(StageConnect))
	h.s.find(t, "login", stage(StageLogin))
	h.s.find(t, "command", stage(StageCommand))
}

func TestSSHBadPasswordRejectedUntilThreshold(t *testing.T) {
	h := start(t, func(c *Config) { c.AcceptAfter = 5; c.MaxAuthAttempts = 3 }, KindSSH)
	_, err := sshClient(t, h, "root", ssh.RetryableAuthMethod(ssh.Password("x"), 3))
	if err == nil {
		t.Fatal("login must fail before AcceptAfter attempts")
	}
}

func TestSSHHoneyKeyIsCritical(t *testing.T) {
	h := start(t, nil, KindSSH)
	g := honeytokens.NewGenerator(h.reg)
	plan, err := g.ForHost(honeytokens.HostSpec{Host: "rocky-ecom", Tokens: []honeytokens.TokenDef{{Kind: "ssh_key"}}})
	if err != nil {
		t.Fatal(err)
	}
	pemStr := plan.Actions[0].Params["content"].(string)
	signer, err := ssh.ParsePrivateKey([]byte(pemStr))
	if err != nil {
		t.Fatal(err)
	}
	cl, err := sshClient(t, h, "backup", ssh.PublicKeys(signer))
	if err != nil {
		t.Fatalf("honey key should be accepted so the attacker keeps going: %v", err)
	}
	cl.Close()
	e := h.s.find(t, "critical", func(e event.Event) bool { return e.Fields["severity"] == SevCritical })
	if e.Fields["token_origin"] != "rocky-ecom" || e.Fields["token_kind"] != "ssh_key" || e.Fields["honeytoken"] != plan.Tokens[0].ID {
		t.Errorf("attribution = %+v", e.Fields)
	}
	if e.Fields["key_fingerprint"] != plan.Tokens[0].Fingerprint {
		t.Errorf("fingerprint %v != %v", e.Fields["key_fingerprint"], plan.Tokens[0].Fingerprint)
	}
	n := 0
	for _, ev := range h.s.all() {
		if ev.Fields["stage"] == StageLogin && ev.Fields["severity"] == SevCritical {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d critical login events for one key use; the query/sign double callback must be deduplicated", n)
	}
	end := h.s.find(t, "end", stage(StageEnd))
	if end.Fields["severity"] != SevCritical || fmt.Sprint(end.Fields["token_origins"]) != "[rocky-ecom]" {
		t.Errorf("end = %+v", end.Fields)
	}
}

// ---- session bounds ----

func TestPerSourceAndTotalBounds(t *testing.T) {
	h := start(t, func(c *Config) { c.MaxPerSource = 2; c.MaxSessions = 10 }, KindRedis)
	c1, c2 := h.dial(t, KindRedis), h.dial(t, KindRedis)
	h.s.find(t, "second connect", func(e event.Event) bool {
		return e.Fields["stage"] == StageConnect && countStage(h.s, StageConnect) >= 2
	})
	c3 := h.dial(t, KindRedis)
	_ = c3.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c3.Read(make([]byte, 1)); err == nil {
		t.Fatal("third connection from one source should be closed")
	}
	if st := h.m.Stats(); st.Rejected != 1 || st.Accepted != 2 {
		t.Errorf("stats = %+v", st)
	}
	h.s.find(t, "rejected", stage(StageRejected))
	// freeing a slot lets the source back in
	c1.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c := h.dial(t, KindRedis)
		fmt.Fprint(c, "PING\r\n")
		c.SetReadDeadline(time.Now().Add(time.Second))
		if n, _ := bufio.NewReader(c).ReadString('\n'); strings.HasPrefix(n, "-NOAUTH") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slot not released after close")
		}
	}
	_ = c2
}

func countStage(s *sink, st string) int {
	n := 0
	for _, e := range s.all() {
		if e.Fields["stage"] == st {
			n++
		}
	}
	return n
}

func TestTotalSessionCap(t *testing.T) {
	h := start(t, func(c *Config) { c.MaxPerSource = 100; c.MaxSessions = 3 }, KindRedis)
	var keep []net.Conn
	for i := 0; i < 3; i++ {
		keep = append(keep, h.dial(t, KindRedis))
	}
	h.s.find(t, "3 connects", func(event.Event) bool { return countStage(h.s, StageConnect) == 3 })
	c := h.dial(t, KindRedis)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("over the total cap must be closed")
	}
	_ = keep
}

func TestSessionTimeoutAndCommandCap(t *testing.T) {
	h := start(t, func(c *Config) { c.SessionTimeout = 400 * time.Millisecond; c.MaxCommands = 5; c.HitRate = 1000 }, KindRedis)
	c := h.dial(t, KindRedis)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := io.ReadAll(c); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("idle session not cut by the session timeout")
	}

	c2 := h.dial(t, KindRedis)
	br := bufio.NewReader(c2)
	closed := false
	for i := 0; i < 50 && !closed; i++ {
		fmt.Fprint(c2, "GET k\r\n")
		if _, err := br.ReadString('\n'); err != nil {
			closed = true
		}
	}
	if !closed {
		t.Fatal("command cap did not end the session")
	}
	end := h.s.find(t, "end after cap", func(e event.Event) bool {
		cm, _ := e.Fields["commands"].([]string)
		return e.Fields["stage"] == StageEnd && len(cm) > 0
	})
	if cm := end.Fields["commands"].([]string); len(cm) > 6 {
		t.Errorf("recorded %d commands past the cap", len(cm))
	}
}

func TestPerSourceHitRateLimitKeepsCritical(t *testing.T) {
	h := start(t, func(c *Config) { c.HitRate = 0.001; c.HitBurst = 3; c.MaxCommands = 1000 }, KindRedis)
	h.token(t, honeytokens.Token{ID: "ht-1", Host: "ubuntu-email", Kind: honeytokens.KindDBCred, User: "svc_x", Secret: "Honey!Pass99"})
	c := h.dial(t, KindRedis)
	br := bufio.NewReader(c)
	for i := 0; i < 30; i++ {
		fmt.Fprint(c, "GET k\r\n")
		br.ReadString('\n')
	}
	if h.m.Stats().HitsDropped == 0 {
		t.Error("flood was not rate limited")
	}
	if n := len(h.s.all()); n > 6 {
		t.Errorf("%d events escaped a burst of 3", n)
	}
	fmt.Fprint(c, "AUTH Honey!Pass99\r\n")
	if l, _ := br.ReadString('\n'); l != "+OK\r\n" {
		t.Fatalf("honey auth reply %q", l)
	}
	e := h.s.find(t, "critical", func(e event.Event) bool { return e.Fields["severity"] == SevCritical })
	if e.Fields["token_origin"] != "ubuntu-email" {
		t.Errorf("origin = %v", e.Fields["token_origin"])
	}
}

// ---- other protocols ----

func TestRedisAuthRecorded(t *testing.T) {
	h := start(t, nil, KindRedis)
	c := h.dial(t, KindRedis)
	br := bufio.NewReader(c)
	fmt.Fprint(c, "*2\r\n$4\r\nAUTH\r\n$6\r\nsecret\r\n")
	if l, _ := br.ReadString('\n'); !strings.HasPrefix(l, "-WRONGPASS") {
		t.Errorf("reply %q", l)
	}
	e := h.s.find(t, "login", stage(StageLogin))
	if e.Fields["secret"] != "secret" || e.Fields["method"] != "redis_auth" {
		t.Errorf("%+v", e.Fields)
	}
	fmt.Fprint(c, "*1\r\n$4\r\nINFO\r\n")
	if l, _ := br.ReadString('\n'); !strings.HasPrefix(l, "-NOAUTH") {
		t.Errorf("reply %q", l)
	}
	// malformed input is dropped without a panic
	fmt.Fprint(c, "*99999\r\n")
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := br.ReadString('\n'); err == nil {
		t.Error("garbage should close the connection")
	}
}

func TestMySQLHoneyPasswordDetectedByScramble(t *testing.T) {
	h := start(t, nil, KindMySQL)
	h.token(t, honeytokens.Token{ID: "ht-db", Host: "rocky-ecom", Kind: honeytokens.KindDBCred, User: "svc_report07", Secret: "Orchid!Vault42"})
	c := h.dial(t, KindMySQL)
	hdr := make([]byte, 4)
	io.ReadFull(c, hdr)
	pkt := make([]byte, int(hdr[0])|int(hdr[1])<<8)
	io.ReadFull(c, pkt)
	if pkt[0] != 0x0a {
		t.Fatalf("handshake version byte %x", pkt[0])
	}
	i := 1 + strings.IndexByte(string(pkt[1:]), 0) + 1 + 4
	salt := append([]byte(nil), pkt[i:i+8]...)
	j := i + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10
	salt = append(salt, pkt[j:j+12]...)
	resp := make([]byte, 32)
	resp[0], resp[1] = 0x85, 0xa2
	resp = append(resp, "svc_report07\x00"...)
	auth := nativeScramble("Orchid!Vault42", salt)
	resp = append(resp, byte(len(auth)))
	resp = append(resp, auth...)
	n := len(resp)
	c.Write(append([]byte{byte(n), byte(n >> 8), byte(n >> 16), 1}, resp...))
	rep := make([]byte, 128)
	k, _ := c.Read(rep)
	if k < 9 || rep[4] != 0xff || !strings.Contains(string(rep[:k]), "Access denied for user 'svc_report07'") {
		t.Errorf("reply %q", rep[:k])
	}
	e := h.s.find(t, "critical", func(e event.Event) bool { return e.Fields["severity"] == SevCritical })
	if e.Fields["honeytoken"] != "ht-db" || e.Fields["token_origin"] != "rocky-ecom" {
		t.Errorf("%+v", e.Fields)
	}
}

// nativeScramble is an independent copy of the client side of mysql_native_password.
func nativeScramble(pw string, salt []byte) []byte {
	a := sha1.Sum([]byte(pw))
	b := sha1.Sum(a[:])
	x := sha1.Sum(append(append([]byte{}, salt...), b[:]...))
	out := make([]byte, 20)
	for i := range out {
		out[i] = a[i] ^ x[i]
	}
	return out
}

func TestMySQLUnknownPasswordRecordedAsHash(t *testing.T) {
	h := start(t, nil, KindMySQL)
	c := h.dial(t, KindMySQL)
	hdr := make([]byte, 4)
	io.ReadFull(c, hdr)
	io.ReadFull(c, make([]byte, int(hdr[0])))
	resp := append(make([]byte, 32), "root\x00"...)
	resp = append(resp, 20)
	resp = append(resp, make([]byte, 20)...)
	n := len(resp)
	c.Write(append([]byte{byte(n), 0, 0, 1}, resp...))
	e := h.s.find(t, "login", stage(StageLogin))
	if e.Fields["account"] != "root" || !strings.HasPrefix(e.Fields["secret"].(string), "$mysql$") {
		t.Errorf("%+v", e.Fields)
	}
}

func TestHTTPAdminRecordsCredentialsAndReflectsNothing(t *testing.T) {
	h := start(t, nil, KindHTTPAdmin)
	c := h.dial(t, KindHTTPAdmin)
	br := bufio.NewReader(c)
	body := "username=admin&password=P%40ss%3Cscript%3E"
	fmt.Fprintf(c, "POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n%s", len(body), body)
	raw := readHTTP(t, br)
	if !strings.Contains(raw, "Invalid username or password") || strings.Contains(raw, "script") {
		t.Errorf("response = %q", raw)
	}
	e := h.s.find(t, "login", stage(StageLogin))
	if e.Fields["account"] != "admin" || e.Fields["secret"] != "P@ss<script>" {
		t.Errorf("%+v", e.Fields)
	}
	fmt.Fprintf(c, "GET /wp-admin/<script> HTTP/1.1\r\nHost: x\r\nAuthorization: Basic %s\r\n\r\n", base64.StdEncoding.EncodeToString([]byte("bob:pw")))
	raw = readHTTP(t, br)
	if !strings.HasPrefix(raw, "HTTP/1.1 404") || strings.Contains(raw, "wp-admin") {
		t.Errorf("404 = %q", raw)
	}
	h.s.find(t, "basic", func(e event.Event) bool { return e.Fields["method"] == "http_basic" && e.Fields["account"] == "bob" })
	h.s.find(t, "request", stage(StageRequest))
}

func readHTTP(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	var sb strings.Builder
	cl := 0
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		sb.WriteString(l)
		if strings.HasPrefix(strings.ToLower(l), "content-length:") {
			fmt.Sscanf(strings.TrimSpace(l[15:]), "%d", &cl)
		}
		if l == "\r\n" {
			break
		}
	}
	b := make([]byte, cl)
	io.ReadFull(br, b)
	sb.Write(b)
	return sb.String()
}

func TestWinRMChallengeOnlyWhereConfigured(t *testing.T) {
	h := start(t, nil, KindWinRM)
	c := h.dial(t, KindWinRM)
	br := bufio.NewReader(c)
	fmt.Fprintf(c, "POST /wsman HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nAuthorization: Basic %s\r\n\r\n", base64.StdEncoding.EncodeToString([]byte("Administrator:Winter2024!")))
	raw := readHTTP(t, br)
	if !strings.HasPrefix(raw, "HTTP/1.1 401") || !strings.Contains(raw, "Negotiate") || !strings.Contains(raw, "Microsoft-HTTPAPI/2.0") {
		t.Errorf("%q", raw)
	}
	e := h.s.find(t, "login", stage(StageLogin))
	if e.Fields["account"] != "Administrator" || e.Fields["protocol"] != KindWinRM {
		t.Errorf("%+v", e.Fields)
	}
}

func TestRDPCookieRecorded(t *testing.T) {
	h := start(t, nil, KindRDP)
	c := h.dial(t, KindRDP)
	cookie := "Cookie: mstshash=administrator\r\n"
	n := 4 + 7 + len(cookie) + 8
	pkt := append([]byte{3, 0, byte(n >> 8), byte(n), byte(n - 5), 0xe0, 0, 0, 0, 0, 0}, cookie...)
	pkt = append(pkt, 1, 0, 8, 0, 3, 0, 0, 0)
	c.Write(pkt)
	rep := make([]byte, 19)
	if _, err := io.ReadFull(c, rep); err != nil || rep[0] != 3 || rep[5] != 0xd0 {
		t.Fatalf("connection confirm %v %x", err, rep)
	}
	e := h.s.find(t, "login", stage(StageLogin))
	if e.Fields["account"] != "administrator" || e.Fields["protocol"] != KindRDP {
		t.Errorf("%+v", e.Fields)
	}
}

func TestTelnetLoginThenFakeShell(t *testing.T) {
	h := start(t, func(c *Config) { c.AcceptAfter = 2 }, KindTelnet)
	c := h.dial(t, KindTelnet)
	br := bufio.NewReader(c)
	expect := func(s string) {
		t.Helper()
		var got []byte
		for !strings.Contains(string(got), s) {
			b, err := br.ReadByte()
			if err != nil {
				t.Fatalf("waiting for %q, got %q: %v", s, got, err)
			}
			got = append(got, b)
		}
	}
	expect("login: ")
	c.Write([]byte("root\r\n"))
	expect("Password: ")
	c.Write([]byte{255, 253, 1}) // IAC DO ECHO in the middle of input
	c.Write([]byte("one\r\n"))
	expect("Login incorrect")
	expect("login: ")
	c.Write([]byte("root\r\n"))
	expect("Password: ")
	c.Write([]byte("two\r\n"))
	expect("# ")
	c.Write([]byte("uname -a\r\n"))
	expect("Linux web01")
	h.s.find(t, "command", func(e event.Event) bool { return e.Fields["command"] == "uname -a" })
}

func TestSMBBannerOnly(t *testing.T) {
	h := start(t, nil, KindSMB)
	c := h.dial(t, KindSMB)
	c.Write([]byte{0x81, 0, 0, 0x44})
	rep := make([]byte, 5)
	if _, err := io.ReadFull(c, rep); err != nil || rep[0] != 0x83 {
		t.Fatalf("%v %x", err, rep)
	}
	h.s.find(t, "smb request", stage(StageRequest))
}

func TestStopClosesEverything(t *testing.T) {
	h := start(t, nil, KindRedis)
	c := h.dial(t, KindRedis)
	h.s.find(t, "connect", stage(StageConnect))
	_ = c
	// cleanup (cancel + wait) in start() asserts the module stops with a live session
}
