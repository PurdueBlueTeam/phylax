package probe

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- WinRM ----

type fakeWinRM struct {
	mu       sync.Mutex
	ntlm     *ntlmServer
	authed   map[string]bool
	steps    []string // per request: remote|hasAuth|action
	cmd      string
	stdout   string // a non-hostname command's stdout
	stderr   string
	exit     int // ExitCode of the last command
	hostname string
	deleted  []string // shell ids the server saw a Delete for
}

func (f *fakeWinRM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	auth := r.Header.Get("Authorization")
	act := ""
	if m := regexp.MustCompile(`Action[^>]*>([^<]+)<`).FindSubmatch(body); m != nil {
		act = string(m[1][strings.LastIndex(string(m[1]), "/")+1:])
	}
	f.steps = append(f.steps, fmt.Sprintf("%s|%v|%s|%s %s", r.RemoteAddr, auth != "", act, r.Method, r.URL.Path))
	if f.authed[r.RemoteAddr] {
		// authenticated connection
	} else if auth == "" {
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.Header().Add("WWW-Authenticate", "NTLM")
		w.WriteHeader(401)
		return
	} else {
		raw, _ := base64.StdEncoding.DecodeString(strings.Fields(auth)[1])
		switch binary.LittleEndian.Uint32(raw[8:]) {
		case 1:
			w.Header().Set("WWW-Authenticate", "Negotiate "+base64.StdEncoding.EncodeToString(f.ntlm.challenge(true)))
			w.WriteHeader(401)
			return
		case 3:
			if !f.ntlm.verify(raw) {
				w.WriteHeader(401)
				return
			}
			f.authed[r.RemoteAddr] = true
		}
	}
	w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
	switch act {
	case "Create":
		fmt.Fprint(w, `<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SHELL-1</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>`)
	case "Delete":
		if m := reSelector.FindSubmatch(body); m != nil {
			f.deleted = append(f.deleted, string(m[1]))
		}
		fmt.Fprint(w, `<s:Envelope><s:Body/></s:Envelope>`)
	case "Command":
		m := regexp.MustCompile(`-EncodedCommand</rsp:Arguments><rsp:Arguments>([^<]+)<`).FindSubmatch(body)
		if m != nil {
			raw, _ := base64.StdEncoding.DecodeString(string(m[1]))
			f.cmd = fromUTF16LE(raw)
		}
		fmt.Fprint(w, `<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>CMD-1</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>`)
	case "Receive":
		out := f.stdout
		if f.cmd == "hostname" {
			out = f.hostname + "\r\n"
		}
		se := ""
		if f.stderr != "" {
			se = `<rsp:Stream Name="stderr" CommandId="CMD-1">` + base64.StdEncoding.EncodeToString([]byte(f.stderr)) + `</rsp:Stream>`
		}
		fmt.Fprintf(w, `<s:Envelope><s:Body><rsp:ReceiveResponse><rsp:Stream Name="stdout" CommandId="CMD-1">%s</rsp:Stream>%s<rsp:CommandState CommandId="CMD-1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>%d</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse></s:Body></s:Envelope>`,
			base64.StdEncoding.EncodeToString([]byte(out)), se, f.exit)
	default:
		fmt.Fprint(w, `<s:Envelope><s:Body/></s:Envelope>`)
	}
}

func TestWinRM(t *testing.T) {
	f := &fakeWinRM{ntlm: &ntlmServer{users: map[string]string{"admin": "pw"}, targetName: "WIN1"}, authed: map[string]bool{}, hostname: "WINBOX"}
	srv := httptest.NewServer(f)
	defer srv.Close()
	h, port := hostPort(t, srv.Listener.Addr().String())
	spec := Spec{Type: WinRM, Host: h, Port: port}
	good := cred("admin", "pw")
	r := runOne(spec, &Item{Output: "WINBOX"}, &good, Options{})
	if !r.OK {
		t.Fatalf("%+v", r)
	}
	f.mu.Lock()
	if f.cmd != "hostname" {
		t.Errorf("default command %q", f.cmd)
	}
	if f.ntlm.gotDomain != "" {
		t.Errorf("a bare user means no NTLM domain, got %q", f.ntlm.gotDomain)
	}
	conns := map[string]bool{}
	for _, s := range f.steps {
		conns[strings.SplitN(s, "|", 2)[0]] = true
	}
	if len(conns) != 1 {
		t.Errorf("NTLM must run on one connection: %v", f.steps)
	}
	if !strings.Contains(f.steps[0], "|false|Create|POST /wsman") {
		t.Errorf("first request must be the unauthenticated create-shell POST: %s", f.steps[0])
	}
	f.mu.Unlock()

	if r = runOne(spec, &Item{Output: "OTHER"}, &good, Options{}); r.OK || r.Class != ClassContent {
		t.Fatalf("%+v", r)
	}
	if r = runOne(spec, &Item{Output: "WIN.+"}, &good, Options{}); r.OK { // exact match by default
		t.Fatalf("%+v", r)
	}
	if r = runOne(spec, &Item{Output: "WIN.+", UseRegex: true}, &good, Options{}); !r.OK {
		t.Fatalf("%+v", r)
	}
	bad := cred("admin", "nope")
	if r = runOne(spec, nil, &bad, Options{}); r.OK || r.Class != ClassAuth {
		t.Fatalf("%+v", r)
	}
	f.mu.Lock()
	f.stderr = "oops"
	f.mu.Unlock()
	if r = runOne(spec, nil, &good, Options{}); r.OK || !strings.Contains(r.Err, "stderr") {
		t.Fatalf("any stderr fails: %+v", r)
	}
}

// ---- LDAP ----

func TestLDAPSimpleBind(t *testing.T) {
	var mu sync.Mutex
	var dns []string
	h, p := listen(t, func(c net.Conn) {
		tag, v, err := readBER(c)
		if err != nil || tag != 0x30 {
			return
		}
		br := &bytesReader{v}
		_, id, _ := readBER(br)
		_, op, _ := readBER(br)
		ir := &bytesReader{op}
		readBER(ir) // version
		_, dn, _ := readBER(ir)
		_, pw, _ := readBER(ir)
		mu.Lock()
		dns = append(dns, string(dn))
		mu.Unlock()
		code := byte(49)
		if string(dn) == "bob@corp.local" && string(pw) == "pw" {
			code = 0
		}
		res := der(0x61, der(0x0a, []byte{code}), der(0x04, nil), der(0x04, []byte("diag")))
		c.Write(der(0x30, der(0x02, id), res))
	})
	spec := Spec{Type: LDAP, Host: h, Port: p, Domain: "corp.local"}
	good := cred("bob", "pw")
	if r := runOne(spec, nil, &good, Options{}); !r.OK {
		t.Fatalf("%+v", r)
	}
	bad := cred("bob", "no")
	if r := runOne(spec, nil, &bad, Options{}); r.OK || r.Class != ClassAuth {
		t.Fatalf("%+v", r)
	}
	empty := cred("bob", "")
	if r := runOne(spec, nil, &empty, Options{Strict: true}); r.OK {
		t.Fatalf("%+v", r)
	}
	mu.Lock()
	defer mu.Unlock()
	if dns[0] != "bob@corp.local" {
		t.Errorf("bind dn %v", dns)
	}
}

// ---- MSSQL ----

type fakeTDS struct {
	mu    sync.Mutex
	user  string
	pass  string
	enc   byte // prelogin ENCRYPTION answer
	tlsc  *tls.Config
	query string
	value string
	got   []string
}

func (f *fakeTDS) serve(c net.Conn) {
	typ, _, err := tdsReadMsg(c)
	if err != nil || typ != tdsPrelogin {
		return
	}
	tdsWrite(c, tdsReply, preloginBody(f.enc))
	var rw io.ReadWriter = c
	var wrap *tdsTLS
	if f.enc == 0 || f.enc == 1 || f.enc == 3 {
		wrap = &tdsTLS{Conn: c}
		ts := tls.Server(wrap, f.tlsc)
		if err := ts.Handshake(); err != nil {
			return
		}
		wrap.pass = true
		rw = ts
	}
	typ, body, err := tdsReadMsg(rw)
	if err != nil || typ != tdsLogin7 {
		return
	}
	// decode user and password out of LOGIN7
	rd := func(pos int, scramble bool) string {
		off := int(binary.LittleEndian.Uint16(body[pos:]))
		n := int(binary.LittleEndian.Uint16(body[pos+2:]))
		b := append([]byte(nil), body[off:off+2*n]...)
		if scramble {
			for i, x := range b {
				x ^= 0xA5
				b[i] = (x<<4)&0xF0 | x>>4
			}
		}
		return fromUTF16LE(b)
	}
	user, pass := rd(40, false), rd(44, true)
	f.mu.Lock()
	f.got = append(f.got, user+":"+pass)
	f.mu.Unlock()
	out := io.ReadWriter(rw)
	if f.enc == 0 {
		out = c // login-only encryption: the rest is plaintext
	}
	if user != f.user || pass != f.pass {
		msg := utf16le("Login failed for user '" + user + "'.")
		e := make([]byte, 0, 64)
		e = binary.LittleEndian.AppendUint32(e, 18456)
		e = append(e, 1, 14)
		e = binary.LittleEndian.AppendUint16(e, uint16(len(msg)/2))
		e = append(e, msg...)
		e = append(e, 0, 0, 0)
		tok := append([]byte{0xAA}, binary.LittleEndian.AppendUint16(nil, uint16(len(e)))...)
		tok = append(append(tok, e...), 0xFD, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
		tdsWrite(out, tdsReply, tok)
		return
	}
	ack := []byte{0xAD, 10, 0, 1, 4, 0, 0, 0x74, 0, 0, 0, 0, 0}
	tdsWrite(out, tdsReply, append(ack, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
	typ, body, err = tdsReadMsg(out)
	if err != nil || typ != tdsBatch {
		return
	}
	f.mu.Lock()
	f.query = fromUTF16LE(body[22:])
	f.mu.Unlock()
	// COLMETADATA: one nvarchar(100) column "c", one ROW
	cm := []byte{0x81, 1, 0, 0, 0, 0, 0, 0, 0, 0xE7, 200, 0, 9, 4, 208, 0, 52, 1, 'c', 0}
	val := utf16le(f.value)
	row := append([]byte{0xD1}, binary.LittleEndian.AppendUint16(nil, uint16(len(val)))...)
	row = append(row, val...)
	tdsWrite(out, tdsReply, append(append(cm, row...), 0xFD, 0x10, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0))
}

func TestMSSQL(t *testing.T) {
	for _, mode := range []struct {
		name string
		enc  byte
	}{{"not-supported", 2}, {"login-only", 0}, {"required", 3}} {
		t.Run(mode.name, func(t *testing.T) {
			f := &fakeTDS{user: "sa", pass: "P@ss:w0rd", enc: mode.enc, tlsc: &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}, MinVersion: tls.VersionTLS12}, value: "WINSQL"}
			h, p := listen(t, f.serve)
			spec := Spec{Type: MSSQL, Host: h, Port: p}
			good := cred("sa", "P@ss:w0rd")
			it := Item{Query: "SELECT @@SERVERNAME", Output: "WINSQL"}
			r := runOne(spec, &it, &good, Options{})
			if !r.OK {
				t.Fatalf("%+v", r)
			}
			f.mu.Lock()
			if f.query != "SELECT @@SERVERNAME" || f.got[0] != "sa:P@ss:w0rd" {
				t.Errorf("query %q login %v", f.query, f.got)
			}
			f.mu.Unlock()
			if r = runOne(spec, &Item{Query: "SELECT 1", Output: "NOPE"}, &good, Options{}); r.OK || r.Class != ClassContent {
				t.Fatalf("%+v", r)
			}
			if r = runOne(spec, &Item{Query: "q", Output: "WIN[A-Z]+", UseRegex: true}, &good, Options{}); !r.OK {
				t.Fatalf("%+v", r)
			}
			bad := cred("sa", "wrong")
			r = runOne(spec, &it, &bad, Options{})
			if r.OK || r.Class != ClassAuth || !strings.Contains(r.Debug, "18456") {
				t.Fatalf("%+v", r)
			}
			if r = runOne(spec, nil, &good, Options{}); !r.OK { // login only
				t.Fatalf("%+v", r)
			}
		})
	}
}

func TestTDSIntRows(t *testing.T) {
	// COLMETADATA int4 + intn, ROW
	b := []byte{0x81, 2, 0, 0, 0, 0, 0, 0, 0, 0x38, 1, 'a', 0, 0, 0, 0, 0, 0, 0, 0x26, 4, 1, 'b', 0}
	b = append(b, 0xD1, 7, 0, 0, 0, 2, 0xFE, 0xFF)
	r := parseTokens(b)
	if r.unsup || len(r.rows) != 1 || r.rows[0][0] != "7" || r.rows[0][1] != "-2" {
		t.Fatalf("%+v", r)
	}
}

// ---- Splunk ----

func TestSplunk(t *testing.T) {
	var mu sync.Mutex
	var reqs []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		mu.Lock()
		reqs = append(reqs, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/services/server/info":
			u, p, ok := r.BasicAuth()
			if !ok || u != "admin" || p != "pw" {
				w.WriteHeader(401)
				return
			}
			w.Write([]byte(`{"entry":[{"name":"server-info"}]}`))
		case "/services/auth/login":
			if r.PostForm.Get("username") == "admin" && r.PostForm.Get("password") == "pw" {
				json.NewEncoder(w).Encode(map[string]string{"sessionKey": "KEY123"})
				return
			}
			w.WriteHeader(401)
		case "/services/search/jobs/export":
			if r.Header.Get("Authorization") != "Splunk KEY123" {
				w.WriteHeader(401)
				return
			}
			if strings.Contains(r.PostForm.Get("search"), "index=_internal") {
				w.Write([]byte(`{"result":{"count":"42"}}`))
			}
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}}
	srv.StartTLS()
	defer srv.Close()
	h, port := hostPort(t, srv.Listener.Addr().String())
	spec := Spec{Type: Splunk, Host: h, Port: port}
	good := cred("admin", "pw")
	if r := runOne(spec, nil, &good, Options{}); !r.OK {
		t.Fatalf("%+v", r)
	}
	it := Item{Query: "index=_internal | stats count", Output: `"count":"42"`}
	if r := runOne(spec, &it, &good, Options{}); !r.OK {
		t.Fatalf("%+v", r)
	}
	it.Output = "nothing"
	if r := runOne(spec, &it, &good, Options{}); r.OK || r.Class != ClassContent {
		t.Fatalf("%+v", r)
	}
	bad := cred("admin", "x")
	if r := runOne(spec, nil, &bad, Options{}); r.OK || r.Class != ClassAuth {
		t.Fatalf("%+v", r)
	}
	_ = time.Second
}
