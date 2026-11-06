package probe

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func hostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := netip.ParseAddrPort(addr)
	_ = h
	return h, int(n.Port()) + 0*len(p)
}

func TestWebQuotientLaxness(t *testing.T) {
	var mu sync.Mutex
	var hosts, uas, accept, conns []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hosts = append(hosts, r.Host)
		uas = append(uas, r.UserAgent())
		accept = append(accept, r.Header.Get("Accept-Encoding")+"|"+r.Header.Get("Connection")+"|"+r.Header.Get("Accept"))
		conns = append(conns, r.RemoteAddr)
		mu.Unlock()
		switch r.URL.Path {
		case "/500":
			http.Error(w, "boom", 500)
		case "/hello":
			w.Write([]byte("hello world"))
		case "/redir":
			http.Redirect(w, r, "/hello", 302)
		}
	}))
	defer srv.Close()
	h, port := hostPort(t, srv.Listener.Addr().String())
	spec := Spec{Type: HTTP, Host: h, Port: port}

	// Quotient passes a 500 when neither status nor regex is configured.
	r := runOne(spec, &Item{Path: "/500"}, nil, Options{})
	if !r.OK || !r.ScorerOK || !r.StrictOK {
		t.Fatalf("lax: %+v", r)
	}
	// Strict mode catches it.
	r = runOne(spec, &Item{Path: "/500"}, nil, Options{Strict: true})
	if r.OK || !r.ScorerOK || r.StrictOK || len(r.StrictIssues) == 0 {
		t.Fatalf("strict: %+v", r)
	}
	// regex / status
	if r = runOne(spec, &Item{Path: "/hello", Regex: "w.rld", Status: 200}, nil, Options{}); !r.OK {
		t.Fatalf("%+v", r)
	}
	if r = runOne(spec, &Item{Path: "/hello", Regex: "nope"}, nil, Options{}); r.OK || r.Class != ClassContent {
		t.Fatalf("%+v", r)
	}
	if r = runOne(spec, &Item{Path: "/hello", Status: 404}, nil, Options{}); r.OK || !strings.Contains(r.Err, "status") {
		t.Fatalf("%+v", r)
	}
	// redirects are followed
	if r = runOne(spec, &Item{Path: "/redir", Regex: "hello"}, nil, Options{}); !r.OK {
		t.Fatalf("%+v", r)
	}
	// strict content hash
	sum := sha256.Sum256([]byte("hello world"))
	if r = runOne(spec, &Item{Path: "/hello", SHA256: hex.EncodeToString(sum[:])}, nil, Options{Strict: true}); !r.OK {
		t.Fatalf("%+v", r)
	}
	if r = runOne(spec, &Item{Path: "/hello", SHA256: strings.Repeat("0", 64)}, nil, Options{Strict: true}); r.OK || !r.ScorerOK {
		t.Fatalf("%+v", r)
	}

	mu.Lock()
	defer mu.Unlock()
	for i := range hosts {
		if hosts[i] != srv.Listener.Addr().String() {
			t.Errorf("Host header %q must carry the port: %q", hosts[i], srv.Listener.Addr())
		}
		if accept[i] != "gzip|close|" && accept[i] != "gzip||" {
			// net/http sends Connection: close when keep-alives are off
			t.Errorf("headers %q", accept[i])
		}
	}
	seen := map[string]bool{}
	for _, u := range uas {
		seen[u] = true
	}
	if len(seen) < 2 {
		t.Errorf("user agent should vary, saw %d", len(seen))
	}
	cs := map[string]bool{}
	for _, c := range conns {
		cs[c] = true
	}
	if len(cs) < len(conns)-1 { // redirects reuse nothing: keep-alives are off
		t.Errorf("connections reused: %d unique of %d", len(cs), len(conns))
	}
}

func TestWebRefusedAndTimeout(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	r := runOne(Spec{Type: HTTP, Host: "127.0.0.1", Port: port}, nil, nil, Options{})
	if r.OK || r.Class != ClassUnreachable {
		t.Fatalf("%+v", r)
	}
	// a server that accepts and never answers: timeout class
	h, p := listen(t, func(c net.Conn) { time.Sleep(2 * time.Second) })
	r = runOne(Spec{Type: HTTP, Host: h, Port: p}, nil, nil, Options{Timeout: 300 * time.Millisecond})
	if r.OK || r.Class != ClassTimeout || r.Elapsed > 2*time.Second {
		t.Fatalf("%+v", r)
	}
}

func TestHTTPSSelfSignedNoSNI(t *testing.T) {
	var sni string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("secure")) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}, GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		sni = h.ServerName
		return nil, nil
	}}
	srv.StartTLS()
	defer srv.Close()
	h, port := hostPort(t, srv.Listener.Addr().String())
	r := runOne(Spec{Type: HTTPS, Host: h, Port: port}, &Item{Regex: "secure"}, nil, Options{})
	if !r.OK {
		t.Fatalf("%+v", r)
	}
	if sni != "" {
		t.Errorf("an IP target must send no SNI, got %q", sni)
	}
}

// fakeDNS answers A and MX queries; drop makes it ignore the first n queries.
type fakeDNS struct {
	mu      sync.Mutex
	queries []dnsmessage.Message
	drop    int
}

func startDNS(t *testing.T, d *fakeDNS, a map[string]netip.Addr, mx map[string]string) int {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			d.mu.Lock()
			d.queries = append(d.queries, q)
			if d.drop > 0 {
				d.drop--
				d.mu.Unlock()
				continue
			}
			d.mu.Unlock()
			resp := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired}, Questions: q.Questions}
			name := q.Questions[0].Name
			switch q.Questions[0].Type {
			case dnsmessage.TypeA:
				if ip, ok := a[name.String()]; ok {
					resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: ip.As4()}})
				}
			case dnsmessage.TypeMX:
				if host, ok := mx[name.String()]; ok {
					resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeMX, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.MXResource{Pref: 10, MX: dnsmessage.MustNewName(host)}})
				}
			}
			b, _ := resp.Pack()
			pc.WriteTo(b, from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func TestDNS(t *testing.T) {
	d := &fakeDNS{}
	port := startDNS(t, d,
		map[string]netip.Addr{"www.team1.local.": netip.MustParseAddr("10.1.1.10")},
		map[string]string{"team1.local.": "mail.team1.local."})
	spec := Spec{Type: DNS, Host: "127.0.0.1", Port: port}
	a := Item{Name: "www.team1.local", Kind: "A", Answers: []string{"10.1.1.10"}}
	if r := runOne(spec, &a, nil, Options{}); !r.OK {
		t.Fatalf("%+v", r)
	}
	d.mu.Lock()
	q := d.queries[0]
	d.mu.Unlock()
	if !q.RecursionDesired || len(q.Additionals) != 0 {
		t.Errorf("query must be plain RD with no EDNS: %+v", q)
	}
	bad := Item{Name: "www.team1.local", Kind: "A", Answers: []string{"10.9.9.9"}}
	if r := runOne(spec, &bad, nil, Options{}); r.OK || r.Class != ClassContent || !strings.Contains(r.Err, "incorrect answer") {
		t.Fatalf("%+v", r)
	}
	if r := runOne(spec, &Item{Name: "nx.team1.local", Kind: "A", Answers: []string{"10.1.1.10"}}, nil, Options{}); r.OK || r.Err != "no records received" {
		t.Fatalf("%+v", r)
	}
	// MX can never pass as the scorer, but strict mode judges the service.
	mx := Item{Name: "team1.local", Kind: "MX", Answers: []string{"10 mail.team1.local."}}
	r := runOne(spec, &mx, nil, Options{})
	if r.OK || r.ScorerOK || r.Class != ClassScorerLimit {
		t.Fatalf("faithful MX should fail: %+v", r)
	}
	r = runOne(spec, &mx, nil, Options{Strict: true})
	if !r.OK || r.ScorerOK || !r.StrictOK {
		t.Fatalf("strict MX should pass the service: %+v", r)
	}
	mxBad := Item{Name: "team1.local", Kind: "MX", Answers: []string{"mail.other.local"}}
	if r = runOne(spec, &mxBad, nil, Options{Strict: true}); r.OK {
		t.Fatalf("%+v", r)
	}
	// the same query is repeated after a deadline
	d.mu.Lock()
	d.queries, d.drop = nil, 1
	d.mu.Unlock()
	r = runOne(spec, &a, nil, Options{Timeout: 3 * time.Second})
	d.mu.Lock()
	n := len(d.queries)
	same := n == 2 && d.queries[0].ID == d.queries[1].ID
	d.mu.Unlock()
	if !r.OK || !same {
		t.Fatalf("retry: ok=%v queries=%d same=%v %+v", r.OK, n, same, r)
	}
}

func TestTCPAndRDP(t *testing.T) {
	h, p := listen(t, func(c net.Conn) {
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		if n >= 6 && buf[0] == 3 && buf[5] == 0xE0 {
			c.Write([]byte{3, 0, 0, 11, 6, 0xD0, 0, 0, 0, 0, 0})
		}
	})
	if r := runOne(Spec{Type: TCP, Host: h, Port: p}, nil, nil, Options{}); !r.OK {
		t.Fatalf("%+v", r)
	}
	if r := runOne(Spec{Type: RDP, Host: h, Port: p}, nil, nil, Options{}); !r.OK {
		t.Fatalf("%+v", r)
	}
	if r := runOne(Spec{Type: RDP, Host: h, Port: p}, nil, nil, Options{Strict: true}); !r.OK {
		t.Fatalf("strict rdp: %+v", r)
	}
	// accepts but is not RDP: bare connect (the scorer) passes, strict does not
	h2, p2 := listen(t, func(c net.Conn) { time.Sleep(300 * time.Millisecond) })
	if r := runOne(Spec{Type: RDP, Host: h2, Port: p2}, nil, nil, Options{}); !r.OK {
		t.Fatalf("%+v", r)
	}
	if r := runOne(Spec{Type: RDP, Host: h2, Port: p2}, nil, nil, Options{Strict: true, Timeout: time.Second}); r.OK || !r.ScorerOK {
		t.Fatalf("%+v", r)
	}
}

func TestPing(t *testing.T) {
	r := runOne(Spec{Type: Ping, Host: "127.0.0.1"}, nil, nil, Options{})
	if r.Class == ClassConfig {
		t.Skipf("no ICMP socket available here: %s", r.Err)
	}
	if !r.OK {
		t.Fatalf("%+v", r)
	}
}

func TestFaithfulSamplingAndSweep(t *testing.T) {
	var mu sync.Mutex
	paths := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths[r.URL.Path]++
		mu.Unlock()
	}))
	defer srv.Close()
	h, port := hostPort(t, srv.Listener.Addr().String())
	spec := Spec{Type: HTTP, Host: h, Port: port, Items: []Item{{Path: "/a"}, {Path: "/b"}, {Path: "/c"}}}
	for range 60 {
		if r := Faithful(t.Context(), spec, Options{Timeout: 2 * time.Second}); !r.OK || r.Mode != "faithful" {
			t.Fatalf("%+v", r)
		}
	}
	mu.Lock()
	for _, p := range []string{"/a", "/b", "/c"} {
		if paths[p] < 5 {
			t.Errorf("item %s sampled %d/60 times", p, paths[p])
		}
	}
	paths = map[string]int{}
	mu.Unlock()
	rs := Sweep(t.Context(), spec, Options{Timeout: 2 * time.Second}, 0)
	if len(rs) != 3 {
		t.Fatalf("sweep ran %d probes", len(rs))
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range []string{"/a", "/b", "/c"} {
		if paths[p] != 1 {
			t.Errorf("sweep hit %s %d times", p, paths[p])
		}
	}
}
