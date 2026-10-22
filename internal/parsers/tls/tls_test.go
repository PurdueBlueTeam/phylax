package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/parsertest"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
	"github.com/PurdueBlueTeam/phylax/internal/scorer"
)

type tap struct {
	net.Conn
	mu    *sync.Mutex
	steps *[]parsertest.Step
}

func (t tap) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	if n > 0 {
		t.mu.Lock()
		*t.steps = append(*t.steps, parsertest.S2C(append([]byte(nil), b[:n]...)))
		t.mu.Unlock()
	}
	return n, err
}

func (t tap) Write(b []byte) (int, error) {
	t.mu.Lock()
	*t.steps = append(*t.steps, parsertest.C2S(append([]byte(nil), b...)))
	t.mu.Unlock()
	return t.Conn.Write(b)
}

func serverCert(t *testing.T) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "web.team21.local"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// handshake runs a real crypto/tls client and server over a pipe and records
// the byte stream as a client's capture would see it.
func handshake(t *testing.T, cc *tls.Config, sc *tls.Config) []parsertest.Step {
	t.Helper()
	c1, c2 := net.Pipe()
	var mu sync.Mutex
	var steps []parsertest.Step
	cli := tls.Client(tap{c1, &mu, &steps}, cc)
	srv := tls.Server(c2, sc)
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Handshake() }()
	if err := cli.Handshake(); err != nil {
		t.Fatal(err)
	}
	c1.Close() // raw close: tls.Conn.Close would block 5s sending close_notify into the pipe
	c2.Close()
	<-done
	mu.Lock()
	defer mu.Unlock()
	return append([]parsertest.Step(nil), steps...)
}

func TestFullHandshakeTLS13AndTLS12(t *testing.T) {
	cert := serverCert(t)
	for _, c := range []struct {
		name    string
		max     uint16
		version string
		wantCrt bool
	}{{"1.3", tls.VersionTLS13, "0x0304", false}, {"1.2", tls.VersionTLS12, "0x0303", true}} {
		t.Run(c.name, func(t *testing.T) {
			steps := handshake(t,
				&tls.Config{InsecureSkipVerify: true, ServerName: "web.team21.local", NextProtos: []string{"h2", "http/1.1"}, MaxVersion: c.max},
				&tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: c.max, NextProtos: []string{"h2"}})
			for _, n := range []int{1 << 20, 100, 1} {
				out := parsertest.Run(New, parsertest.Resegment(steps, n)...)
				if len(out) != 1 {
					t.Fatalf("n=%d got %d txns", n, len(out))
				}
				x := out[0]
				if x.Attr["tls.sni"] != "web.team21.local" || x.Attr["tls.sh_version"] != c.version || x.Attr["tls.sh_cipher"] == "" {
					t.Fatalf("n=%d attrs %v", n, x.Attr)
				}
				if len(x.List["tls.alpn"]) != 2 || x.List["tls.alpn"][0] != "h2" {
					t.Fatalf("alpn %v", x.List["tls.alpn"])
				}
				if _, has := x.Attr["tls.cert_sha256"]; has != c.wantCrt {
					t.Fatalf("n=%d certificate visibility: %v (1.2 only)", n, x.Attr)
				}
				if c.wantCrt && x.Attr["tls.cert_subject"] != "CN=web.team21.local" {
					t.Fatalf("subject %q", x.Attr["tls.cert_subject"])
				}
			}
		})
	}
}

func TestScorerShapedHelloIsClassified(t *testing.T) {
	cert := serverCert(t)
	steps := handshake(t, &tls.Config{InsecureSkipVerify: true}, &tls.Config{Certificates: []tls.Certificate{cert}})
	x := parsertest.Run(New, steps...)[0]
	if x.Attr["tls.sni"] != "" {
		t.Fatal("expected no SNI")
	}
	if v, ok := x.List["tls.alpn"]; !ok || len(v) != 0 {
		t.Fatalf("alpn must be present and empty: %v %v", v, ok)
	}
	c, _ := scorer.NewClassifier(scorer.DefaultTable())
	r := c.Classify(x.Features())
	// the current toolchain's JA3/JA4 differ from the Go 1.25 table values, but
	// the shape rules (no SNI, no ALPN, ~1.5 KB hello) must fire
	for _, id := range []string{"tls.no_sni", "tls.no_alpn"} {
		if !r.HasEvidence(id) {
			t.Fatalf("missing %s in %+v", id, r)
		}
	}
	if x.Attr["tls.ja4"] == "" || x.Attr["tls.ja3"] == "" {
		t.Fatal("fingerprints missing")
	}
}

func TestAlertAndNonTLS(t *testing.T) {
	if out := parsertest.Run(New, parsertest.C2S([]byte("GET / HTTP/1.1\r\n\r\n"))); len(out) != 0 {
		t.Fatalf("http produced tls txn: %v", out)
	}
	var out []txn.Txn
	s := New(parsertest.Meta(), func(x txn.Txn) { out = append(out, x) })
	s.Data(txn.C2S, []byte{0x16, 3, 1, 0, 3, 1, 0, 0}, parsertest.T0) // truncated handshake
	s.End(parsertest.T0)
	if len(out) != 0 {
		t.Fatalf("%v", out)
	}
}

func FuzzTLS(f *testing.F) {
	rec := goHelloForFuzz()
	parsertest.Fuzz(f, New, []parsertest.Step{parsertest.C2S(rec)})
}
