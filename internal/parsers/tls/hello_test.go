package tls

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/parsertest"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
)

// goClientHello captures the first TLS record a crypto/tls client sends.
func goClientHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() { _ = tls.Client(c1, cfg).Handshake() }()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c2, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	if _, err := io.ReadFull(c2, body); err != nil {
		t.Fatal(err)
	}
	return append(hdr, body...)
}

func TestGoClientHelloFingerprint(t *testing.T) {
	rec := goClientHello(t, &tls.Config{InsecureSkipVerify: true})
	h, err := ParseClientHello(rec[9:], len(rec)-5)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("go %s: ja4=%s ja3=%s ciphers=%d exts=%d len=%d groups=%v", "runtime", h.JA4(), h.JA3(), len(h.Ciphers), len(h.Extensions), h.Len, h.Groups)
	t.Logf("ja3 string: %s", h.JA3String())
}

// TestGo125HelloMatchesQuotient parses a ClientHello recorded from the real
// crypto/tls client of Go 1.25.3 (testdata, produced by running that toolchain
// with an empty ServerName and InsecureSkipVerify: the shape Quotient's HTTPS
// check sends) and requires the exact JA3 and JA4 quotient.md section 6 records
// for Quotient. Only the random, session id and key share bytes vary between
// runs, and none of them enters either fingerprint.
func TestGo125HelloMatchesQuotient(t *testing.T) {
	raw, err := os.ReadFile("testdata/go1.25.3_clienthello.hex")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	h, err := ParseClientHello(rec[9:], len(rec)-5)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := h.JA4(), "t13i131000_f57a46bbacb6_ab7e3b40a677"; got != want {
		t.Fatalf("JA4 %s want %s", got, want)
	}
	if got, want := h.JA3(), "006598cf32b8feecd39e4337bdba9c44"; got != want {
		t.Fatalf("JA3 %s want %s", got, want)
	}
	if h.SNI != "" || len(h.ALPN) != 0 || len(h.Ciphers) != 13 || h.Len < 1400 || h.Len > 1600 {
		t.Fatalf("shape: sni=%q alpn=%v ciphers=%d len=%d", h.SNI, h.ALPN, len(h.Ciphers), h.Len)
	}
}

// TestCurrentGoDiffersFromQuotient documents that the toolchain building this
// repository (Go 1.27) produces a different JA4 c-part than Quotient's Go 1.25,
// which is why the table is per-event (scorer.ParseTable).
func TestCurrentGoDiffersFromQuotient(t *testing.T) {
	rec := goClientHello(t, &tls.Config{InsecureSkipVerify: true})
	h, err := ParseClientHello(rec[9:], len(rec)-5)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s ja4=%s", runtime.Version(), h.JA4())
	if !strings.HasPrefix(h.JA4(), "t13i1310") {
		t.Fatalf("unexpected a-part %s", h.JA4())
	}
}

func TestJA4Details(t *testing.T) {
	h := &ClientHello{
		LegacyVersion: 0x0303, SuppVersions: []uint16{0x0a0a, 0x0304, 0x0303}, HasSNI: true, SNI: "example.com",
		ALPN: []string{"h2", "http/1.1"}, Ciphers: []uint16{0x1a1a, 0x1301, 0x1302},
		Extensions: []uint16{0x0a0a, 0, 16, 43, 13}, SigAlgs: []uint16{0x0403, 0x0804},
	}
	a := strings.Split(h.JA4(), "_")
	if a[0] != "t13d0204h2" {
		t.Fatalf("a-part %s (GREASE must be excluded; counts 2 ciphers, 4 extensions)", a[0])
	}
	h.ALPN = nil
	h.HasSNI = false
	if got := strings.Split(h.JA4(), "_")[0]; got != "t13i020400" {
		t.Fatalf("no SNI / no ALPN: %s", got)
	}
	if !IsGREASE(0x0a0a) || !IsGREASE(0xfafa) || IsGREASE(0x1301) {
		t.Fatal("GREASE detection")
	}
}

func TestMalformedHelloNeverPanics(t *testing.T) {
	rec := goClientHello(t, &tls.Config{InsecureSkipVerify: true})
	for i := 9; i <= len(rec); i += 7 {
		_, _ = ParseClientHello(rec[9:i], i-5)
	}
	for i := 0; i <= len(rec); i += 13 {
		_ = parsertest.Run(New, parsertest.C2S(rec[:i]))
	}
}

func goHelloForFuzz() []byte {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() { _ = tls.Client(c1, &tls.Config{InsecureSkipVerify: true, ServerName: "a.example"}).Handshake() }()
	hdr := make([]byte, 5)
	_, _ = io.ReadFull(c2, hdr)
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	_, _ = io.ReadFull(c2, body)
	return append(hdr, body...)
}
