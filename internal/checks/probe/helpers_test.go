package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

func cred(u, p string) Cred { return Cred{User: u, Pass: vault.NewSecretString(p)} }

// listen starts a TCP listener on loopback, serving each connection with h.
func listen(t *testing.T, h func(net.Conn)) (host string, port int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); h(c) }()
		}
	}()
	a := l.Addr().(*net.TCPAddr)
	return "127.0.0.1", a.Port
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func runOne(spec Spec, it *Item, cr *Cred, o Options) Result {
	if o.Timeout == 0 {
		o.Timeout = 5 * time.Second
	}
	return Run(context.Background(), spec, it, cr, o)
}

// recorder collects commands seen by a fake server.
type recorder struct {
	mu sync.Mutex
	l  []string
}

func (r *recorder) add(s string) { r.mu.Lock(); r.l = append(r.l, s); r.mu.Unlock() }
func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.l...)
}

func portStr(p int) string { return strconv.Itoa(p) }
