package link

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"
)

// ALPN values (docs/protocol.md § Transport).
const (
	ALPNAgent    = "phylax/agent"
	ALPNRelay    = "phylax/relay"
	ALPNSplice   = "phylax/splice" // one device-proxy or bootstrap stream
	ALPNPatch    = "phylax/patch"
)
type Pin string

// PinKey computes the pin for an ed25519 public key (marshaled form).
func PinKey(pub ed25519.PublicKey) Pin {
	sum := sha256.Sum256(pub)
	return Pin(base64.StdEncoding.EncodeToString(sum[:]))
}

// PinCert computes the pin for a TLS certificate.
func PinCert(cert *x509.Certificate) Pin {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return Pin(base64.StdEncoding.EncodeToString(sum[:]))
}

// NewKeyPair generates an ed25519 keypair.
func NewKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// SelfSignedCert builds a long-lived self-signed certificate for pinning.
// Dates are wide; both sides ignore them (clock moves are a declared
// adversary capability, so dates must never gate authentication).
func SelfSignedCert(priv ed25519.PrivateKey, cn string) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(9999999999, 0), // year 2286; ignored by pinning
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// ClientConfig returns a TLS client config that pins the server's SPKI to
// pin and ignores certificate dates. alpn lists acceptable protocols in
// priority order. The client presents its own cert (agent identity); the
// controller may not know it before enrollment, so the client side never
// rejects on the server cert beyond the pin.
func ClientConfig(priv ed25519.PrivateKey, cert *x509.Certificate, pin Pin, alpn []string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12, // bootstrap accepts 1.2; 1.3 preferred
		MaxVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: priv}},
		NextProtos:         alpn,
		InsecureSkipVerify: true, // replaced by the pin check below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("link: no peer certificate")
			}
			peer, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			if got := PinCert(peer); got != pin {
				return fmt.Errorf("link: peer key pin mismatch: got %s want %s", got, pin)
			}
			return nil
		},
	}
}

// ServerConfig returns the TLS server config for the controller's one
// listener. Client certificates are REQUESTED, not required: bootstrap
// clients (curl, PowerShell) send none, and the application layer decides
// what a missing or mismatched certificate means (agent handler: required;
// bootstrap handler: expected). verify, when non-nil, sees the peer
// certificate (nil when the client sent none) and may reject. Dates are
// always ignored: pinning is the identity mechanism.
func ServerConfig(priv ed25519.PrivateKey, cert *x509.Certificate, alpn []string, verify func(peer *x509.Certificate) error) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: priv}},
		NextProtos:   alpn,
		ClientAuth:   tls.RequestClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			var peer *x509.Certificate
			if len(rawCerts) > 0 {
				peer, _ = x509.ParseCertificate(rawCerts[0])
			}
			if verify != nil {
				return verify(peer)
			}
			return nil
		},
	}
}
