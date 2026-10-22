package link

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"runtime"
	"strings"
)

func isWindows() bool { return runtime.GOOS == "windows" }

// ALPN protocol ids. One listener serves all of them; the negotiated id picks
// the handler. Bootstrap downloads negotiate none (or http/1.1).
const (
	ALPNAgent  = "phylax/agent"
	ALPNRelay  = "phylax/relay"
	ALPNSplice = "phylax/splice"
	ALPNPatch  = "phylax/patch"
)

var phylaxALPNs = []string{ALPNAgent, ALPNRelay, ALPNSplice, ALPNPatch}

// ErrPinMismatch is returned when a peer's key does not match the pin.
var ErrPinMismatch = errors.New("link: peer key does not match pinned key")

// PeerCheck decides whether a peer presenting the key with the given pin may
// proceed past the TLS handshake. It runs inside the handshake, before any
// application data is read. A controller accepts unknown agent keys here only
// if enrollment (token in hello) is allowed; it then decides on the hello.
type PeerCheck func(Pin) error

// verifyPin builds a VerifyPeerCertificate callback. check may be nil only
// when mustPresent is false (bootstrap clients present no certificate).
func verifyPin(check PeerCheck) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("link: peer presented no certificate")
		}
		cert, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return fmt.Errorf("link: bad peer certificate: %w", err)
		}
		pin, err := pinOfCert(cert)
		if err != nil {
			return err
		}
		return check(pin)
	}
}

// PinEquals returns a PeerCheck that accepts exactly one pin.
func PinEquals(want Pin) PeerCheck {
	return func(got Pin) error {
		if got != want {
			return ErrPinMismatch
		}
		return nil
	}
}

func clientTLS(id *Identity, serverPin Pin, alpn string) *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{id.Cert},
		MinVersion:            tls.VersionTLS13,
		MaxVersion:            tls.VersionTLS13,
		NextProtos:            []string{alpn},
		InsecureSkipVerify:    true, // replaced by pin verification below
		VerifyPeerCertificate: verifyPin(PinEquals(serverPin)),
		// No session cache: every connection re-verifies the pin.
	}
}

// serverTLS returns the listener's config. The per-hello selection keeps the
// two worlds apart: a client offering any phylax/* protocol gets TLS 1.3 only,
// a mandatory client certificate and pin verification; everything else gets
// the bootstrap config (TLS 1.2+, no client certificate, server pinned by the
// client only) which the application may use for downloads and nothing else.
func serverTLS(id *Identity, check PeerCheck) *tls.Config {
	strict := &tls.Config{
		Certificates:           []tls.Certificate{id.Cert},
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		NextProtos:             phylaxALPNs,
		ClientAuth:             tls.RequireAnyClientCert,
		VerifyPeerCertificate:  verifyPin(check),
		SessionTicketsDisabled: true,
	}
	boot := &tls.Config{
		Certificates:           []tls.Certificate{id.Cert},
		MinVersion:             tls.VersionTLS12,
		NextProtos:             []string{"http/1.1"},
		ClientAuth:             tls.NoClientCert,
		SessionTicketsDisabled: true,
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{id.Cert},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			for _, p := range h.SupportedProtos {
				if strings.HasPrefix(p, "phylax/") {
					return strict, nil
				}
			}
			return boot, nil
		},
	}
}
