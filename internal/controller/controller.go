// Package controller implements `phylax serve`: the one-listener protocol
// server (ALPN dispatch), enrollment, event mirroring with chain
// verification, ack watermarks, bootstrap downloads and the platform page.
package controller
import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// Controller is the `phylax serve` state.
type Controller struct {
	st     *store.Store
	log    *log.Logger
	key    ed25519.PrivateKey
	cert   *x509.Certificate
	pin    link.Pin
	binary  []byte // agent binary served for bootstrap
	ln      net.Listener
	advertise string
	darkAfter time.Duration
	stopped atomic.Bool

	// plan execution (M2)
	ctx      context.Context
	ctxStop  context.CancelFunc
	planKey  ed25519.PrivateKey
	planKeyPub string
	plansMu  sync.Mutex
	plans    map[string]*plan.Exec
	planName map[string]string // host -> active plan name
	seqMu    sync.Mutex
	seq      uint64
	safeMu   sync.Mutex
	safeModes map[string]bool
	connsMu  sync.Mutex
	conns    map[string]*agentConn
}

// New opens (or creates) the controller state under dir.
func New(dir string, logf *log.Logger) (*Controller, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	st, err := store.Open(dir)
	if err != nil {
		return nil, err
	}
	if logf == nil {
		logf = log.New(os.Stderr, "serve: ", log.LstdFlags)
	}
	c := &Controller{
		st: st, log: logf, darkAfter: 15 * time.Second,
		plans:     map[string]*plan.Exec{},
		planName:  map[string]string{},
		safeModes: map[string]bool{},
		conns:     map[string]*agentConn{},
	}
	c.ctx, c.ctxStop = context.WithCancel(context.Background())
	if err := c.loadOrCreateIdentity(); err != nil {
		st.Close()
		return nil, err
	}
	if err := c.loadOrCreatePlanKey(); err != nil {
		st.Close()
		return nil, err
	}
	return c, nil
}

func (c *Controller) loadOrCreateIdentity() error {
	keyPath := filepath.Join(c.st.Dir(), "controller.key")
	if b, err := os.ReadFile(keyPath); err == nil && len(b) == ed25519.PrivateKeySize {
		c.key = ed25519.PrivateKey(b)
		cert, err := controllerCert(c.key)
		if err != nil {
			return err
		}
		c.cert = cert
	} else {
		_, priv, err := link.NewKeyPair()
		if err != nil {
			return err
		}
		cert, err := controllerCert(priv)
		if err != nil {
			return err
		}
		c.key, c.cert = priv, cert
		if err := os.WriteFile(keyPath, []byte(priv), 0o600); err != nil {
			return err
		}
	}
	c.pin = link.PinCert(c.cert)
	c.log.Printf("controller pin %s", c.pin)
	return nil
}

// controllerCert builds the self-signed cert for the transport key. The
// pin is over the SPKI, so the random serial never affects it.
func controllerCert(key ed25519.PrivateKey) (*x509.Certificate, error) {
	return link.SelfSignedCert(key, "phylax-controller")
}

// Pin is the controller's public-key pin (in every bootstrap bundle).
func (c *Controller) Pin() link.Pin { return c.pin }

// Logf logs a controller message.
func (c *Controller) Logf(format string, args ...any) { c.log.Printf(format, args...) }

// Addr is the listener address (nil before Run).
func (c *Controller) Addr() net.Addr {
	if c.ln == nil {
		return nil
	}
	return c.ln.Addr()
}

// SetDarkAfter sets the heartbeat-silence threshold for dark marking
// (15 s in production; shorter in tests).
func (c *Controller) SetDarkAfter(d time.Duration) { c.darkAfter = d }

// DarkAfter is the current silence threshold.
func (c *Controller) DarkAfter() time.Duration { return c.darkAfter }

// Store exposes the state store (for commands and tests).
func (c *Controller) Store() *store.Store { return c.st }

// SetBinary sets the agent binary served at /phylax.
func (c *Controller) SetBinary(b []byte) { c.binary = b }

// Run listens on addr (e.g. 0.0.0.0:7443) and dispatches by ALPN until the
// listener is closed.
func (c *Controller) Run(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	// The listener serves every connection type on one port. Phylax
	// streams negotiate their ALPN (phylax/agent, ...); plain-HTTPS
	// bootstrap clients (curl, PowerShell) offer none. Accept any ALPN
	// and dispatch on what was negotiated.
	tlsCfg := link.ServerConfig(c.key, c.cert, nil, nil)
	tlsCfg.NextProtos = nil
	tlsLn := tls.NewListener(ln, tlsCfg)
	c.stopped.Store(false)
	c.ln = tlsLn
	c.log.Printf("listening on %s", addr)
	for {
		conn, err := tlsLn.Accept()
		if err != nil {
			if c.stopped.Load() {
				return nil // stopped
			}
			c.log.Printf("accept error: %v", err)
			continue
		}
		tc := conn.(*tls.Conn)
		// Go 1.27+ tls.NewListener defers the handshake; complete it here
		// so dispatch can rely on the negotiated protocol.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err = tc.HandshakeContext(ctx)
		cancel()
		if err != nil {
			tc.Close()
			c.log.Printf("handshake error: %v", err)
			continue
		}
		go c.dispatch(tc)
	}
}
// Stop closes the listener.
func (c *Controller) Stop() {
	c.stopped.Store(true)
	if c.ln != nil {
		c.ln.Close()
		c.ln = nil
	}
}
func (c *Controller) dispatch(conn *tls.Conn) {
	cs := conn.ConnectionState()
	// Plain-HTTPS bootstrap clients (curl, PowerShell) send no client
	// certificate; every phylax stream presents its enrollment identity.
	// The split is on the certificate, not ALPN, so a no-ALPN client can
	// never be mistaken for an agent.
	if len(cs.PeerCertificates) == 0 {
		c.handleBootstrap(conn)
		return
	}
	switch cs.NegotiatedProtocol {
	case link.ALPNRelay:
		c.handleRelay(conn)
	case link.ALPNSplice:
		c.handleSplice(conn)
	default: // phylax/agent (or an ALPN-less agent stream)
		c.handleAgent(conn)
	}
}

// IssueToken creates a one-time enrollment token (operator action).
func (c *Controller) IssueToken(host string, ttl time.Duration) (string, error) {
	return c.st.IssueToken(host, ttl)
}

// BinarySHA256Hex is the binary's hash, for the console one-liner.
func (c *Controller) BinarySHA256Hex() string {
	sum := sha256.Sum256(c.binary)
	return fmt.Sprintf("%x", sum)
}
