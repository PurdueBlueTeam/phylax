package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/link"
)

// relayConn is one live relay control connection (ALPN phylax/relay).
type relayConn struct {
	c         *Controller
	lc        *link.Conn
	host      string
	helloDone chan error
}

// liveRelays tracks relay control connections by host.
var (
	relayMu    sync.Mutex
	liveRelays = map[string]*relayConn{}
)

func (c *Controller) handleRelay(conn *tls.Conn) {
	cs := conn.ConnectionState()
	var peerCert *x509.Certificate
	if len(cs.PeerCertificates) > 0 {
		peerCert = cs.PeerCertificates[0]
	}
	rc := &relayConn{c: c, lc: link.NewConn(conn, conn.RemoteAddr().String()), helloDone: make(chan error, 1)}
	defer rc.lc.Close()
	rc.lc.On(link.TypHello, func(_ context.Context, _ *link.Conn, m *link.Message) error {
		return rc.handleHello(peerCert, m)
	})
	rc.lc.On(link.TypHeartbeat, rc.handleHeartbeat)
	rc.lc.On(link.TypRelayRequest, rc.handleRelayRequest)

	select {
	case err := <-rc.helloDone:
		if err != nil {
			c.log.Printf("relay %s: hello rejected: %v", conn.RemoteAddr(), err)
			return
		}
	case <-rc.lc.Done():
		return
	}
	<-rc.lc.Done()
}

func (rc *relayConn) finishHello(err error) error {
	select {
	case rc.helloDone <- err:
	default:
	}
	if err != nil {
		return errors.New("link: closing: " + err.Error())
	}
	return nil
}

func (rc *relayConn) handleHello(peerCert *x509.Certificate, m *link.Message) error {
	var h link.Hello
	if err := link.DecodeJSON(m.Payload, &h); err != nil {
		return rc.finishHello(err)
	}
	if peerCert == nil {
		return rc.finishHello(errors.New("relay connection without certificate"))
	}
	pin := link.PinCert(peerCert)
	keyB64 := base64.StdEncoding.EncodeToString(peerCert.RawSubjectPublicKeyInfo)

	if h.Token != "" {
		issuedFor, err := rc.c.st.ConsumeToken(h.Token)
		if err != nil {
			return rc.finishHello(err)
		}
		if issuedFor != h.Host {
			return rc.finishHello(fmt.Errorf("token issued for %s, claimed %s", issuedFor, h.Host))
		}
		if existing, err := rc.c.st.GetHost(h.Host); err == nil {
			if existing.KeyB64 != keyB64 {
				return rc.finishHello(errors.New("re-enrollment requires operator action"))
			}
		} else {
			if err := rc.c.st.EnrollHost(h.Host, string(pin), keyB64, []string{"relay"}); err != nil {
				return rc.finishHello(err)
			}
		}
		rc.c.log.Printf("relay %s enrolled (pin %s)", h.Host, pin)
	} else {
		host, err := rc.c.st.GetHost(h.Host)
		if err != nil {
			return rc.finishHello(fmt.Errorf("unknown relay %s", h.Host))
		}
		if host.Pin != string(pin) {
			return rc.finishHello(errors.New("relay key does not match enrolled host"))
		}
		hasRole := false
		for _, r := range host.Roles {
			if r == "relay" {
				hasRole = true
			}
		}
		if !hasRole {
			return rc.finishHello(fmt.Errorf("host %s has no relay role", h.Host))
		}
	}
	rc.host = h.Host
	relayMu.Lock()
	liveRelays[h.Host] = rc
	relayMu.Unlock()
	defer func() {
		relayMu.Lock()
		if liveRelays[h.Host] == rc {
			delete(liveRelays, h.Host)
		}
		relayMu.Unlock()
	}()
	rc.c.log.Printf("relay %s connected", h.Host)
	b, err := link.EncodeJSON(&link.Ack{Host: h.Host, Seq: 0})
	if err != nil {
		return rc.finishHello(err)
	}
	if err := rc.lc.Enqueue(link.PrioCore, &link.Message{Type: link.TypAck, Payload: b}); err != nil {
		return rc.finishHello(err)
	}
	return rc.finishHello(nil)
}

func (rc *relayConn) handleHeartbeat(_ context.Context, _ *link.Conn, m *link.Message) error {
	var hb link.Heartbeat
	if err := link.DecodeJSON(m.Payload, &hb); err != nil {
		return err
	}
	return rc.c.st.TouchHeartbeat(rc.host, time.Now().UTC(), hb.Seq, "")
}

// handleRelayRequest is the controller's own device-proxy mechanism: a
// request to splice arrives on a relay's CONTROL connection only if the
// controller sent it; relays never originate these (defense in depth).
func (rc *relayConn) handleRelayRequest(_ context.Context, _ *link.Conn, m *link.Message) error {
	var rr link.RelayRequest
	if err := link.DecodeJSON(m.Payload, &rr); err != nil {
		return err
	}
	rc.c.log.Printf("relay %s: unsolicited relay_request %s (ignored)", rc.host, rr.Target)
	return nil
}

// SendRelayRequest asks a live relay to splice a stream to target.
func (c *Controller) SendRelayRequest(relayHost string, rr link.RelayRequest) error {
	relayMu.Lock()
	rc := liveRelays[relayHost]
	relayMu.Unlock()
	if rc == nil {
		return fmt.Errorf("no live relay connection for %s", relayHost)
	}
	b, err := link.EncodeJSON(rr)
	if err != nil {
		return err
	}
	return rc.lc.Enqueue(link.PrioSteps, &link.Message{Type: link.TypRelayRequest, Payload: b})
}

// handleSplice accepts a relay-opened phylax/splice stream: the first
// framed message is RelayRequest metadata, the rest is the device stream
// (end to end). M1: verify + log; M2 hands the stream to device adapters.
func (c *Controller) handleSplice(conn *tls.Conn) {
	defer conn.Close()
	// Relay identity: pin must match an enrolled relay host.
	cs := conn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return
	}
	pin := link.PinCert(cs.PeerCertificates[0])
	// Peek the first frame for metadata.
	rd := link.NewReader(conn)
	m, err := rd.Read()
	if err != nil || m.Type != link.TypRelayRequest {
		return
	}
	var rr link.RelayRequest
	if err := link.DecodeJSON(m.Payload, &rr); err != nil {
		return
	}
	c.log.Printf("splice from %s: %s class=%s (M1: metadata recorded, stream closed)", pin, rr.Target, rr.Class)
	// Drain briefly so the relay's side sees a clean close.
	buf := make([]byte, 64<<10)
	for {
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}
