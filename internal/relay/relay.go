// Package relay implements the relay role: a dumb splicer that forwards
// its segment's agent connections to its parent (controller or parent
// relay) and carries device-proxy splice requests. The agent's TLS runs
// end to end; the relay copies bytes and holds no agent keys.
package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/link"
)

// Parent is what the relay needs to reach its parent.
type Parent struct {
	Address string   `json:"address"` // addr:port
	Pin     link.Pin `json:"pin"`
	Host    string   `json:"host"` // relay's manifest identity
	Token   string   `json:"token"`
}

// Relay is one relay's state.
type Relay struct {
	parent      Parent
	key         ed25519.PrivateKey
	cert        *x509.Certificate
	log         *log.Logger
	allowlist   []net.IPNet // agent source CIDRs
	deviceAllow []string    // "host:port" / "host:*" device targets
	slices      int64       // completed splices (self-health)
	ln          net.Listener
	enrolled    bool        // true after the parent confirmed us
}

// Addr is the relay listener address (nil before Run).
func (r *Relay) Addr() net.Addr {
	if r.ln == nil {
		return nil
	}
	return r.ln.Addr()
}

// New opens (or creates) relay identity under dir. allowCIDRs are the
// source networks allowed to reach the relay listener; deviceTargets are
// the device-management addresses the relay may proxy.
func New(dir string, parent Parent, allowCIDRs, deviceTargets []string, logf *log.Logger) (*Relay, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if logf == nil {
		logf = log.New(os.Stderr, "relay: ", log.LstdFlags)
	}
	r := &Relay{parent: parent, log: logf, deviceAllow: deviceTargets}
	for _, c := range allowCIDRs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("bad allow CIDR %q: %w", c, err)
		}
		r.allowlist = append(r.allowlist, *ipnet)
	}
	if err := r.loadOrCreateIdentity(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Relay) loadOrCreateIdentity() error {
	keyPath := filepath.Join(r.parent.Host+"-identity", "key")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	if b, err := os.ReadFile(keyPath); err == nil && len(b) == ed25519.PrivateKeySize {
		r.key = ed25519.PrivateKey(b)
		cert, err := link.SelfSignedCert(r.key, r.parent.Host)
		if err != nil {
			return err
		}
		r.cert = cert
		// A rebooted relay keeps its enrollment: the parent checks the
		// pin, no token needed.
		if b, err := os.ReadFile(filepath.Dir(keyPath)+"/enrolled"); err == nil {
			r.enrolled = string(b) == "1"
		}
		return nil
	}
	_, priv, err := link.NewKeyPair()
	if err != nil {
		return err
	}
	cert, err := link.SelfSignedCert(priv, r.parent.Host)
	if err != nil {
		return err
	}
	r.key, r.cert = priv, cert
	return os.WriteFile(keyPath, []byte(priv), 0o600)
}

// Run listens on addr for agent connections and keeps the control
// connection to the parent up. Blocks until ctx is done.
func (r *Relay) Run(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	r.ln = ln
	defer func() { r.ln = nil }()
	go r.controlLoop(ctx)
	errCh := make(chan error, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go r.spliceAgent(conn, errCh)
		}
	}()
	select {
	case <-ctx.Done():
		ln.Close()
		return nil
	case err := <-errCh:
		r.log.Printf("listener error: %v", err)
		ln.Close()
		return err
	}
}

// spliceAgent checks the source allowlist, opens a plain TCP path to the
// parent, and copies bytes both ways. The agent's TLS handshake and
// session run end to end through this copy.
func (r *Relay) spliceAgent(conn net.Conn, errCh chan error) {
	defer conn.Close()
	src := conn.RemoteAddr().(*net.TCPAddr).IP
	if !r.allowed(src) {
		r.log.Printf("refusing agent connection from %s (not in segment)", src)
		return
	}
	parentConn, err := net.DialTimeout("tcp", r.parent.Address, 10*time.Second)
	if err != nil {
		r.log.Printf("parent unreachable: %v", err)
		return
	}
	defer parentConn.Close()
	start := time.Now()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(parentConn, conn)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, parentConn)
	}()
	wg.Wait()
	r.log.Printf("splice %s -> %s done (%s)", src, r.parent.Address, time.Since(start).Round(time.Millisecond))
}

func (r *Relay) allowed(ip net.IP) bool {
	for _, n := range r.allowlist {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (r *Relay) deviceAllowed(target string) bool {
	for _, t := range r.deviceAllow {
		if t == target {
			return true
		}
		if strings.HasSuffix(t, ":*") {
			host := strings.TrimSuffix(t, ":*")
			if h, _, err := net.SplitHostPort(target); err == nil && h == host {
				return true
			}
		}
	}
	return false
}

// controlLoop keeps the phylax/relay control connection to the parent.
func (r *Relay) controlLoop(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := r.controlOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			r.log.Printf("control down: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

func (r *Relay) controlOnce(ctx context.Context) error {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	cfg := link.ClientConfig(r.key, r.cert, r.parent.Pin, []string{link.ALPNRelay})
	conn, err := tls.DialWithDialer(dialer, "tcp", r.parent.Address, cfg)
	if err != nil {
		return err
	}
	lc := link.NewConn(conn, r.parent.Address)
	defer lc.Close()

	lc.On(link.TypRelayRequest, func(_ context.Context, _ *link.Conn, m *link.Message) error {
		var rr link.RelayRequest
		if err := link.DecodeJSON(m.Payload, &rr); err != nil {
			return err
		}
		if err := r.doSplice(rr); err != nil {
			r.log.Printf("splice %s failed: %v", rr.Target, err)
		}
		return nil
	})
	// Confirmation: the parent acks an accepted hello.
	conf := make(chan struct{}, 1)
	lc.On(link.TypAck, func(_ context.Context, _ *link.Conn, m *link.Message) error {
		select {
		case conf <- struct{}{}:
		default:
		}
		return nil
	})
	hello := link.Hello{Host: r.parent.Host, Version: "0.1.0", Roles: []string{"relay"}}
	if !r.enrolled {
		hello.Token = r.parent.Token
	}
	b, err := link.EncodeJSON(&hello)
	if err != nil {
		return err
	}
	if err := lc.Enqueue(link.PrioCore, &link.Message{Type: link.TypHello, Payload: b}); err != nil {
		return err
	}
	select {
	case <-conf:
		r.enrolled = true
		_ = os.WriteFile(filepath.Join(r.parent.Host+"-identity", "enrolled"), []byte("1"), 0o600)
	case <-lc.Done():
		return fmt.Errorf("control rejected by parent")
	case <-time.After(5 * time.Second):
		return fmt.Errorf("no confirmation from parent")
	}
	// Heartbeat on the control connection too (relay health).
	hb := time.NewTicker(5 * time.Second)
	defer hb.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-lc.Done():
			return fmt.Errorf("control connection closed")
		case <-hb.C:
			hbMsg, _ := link.EncodeJSON(&link.Heartbeat{
				Seq: 0, HostClock: time.Now().UTC().Format(time.RFC3339Nano),
				Modules: map[string]string{"relay": "ok"},
			})
			if err := lc.Enqueue(link.PrioCore, &link.Message{Type: link.TypHeartbeat, Payload: hbMsg}); err != nil {
				return err
			}
		}
	}
}

// doSplice handles one device-proxy request: check the allowlist, open the
// device connection and a phylax/splice session to the parent, send the
// metadata frame, then copy bytes both ways.
func (r *Relay) doSplice(rr link.RelayRequest) error {
	if !r.deviceAllowed(rr.Target) {
		return fmt.Errorf("target %s not in device allowlist", rr.Target)
	}
	dev, err := net.DialTimeout("tcp", rr.Target, 10*time.Second)
	if err != nil {
		return err
	}
	defer dev.Close()
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	cfg := link.ClientConfig(r.key, r.cert, r.parent.Pin, []string{link.ALPNSplice})
	parent, err := tls.DialWithDialer(dialer, "tcp", r.parent.Address, cfg)
	if err != nil {
		return err
	}
	defer parent.Close()
	meta, err := link.EncodeJSON(&rr)
	if err != nil {
		return err
	}
	if err := link.NewWriter(parent).Write(&link.Message{Type: link.TypRelayRequest, Payload: meta}); err != nil {
		return err
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(parent, dev) }()
	go func() { defer wg.Done(); _, _ = io.Copy(dev, parent) }()
	wg.Wait()
	return nil
}
