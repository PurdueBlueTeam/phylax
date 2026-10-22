package link

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"
)

// Conn is an established, authenticated TLS connection.
type Conn struct {
	*tls.Conn
	// ALPN is the negotiated protocol ("" for bootstrap clients).
	ALPN string
	// Peer is the pin of the peer's key. The zero Pin means the peer presented
	// no certificate (bootstrap downloads only).
	Peer Pin
}

func newConn(c *tls.Conn) (*Conn, error) {
	st := c.ConnectionState()
	out := &Conn{Conn: c, ALPN: st.NegotiatedProtocol}
	if len(st.PeerCertificates) > 0 {
		p, err := pinOfCert(st.PeerCertificates[0])
		if err != nil {
			return nil, err
		}
		out.Peer = p
	}
	return out, nil
}

// DialOptions configure Dial and Client.
type DialOptions struct {
	Identity  *Identity
	ServerPin Pin
	ALPN      string
	// Timeout bounds TCP connect plus TLS handshake (default 10 s).
	Timeout time.Duration
	// KeepAlive is the TCP keepalive period (default 15 s).
	KeepAlive time.Duration
}

func (o *DialOptions) defaults() {
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.KeepAlive <= 0 {
		o.KeepAlive = 15 * time.Second
	}
}

// Dial connects to addr and completes a pinned TLS 1.3 handshake. The server's
// key must match o.ServerPin and the server must select o.ALPN. On failure no
// application data has been sent.
func Dial(ctx context.Context, addr string, o DialOptions) (*Conn, error) {
	o.defaults()
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	d := net.Dialer{KeepAlive: o.KeepAlive}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	c, err := clientOver(ctx, raw, o)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

// Client runs the client side of the handshake over an existing connection
// (for example one already dialed through a proxy). It closes raw on failure.
func Client(ctx context.Context, raw net.Conn, o DialOptions) (*Conn, error) {
	o.defaults()
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	c, err := clientOver(ctx, raw, o)
	if err != nil {
		raw.Close()
	}
	return c, err
}

func clientOver(ctx context.Context, raw net.Conn, o DialOptions) (*Conn, error) {
	if o.Identity == nil || o.ALPN == "" {
		return nil, errors.New("link: dial needs an identity and an ALPN id")
	}
	tc := tls.Client(raw, clientTLS(o.Identity, o.ServerPin, o.ALPN))
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("link: handshake: %w", err)
	}
	if got := tc.ConnectionState().NegotiatedProtocol; got != o.ALPN {
		return nil, fmt.Errorf("link: server selected ALPN %q, wanted %q", got, o.ALPN)
	}
	return newConn(tc)
}
