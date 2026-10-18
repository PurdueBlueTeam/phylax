package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/spool"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

const eventsBatch = 200

// agentConn is one live agent (or spliced-through-relay) connection.
type agentConn struct {
	c         *Controller
	lc        *link.Conn
	host      string
	helloDone chan error
	// nextSeq/nextHash is the chain tip this connection expects next.
	nextSeq  uint64
	nextHash string
}

// handleAgent runs one phylax/agent connection until it dies.
func (c *Controller) handleAgent(conn *tls.Conn) {
	cs := conn.ConnectionState()
	var peerCert *x509.Certificate
	if len(cs.PeerCertificates) > 0 {
		peerCert = cs.PeerCertificates[0]
	}
	ac := &agentConn{c: c, lc: link.NewConn(conn, conn.RemoteAddr().String()), helloDone: make(chan error, 1)}
	defer ac.lc.Close()

	ac.lc.On(link.TypHello, func(ctx context.Context, lc *link.Conn, m *link.Message) error {
		return ac.handleHello(peerCert, m)
	})
	ac.lc.On(link.TypHeartbeat, ac.handleHeartbeat)
	ac.lc.On(link.TypEvents, ac.handleEvents)
	ac.lc.On(link.TypStepResult, ac.handleStepResult)
	ac.lc.On(link.TypChunk, ac.handleChunk)

	select {
	case err := <-ac.helloDone:
		if err != nil {
			c.log.Printf("%s: hello rejected: %v", conn.RemoteAddr(), err)
			return
		}
	case <-ac.lc.Done():
		return
	}
	<-ac.lc.Done()
}


// handleHello enrolls or authenticates, then tells the agent where its
// ack watermark stands so it can resume.
func (ac *agentConn) handleHello(peerCert *x509.Certificate, m *link.Message) error {
	var h link.Hello
	if err := link.DecodeJSON(m.Payload, &h); err != nil {
		return ac.finishHello(errors.New("bad hello"))
	}
	if h.Host == "" {
		return ac.finishHello(errors.New("empty host"))
	}
	ac.host = h.Host

	var (
		pin    link.Pin
		keyB64 string
	)
	if peerCert != nil {
		pin = link.PinCert(peerCert)
		keyB64 = base64.StdEncoding.EncodeToString(peerCert.RawSubjectPublicKeyInfo)
	}

	if h.Token != "" {
		// Enrollment.
		if peerCert == nil {
			return ac.finishHello(errors.New("enrollment requires a client certificate"))
		}
		issuedFor, err := ac.c.st.ConsumeToken(h.Token)
		if err != nil {
			return ac.finishHello(err)
		}
		if issuedFor != h.Host {
			return ac.finishHello(fmt.Errorf("token issued for %s, claimed %s", issuedFor, h.Host))
		}
		if existing, err := ac.c.st.GetHost(h.Host); err == nil {
			if existing.KeyB64 != keyB64 {
				ac.c.log.Printf("ALERT: new key for existing host %s (re-enrollment attempt)", h.Host)
				return ac.finishHello(errors.New("re-enrollment requires operator action"))
			}
		} else {
			if err := ac.c.st.EnrollHost(h.Host, string(pin), keyB64, h.Roles); err != nil {
				return ac.finishHello(err)
			}
		}
		ac.c.log.Printf("host %s enrolled (pin %s, roles %v)", h.Host, pin, h.Roles)
	} else {
		// Established connection: pin must match the enrolled key.
		if peerCert == nil {
			return ac.finishHello(errors.New("agent connection without certificate or token"))
		}
		existing, err := ac.c.st.GetHost(h.Host)
		if err != nil {
			return ac.finishHello(fmt.Errorf("unknown host %s", h.Host))
		}
		if existing.Pin != string(pin) {
			ac.c.log.Printf("ALERT: pin mismatch for host %s", h.Host)
			return ac.finishHello(errors.New("key does not match enrolled host"))
		}
	}

	// Resume point: the agent resends from acked+1.
	acked, err := ac.c.st.Acked(h.Host)
	if err != nil {
		return ac.finishHello(err)
	}
	ac.nextSeq = acked + 1
	ac.nextHash = ""
	if acked > 0 {
		if hash, ok := ac.c.st.ChainAt(h.Host, acked); ok {
			ac.nextHash = hash
		}
	}
	if err := ac.send(&link.Ack{Host: h.Host, Seq: acked}); err != nil {
		return ac.finishHello(err)
	}
	if err := ac.sendConfig(); err != nil {
		return ac.finishHello(err)
	}
	return ac.finishHello(nil)
}

func (ac *agentConn) finishHello(err error) error {
	select {
	case ac.helloDone <- err:
	default:
	}
	if err != nil {
		return errors.New("link: closing: " + err.Error())
	}
	return nil
}

func (ac *agentConn) sendConfig() error {
	// M1: empty signed rules; the plan-signing key arrives with M2.
	return ac.send(&link.Config{Host: ac.host, Epoch: 1, Rules: nil, Sig: ""})
}

func (ac *agentConn) send(msg any) error {
	b, err := link.EncodeJSON(msg)
	if err != nil {
		return err
	}
	typ := link.TypAck
	switch msg.(type) {
	case *link.Ack:
		typ = link.TypAck
	case *link.Config:
		typ = link.TypConfig
	}
	return ac.lc.Enqueue(link.PrioCore, &link.Message{Type: typ, Payload: b})
}

func (ac *agentConn) handleHeartbeat(_ context.Context, _ *link.Conn, m *link.Message) error {
	if ac.host == "" {
		return nil
	}
	var hb link.Heartbeat
	if err := link.DecodeJSON(m.Payload, &hb); err != nil {
		return err
	}
	// The spool tip the agent reports is the chain tip we verify future
	// batches against (only advance, never regress).
	if hb.Seq >= ac.nextSeq {
		if h, ok := ac.c.st.ChainAt(ac.host, hb.Seq); ok {
			ac.nextSeq = hb.Seq + 1
			ac.nextHash = h
		}
	}
	return ac.c.st.TouchHeartbeat(ac.host, time.Now().UTC(), hb.Seq, "")
}

// handleEvents verifies the chain, mirrors the batch, and acks the new
// contiguous watermark.
func (ac *agentConn) handleEvents(_ context.Context, _ *link.Conn, m *link.Message) error {
	if ac.host == "" {
		return errors.New("events before hello")
	}
	var batch link.Events
	if err := link.DecodeJSON(m.Payload, &batch); err != nil {
		return err
	}
	for _, ev := range batch.Events {
		if ev.Seq != ac.nextSeq {
			if ev.Seq <= ac.nextSeq-1 {
				continue // duplicate the agent resends; acked already
			}
			ac.c.log.Printf("host %s: chain gap at %d (expecting %d)", ac.host, ev.Seq, ac.nextSeq)
			return fmt.Errorf("chain gap at %d", ev.Seq)
		}
		want := spool.HashRecord(ac.nextHash, ev.Seq, ev.TS, ev.Type, ev.Data)
		if want != ev.Hash || ev.Prev != ac.nextHash {
			ac.c.log.Printf("ALERT: host %s chain broken at %d", ac.host, ev.Seq)
			return fmt.Errorf("chain broken at %d", ev.Seq)
		}
		data, err := base64.StdEncoding.DecodeString(ev.Data)
		if err != nil {
			return err
		}
		if _, err := ac.c.st.RecordEvent(ac.host, store.Event{Seq: ev.Seq, TS: ev.TS, Type: ev.Type, Data: data, Hash: ev.Hash}); err != nil {
			return err
		}
		ac.nextSeq++
		ac.nextHash = ev.Hash
	}
	acked, err := ac.c.st.Acked(ac.host)
	if err != nil {
		return err
	}
	// The contiguous watermark is the largest n such that every seq <= n
	// is mirrored; with per-batch monotonic verification it is nextSeq-1.
	if ac.nextSeq-1 > acked {
		if err := ac.c.st.SetAcked(ac.host, ac.nextSeq-1); err != nil {
			return err
		}
		acked = ac.nextSeq - 1
	}
	return ac.send(&link.Ack{Host: ac.host, Seq: acked})
}


func (ac *agentConn) handleStepResult(_ context.Context, _ *link.Conn, m *link.Message) error {
	var sr link.StepResult
	if err := link.DecodeJSON(m.Payload, &sr); err != nil {
		return err
	}
	ac.c.log.Printf("host %s: step %s/%s %s ok=%v %s", ac.host, sr.Plan, sr.Node, sr.Phase, sr.OK, sr.Detail)
	return nil
}

func (ac *agentConn) handleChunk(_ context.Context, _ *link.Conn, m *link.Message) error {
	var ch link.Chunk
	if err := link.DecodeJSON(m.Payload, &ch); err != nil {
		return err
	}
	// M1: accept and discard bulk; M4 stores it by content hash.
	ac.c.log.Printf("host %s: chunk %s@%d (%d bytes)", ac.host, ch.SHA[:min(8, len(ch.SHA))], ch.Offset, len(ch.Payload))
	return nil
}
