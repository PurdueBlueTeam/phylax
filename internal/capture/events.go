package capture

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"time"

	netmod "github.com/PurdueBlueTeam/phylax/internal/collect/net"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
)

// Event kinds the capture module publishes.
const (
	KindTxn      = "net.txn"  // one parsed non-HTTP transaction, with the scorer's feature keys
	KindFlow     = "net.flow" // one ended flow (including SYN-only and refused ones)
	KindScan     = "net.scan" // an aggregated scan by one source
	KindEvidence = "capture.evidence"
	KindStats    = "capture.stats"
)

// Bounds on what one event may carry, so a hostile peer cannot inflate the spool.
const (
	maxAttrValue = 512
	maxListItems = 64
	maxAttrs     = 64
)

// Sealer encrypts one credential-derived value for field-level storage.
type Sealer interface {
	Seal(plain string) (string, error)
}

// AESGCMSealer seals values with AES-256-GCM under a 32-byte key. Output is
// "enc1:" + base64(nonce || ciphertext). Only the holder of the key (the
// controller) can open it; the spool and the wire never carry the plaintext.
type AESGCMSealer struct{ aead cipher.AEAD }

// NewAESGCMSealer needs a 32-byte key.
func NewAESGCMSealer(key []byte) (*AESGCMSealer, error) {
	if len(key) != 32 {
		return nil, errors.New("capture: seal key must be 32 bytes")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &AESGCMSealer{aead: g}, nil
}

// Seal implements Sealer.
func (s *AESGCMSealer) Seal(plain string) (string, error) {
	n := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return "", err
	}
	return "enc1:" + base64.StdEncoding.EncodeToString(s.aead.Seal(n, n, []byte(plain), nil)), nil
}

// Open reverses Seal (the controller side; also used by tests).
func (s *AESGCMSealer) Open(sealed string) (string, error) {
	raw, ok := strings.CutPrefix(sealed, "enc1:")
	if !ok {
		return "", errors.New("capture: not a sealed value")
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(b) < s.aead.NonceSize() {
		return "", errors.New("capture: bad sealed value")
	}
	p, err := s.aead.Open(nil, b[:s.aead.NonceSize()], b[s.aead.NonceSize():], nil)
	return string(p), err
}

// Converter turns capture output into agent events.
type Converter struct {
	HTTP *HTTPEvents
	// Local reports whether an address belongs to this host; it decides a
	// flow's direction. Nil leaves direction unset.
	Local func(netip.Addr) bool
	// Seal encrypts credential-derived fields. Nil drops them: a password
	// hash never reaches the spool in the clear either way.
	Seal Sealer
}

func clipStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// isSecretKey is the defensive net under Txn.Secret: a parser that forgot to
// list a credential-looking attribute still does not leak it.
func isSecretKey(k string) bool {
	k = strings.ToLower(k)
	return strings.Contains(k, "pass_hash") || strings.Contains(k, "password") || strings.Contains(k, "passwd") || strings.Contains(k, "secret")
}

// TxnEvent converts a transaction: HTTP exchanges become http_request, every
// other protocol net.txn. Credential-derived values are sealed or dropped.
func (c *Converter) TxnEvent(t txn.Txn) (event.Event, bool) {
	if t.Proto == "http" && t.Type == "exchange" && c.HTTP != nil {
		return c.HTTP.Event(t)
	}
	if t.Proto == "http" && t.Type == "exchange" {
		return event.Event{}, false
	}
	secret := map[string]bool{}
	for _, s := range t.Secret {
		secret[s] = true
	}
	f := map[string]any{
		"proto": t.Proto, "type": t.Type,
		"src_ip": t.Client.Addr().String(), "src_port": int(t.Client.Port()),
		"dst_ip": t.Server.Addr().String(), "dst_port": int(t.Server.Port()),
	}
	if t.CommunityID != "" {
		f["community_id"] = t.CommunityID
	}
	if t.OK != nil {
		f["ok"] = *t.OK
	}
	if !t.End.IsZero() {
		f["duration_ms"] = t.End.Sub(t.Time).Milliseconds()
	}
	sealed := map[string]any{}
	var dropped []any
	hide := func(name, plain string) {
		if plain == "" {
			return
		}
		if c.Seal != nil {
			if s, err := c.Seal.Seal(plain); err == nil {
				sealed[name] = s
				return
			}
		}
		dropped = append(dropped, name)
	}
	attr := map[string]any{}
	keys := t.Keys()
	for _, k := range keys {
		if len(attr) >= maxAttrs {
			break
		}
		if secret[k] || isSecretKey(k) {
			hide(k, t.Attr[k])
			continue
		}
		attr[k] = clipStr(t.Attr[k], maxAttrValue)
	}
	if len(attr) > 0 {
		f["attr"] = attr
	}
	if len(t.List) > 0 {
		lists := map[string]any{}
		lk := make([]string, 0, len(t.List))
		for k := range t.List {
			lk = append(lk, k)
		}
		sort.Strings(lk)
		for _, k := range lk {
			if len(lists) >= maxAttrs {
				break
			}
			if secret[k] || isSecretKey(k) {
				continue
			}
			v := t.List[k]
			if len(v) > maxListItems {
				v = v[:maxListItems]
			}
			out := make([]any, 0, len(v)) // non-nil even when empty: MatchEmptyList needs presence
			for _, s := range v {
				out = append(out, clipStr(s, maxAttrValue))
			}
			lists[k] = out
		}
		f["list"] = lists
	}
	if cr := t.Cred; cr != nil {
		m := map[string]any{}
		if cr.User != "" {
			m["user"] = clipStr(cr.User, 128)
		}
		if cr.Domain != "" {
			m["domain"] = clipStr(cr.Domain, 128)
		}
		if cr.Mech != "" {
			m["mech"] = cr.Mech
		}
		hide("cred.pass_hash", cr.PassHash) // always a secret, listed or not
		f["cred"] = m
	}
	if len(sealed) > 0 {
		f["sealed"] = sealed
	}
	if len(dropped) > 0 {
		f["secrets_dropped"] = dropped
	}
	return event.Event{Time: t.Time, Kind: KindTxn, Priority: event.PriorityNormal, Fields: f}, true
}

func protoName(p uint8) string {
	switch p {
	case netmod.ProtoTCP:
		return "tcp"
	case netmod.ProtoUDP:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	}
	return "ip"
}

// FlowEvent converts an ended flow. raddr/laddr/lport/dir are set when the
// host's own addresses are known, in the field names the network rules use.
func (c *Converter) FlowEvent(fl Flow) event.Event {
	f := map[string]any{
		"community_id": fl.CommunityID, "proto": protoName(fl.Proto),
		"src_ip": fl.Client.Addr().String(), "src_port": int(fl.Client.Port()),
		"dst_ip": fl.Server.Addr().String(), "dst_port": int(fl.Server.Port()),
		"start": fl.Start.UTC().Format(time.RFC3339Nano), "end": fl.End.UTC().Format(time.RFC3339Nano),
		"pkts_c2s": fl.PktsC2S, "pkts_s2c": fl.PktsS2C, "bytes_c2s": fl.BytesC2S, "bytes_s2c": fl.BytesS2C,
		"payload_c2s": fl.PayloadC2S, "payload_s2c": fl.PayloadS2C, "end_reason": fl.EndReason,
	}
	if fl.Handshake != "" {
		f["handshake"] = fl.Handshake
	}
	if fl.Resets > 0 {
		f["resets"] = fl.Resets
		f["reset_by"] = fl.ResetBy
	}
	if fl.Service != "" {
		f["service"] = fl.Service
	}
	if fl.Scan {
		f["scan"] = true
	}
	if fl.Truncated {
		f["truncated"] = true
	}
	if fl.Txns > 0 {
		f["txns"] = fl.Txns
	}
	if c.Local != nil {
		switch {
		case c.Local(fl.Server.Addr()):
			f["dir"], f["raddr"], f["laddr"], f["lport"] = "inbound", fl.Client.Addr().String(), fl.Server.Addr().String(), int(fl.Server.Port())
			f["rport"] = int(fl.Client.Port())
		case c.Local(fl.Client.Addr()):
			f["dir"], f["raddr"], f["laddr"], f["lport"] = "outbound", fl.Server.Addr().String(), fl.Client.Addr().String(), int(fl.Client.Port())
			f["rport"] = int(fl.Server.Port())
		}
	}
	return event.Event{Time: fl.Start, Kind: KindFlow, Priority: event.PriorityBulk, Fields: f}
}

// ScanEvent converts an aggregated scan report.
func (c *Converter) ScanEvent(s Scan) event.Event {
	return event.Event{Time: s.End, Kind: KindScan, Priority: event.PriorityHigh, Fields: map[string]any{
		"src_ip": s.Src.String(), "start": s.Start.UTC().Format(time.RFC3339Nano), "end": s.End.UTC().Format(time.RFC3339Nano),
		"targets": s.Targets, "hosts": s.Hosts, "final": s.Final,
	}}
}
