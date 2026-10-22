// Package txn defines the typed transaction event every protocol parser emits
// and the small Stream interface the capture engine drives them through.
//
// A Txn carries the feature keys internal/scorer's classifier reads (Attr and
// List, same names as the scorer.Features doc comment) plus parser-specific
// extras. Passwords are never stored: parsers put a salted-prefix SHA-256 of
// the secret in Cred.PassHash and list the field in Txn.Secret so the
// controller can encrypt it field by field.
package txn

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/scorer"
)

// Dir is the direction of bytes in a stream relative to the TCP client (the
// side that sent the SYN, or for mid-stream pickup the side nearer an ephemeral
// port).
type Dir uint8

const (
	C2S Dir = 0 // client to server
	S2C Dir = 1 // server to client
)

// Meta identifies the flow a parser is attached to.
type Meta struct {
	Client      netip.AddrPort
	Server      netip.AddrPort
	CommunityID string
	Start       time.Time
	// Expect lets a parser announce a related connection (FTP data channel).
	// May be nil.
	Expect func(server netip.AddrPort, note string)
}

// Cred is a credential seen on the wire. The secret is never kept.
type Cred struct {
	User     string `json:"user,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Mech     string `json:"mech,omitempty"`      // plain, login, ntlm, ...
	PassHash string `json:"pass_hash,omitempty"` // HashSecret(pass); empty when none was seen
}

// Txn is one parsed exchange.
type Txn struct {
	Time        time.Time `json:"time"`
	End         time.Time `json:"end,omitempty"`
	Proto       string    `json:"proto"` // scorer.Features.Proto vocabulary
	Type        string    `json:"type"`  // per-protocol kind, e.g. "exchange", "session", "login"
	Client      netip.AddrPort
	Server      netip.AddrPort
	CommunityID string `json:"community_id,omitempty"`
	OK          *bool  `json:"ok,omitempty"` // service-side success when determinable

	Attr map[string]string   `json:"attr,omitempty"`
	List map[string][]string `json:"list,omitempty"`
	Cred *Cred               `json:"cred,omitempty"`
	// Secret names the Attr keys / Cred fields that hold credential-derived
	// values, for field-level encryption downstream.
	Secret []string `json:"secret,omitempty"`
}

// New starts a Txn bound to a flow.
func New(m Meta, proto, typ string, ts time.Time) Txn {
	return Txn{
		Time: ts, Proto: proto, Type: typ,
		Client: m.Client, Server: m.Server, CommunityID: m.CommunityID,
		Attr: map[string]string{}, List: map[string][]string{},
	}
}

// Set stores an attribute.
func (t *Txn) Set(k, v string) {
	if t.Attr == nil {
		t.Attr = map[string]string{}
	}
	t.Attr[k] = v
}

// SetInt stores an integer attribute.
func (t *Txn) SetInt(k string, v int64) { t.Set(k, strconv.FormatInt(v, 10)) }

// SetBool stores a boolean attribute.
func (t *Txn) SetBool(k string, v bool) { t.Set(k, strconv.FormatBool(v)) }

// Add appends to a list feature, creating it (non-nil, possibly empty) first.
func (t *Txn) Add(k string, v ...string) {
	if t.List == nil {
		t.List = map[string][]string{}
	}
	t.List[k] = append(t.List[k], v...)
}

// EnsureList makes a (possibly empty) list present, which MatchEmptyList needs.
func (t *Txn) EnsureList(k string) {
	if t.List == nil {
		t.List = map[string][]string{}
	}
	if t.List[k] == nil {
		t.List[k] = []string{}
	}
}

// Succeeded records the outcome.
func (t *Txn) Succeeded(ok bool) { t.OK = &ok }

// Features converts the transaction to scorer input. InBurst, OneShot,
// LearnedCred and AdvisoryRunner are for the caller to fill in.
func (t Txn) Features() scorer.Features {
	f := scorer.Features{Proto: t.Proto, Port: int(t.Server.Port()), Attr: map[string]string{}, List: map[string][]string{}}
	for k, v := range t.Attr {
		f.Attr[k] = v
	}
	for k, v := range t.List {
		f.List[k] = append([]string{}, v...)
	}
	return f
}

// Keys returns Attr keys sorted (stable output for tests and logs).
func (t Txn) Keys() []string {
	ks := make([]string, 0, len(t.Attr))
	for k := range t.Attr {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// Emit receives finished transactions.
type Emit func(Txn)

// Stream is a protocol parser bound to one TCP connection. The engine calls
// Data with in-order bytes only; a hole in the stream ends the parser with End.
// Implementations must tolerate arbitrary bytes, never block and keep their
// own buffering bounded.
type Stream interface {
	Data(d Dir, b []byte, ts time.Time)
	// End flushes: the connection closed, was reset, idled out or the engine
	// gave up on it (gap, byte cap).
	End(ts time.Time)
}

// MaxText bounds every free-text value a parser stores.
const MaxText = 256

// Clip truncates s to MaxText bytes on a rune-agnostic boundary.
func Clip(s string) string {
	if len(s) > MaxText {
		return s[:MaxText]
	}
	return s
}

// HashSecret returns the stored form of a password: the first 16 hex digits of
// SHA-256("phylax-cred-v1\x00" + secret). It is enough to recognise a learned
// credential in a pool but is not the password. Low-entropy passwords can still
// be guessed from it, which is why Cred is also listed in Txn.Secret.
func HashSecret(secret string) string {
	h := sha256.Sum256([]byte("phylax-cred-v1\x00" + secret))
	return hex.EncodeToString(h[:8])
}

// SHA256Hex is a full hex digest.
func SHA256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
