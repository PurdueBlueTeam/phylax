// Package winrm parses WinRM over plaintext HTTP (port 5985): POST /wsman with
// an NTLM or Negotiate exchange. It reports the request shape the scorer
// sends (method, path, User-Agent, first request without Authorization) and
// the NTLM user and domain from the type 3 message. Only metadata is read:
// message bodies (SOAP, or SPNEGO-sealed data) are hashed, not parsed.
package winrm

import (
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/internal/httpwire"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/ntlm"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
)

const maxPending = 32

// Parser is the per-connection WinRM parser.
type Parser struct {
	meta    txn.Meta
	emit    txn.Emit
	req     *httpwire.Reader
	resp    *httpwire.Reader
	pending []*httpwire.Message
	count   int
	// first is set once the first request of the connection has been classified.
	firstNoAuth *bool
}

// New returns the stream parser.
func New(m txn.Meta, emit txn.Emit) txn.Stream {
	p := &Parser{meta: m, emit: emit}
	p.req = &httpwire.Reader{Request: true, OnDone: p.onRequest}
	p.resp = &httpwire.Reader{OnHead: p.onRespHead, OnDone: p.onResponse}
	return p
}

func isWSMan(target string) bool {
	path, _, _ := strings.Cut(target, "?")
	return strings.EqualFold(strings.TrimRight(path, "/"), "/wsman")
}

func (p *Parser) onRequest(m *httpwire.Message) {
	if p.firstNoAuth == nil {
		_, has := m.Get("Authorization")
		v := !has
		p.firstNoAuth = &v
	}
	if len(p.pending) >= maxPending {
		p.flush(nil)
	}
	p.pending = append(p.pending, m)
}

func (p *Parser) onRespHead(m *httpwire.Message) (bool, bool) {
	return m.Status/100 == 1 || m.Status == 204 || m.Status == 304, false
}

func (p *Parser) onResponse(m *httpwire.Message) {
	if m.Status/100 == 1 {
		return
	}
	p.flush(m)
}

func (p *Parser) flush(resp *httpwire.Message) {
	if len(p.pending) == 0 {
		return
	}
	req := p.pending[0]
	p.pending = p.pending[1:]
	first := p.count == 0
	p.count++
	if !isWSMan(req.Target) {
		return
	}
	t := txn.New(p.meta, "winrm", "exchange", req.Start)
	t.End = req.End
	t.Set("winrm.method", req.Method)
	path, _, _ := strings.Cut(req.Target, "?")
	t.Set("winrm.path", strings.ToLower(txn.Clip(path)))
	if v, ok := req.Get("User-Agent"); ok {
		t.Set("winrm.ua", txn.Clip(v))
	}
	if v, ok := req.Get("Host"); ok {
		t.Set("winrm.host", txn.Clip(v))
	}
	if first && p.firstNoAuth != nil {
		t.SetBool("winrm.first_no_auth", *p.firstNoAuth)
	}
	auth, hasAuth := req.Get("Authorization")
	if hasAuth {
		t.Set("winrm.auth_scheme", strings.ToLower(strings.SplitN(auth, " ", 2)[0]))
		if raw := ntlm.FromHeader(auth); raw != nil {
			if nm, ok := ntlm.Parse(raw); ok {
				t.SetInt("winrm.ntlm_type", int64(nm.Type))
				if nm.Type == 3 {
					t.Cred = &txn.Cred{User: txn.Clip(nm.User), Domain: txn.Clip(nm.Domain), Mech: "ntlm"}
					t.Set("winrm.ntlm_flags", hex8(nm.Flags))
					t.Set("winrm.workstation", txn.Clip(nm.Workstation))
				}
			}
		}
	}
	t.SetInt("winrm.req_body_len", req.BodyLen)
	if req.BodySHA256 != "" {
		t.Set("winrm.req_body_sha256", req.BodySHA256)
	}
	if resp != nil {
		t.End = resp.End
		t.SetInt("winrm.status", int64(resp.Status))
		for _, h := range resp.Headers {
			if strings.EqualFold(h.Name, "WWW-Authenticate") {
				t.Add("winrm.offered_auth", strings.ToLower(strings.SplitN(h.Value, " ", 2)[0]))
			}
		}
		t.SetInt("winrm.resp_body_len", resp.BodyLen)
		t.Succeeded(resp.Status/100 == 2)
	}
	p.emit(t)
}

func hex8(v uint32) string {
	const d = "0123456789abcdef"
	b := []byte("0x00000000")
	for i := 0; i < 8; i++ {
		b[9-i] = d[v&0xf]
		v >>= 4
	}
	return string(b)
}

// Data implements txn.Stream.
func (p *Parser) Data(d txn.Dir, b []byte, ts time.Time) {
	if d == txn.C2S {
		p.req.Write(b, ts)
	} else {
		p.resp.Write(b, ts)
	}
}

// End implements txn.Stream.
func (p *Parser) End(ts time.Time) {
	p.resp.Close(ts)
	p.req.Close(ts)
	for len(p.pending) > 0 {
		p.flush(nil)
	}
}
