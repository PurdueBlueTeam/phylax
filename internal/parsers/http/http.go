// Package http parses reassembled HTTP/1.x streams into one transaction per
// request/response pair. Bodies are hashed, never stored. Authorization and
// Cookie values are never stored; Basic credentials are reduced to a Cred.
package http

import (
	"bytes"
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/internal/httpwire"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
)

const maxPending = 32

// Parser is the per-connection HTTP parser.
type Parser struct {
	meta    txn.Meta
	emit    txn.Emit
	req     *httpwire.Reader
	resp    *httpwire.Reader
	pending []*httpwire.Message
	n       int // exchanges emitted
}

// New returns a stream parser for HTTP/1.x on a connection.
func New(m txn.Meta, emit txn.Emit) txn.Stream {
	p := &Parser{meta: m, emit: emit}
	p.req = &httpwire.Reader{Request: true, OnDone: p.onRequest}
	p.resp = &httpwire.Reader{OnHead: p.onRespHead, OnDone: p.onResponse}
	return p
}

var methods = [][]byte{[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("HEAD "), []byte("DELETE "),
	[]byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "), []byte("TRACE "), []byte("PROPFIND ")}

// Sniff reports whether b (the first client bytes) looks like an HTTP request.
func Sniff(b []byte) bool {
	for _, m := range methods {
		if bytes.HasPrefix(b, m) {
			return true
		}
	}
	return false
}

func (p *Parser) onRequest(m *httpwire.Message) {
	if len(p.pending) >= maxPending {
		p.flushOne(nil)
	}
	p.pending = append(p.pending, m)
}

func (p *Parser) flushOne(resp *httpwire.Message) {
	if len(p.pending) == 0 {
		return
	}
	req := p.pending[0]
	p.pending = p.pending[1:]
	p.emit(Transaction(p.meta, req, resp))
	p.n++
}

func (p *Parser) onRespHead(m *httpwire.Message) (noBody, opaque bool) {
	var req *httpwire.Message
	if len(p.pending) > 0 {
		req = p.pending[0]
	}
	if m.Status == 101 || (req != nil && req.Method == "CONNECT" && m.Status/100 == 2) {
		return true, true
	}
	if m.Status/100 == 1 || m.Status == 204 || m.Status == 304 || (req != nil && req.Method == "HEAD") {
		return true, false
	}
	return false, false
}

func (p *Parser) onResponse(m *httpwire.Message) {
	if m.Status/100 == 1 && m.Status != 101 { // 100 Continue: the real response follows
		return
	}
	p.flushOne(m)
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
		p.flushOne(nil)
	}
}

// Transaction builds the event for one exchange; resp may be nil.
func Transaction(meta txn.Meta, req, resp *httpwire.Message) txn.Txn {
	t := txn.New(meta, "http", "exchange", req.Start)
	t.End = req.End
	t.Set("http.method", req.Method)
	t.Set("http.path", txn.Clip(req.Target))
	t.Set("http.version", req.Version)
	if v, ok := req.Get("Host"); ok {
		t.Set("http.host", txn.Clip(v))
	}
	if v, ok := req.Get("User-Agent"); ok {
		t.Set("http.ua", txn.Clip(v))
	}
	t.EnsureList("http.headers")
	for _, h := range req.Headers {
		t.Add("http.headers", h.Name)
	}
	t.SetInt("http.req_body_len", req.BodyLen)
	if req.BodySHA256 != "" {
		t.Set("http.req_body_sha256", req.BodySHA256)
	}
	if v, ok := req.Get("Content-Type"); ok {
		t.Set("http.req_content_type", txn.Clip(v))
	}
	if v, ok := req.Get("Authorization"); ok {
		scheme := strings.ToLower(strings.SplitN(v, " ", 2)[0])
		t.Set("http.auth_scheme", scheme)
		if scheme == "basic" {
			if c := BasicCred(v); c != nil {
				t.Cred = c
				t.Secret = append(t.Secret, "cred.pass_hash")
			}
		}
	}
	if resp != nil {
		t.End = resp.End
		t.SetInt("http.status", int64(resp.Status))
		t.SetInt("http.resp_body_len", resp.BodyLen)
		if resp.BodySHA256 != "" {
			t.Set("http.resp_body_sha256", resp.BodySHA256)
		}
		if resp.BodyTruncated {
			t.SetBool("http.resp_body_truncated", true)
		}
		if v, ok := resp.Get("Content-Type"); ok {
			t.Set("http.content_type", txn.Clip(v))
		}
		if v, ok := resp.Get("Server"); ok {
			t.Set("http.server", txn.Clip(v))
		}
		if v, ok := resp.Get("Location"); ok {
			t.Set("http.location", txn.Clip(v))
		}
		if v, ok := resp.Get("Content-Length"); ok {
			if _, err := strconv.Atoi(v); err == nil {
				t.Set("http.resp_content_length", v)
			}
		}
		t.Succeeded(resp.Status < 400)
	}
	return t
}

// BasicCred decodes "Basic base64(user:pass)" into a Cred holding only a hash
// of the password.
func BasicCred(v string) *txn.Cred {
	f := strings.Fields(v)
	if len(f) != 2 || !strings.EqualFold(f[0], "basic") {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return nil
	}
	u, pw, ok := strings.Cut(string(raw), ":")
	if !ok {
		return nil
	}
	return &txn.Cred{User: txn.Clip(u), Mech: "basic", PassHash: txn.HashSecret(pw)}
}
