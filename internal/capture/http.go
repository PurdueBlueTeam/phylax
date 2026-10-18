package capture

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Transaction is one parsed HTTP exchange on a declared service port
// (docs: Capture tiers — transactions).
type Transaction struct {
	TS       time.Time      `json:"ts"`
	Src      [16]byte       `json:"src"`
	Sport    uint16         `json:"sport"`
	Dst      [16]byte       `json:"dst"`
	Dport    uint16         `json:"dport"`
	Method   string         `json:"method"`
	Host     string         `json:"host"`
	Path     string         `json:"path"`
	Body     string         `json:"body,omitempty"`     // first bytes, capped
	Resp     int            `json:"resp,omitempty"`     // status
	RespHead string         `json:"resp_head,omitempty"` // first bytes, capped
	Complete bool           `json:"complete"`
}

const bodyCap = 4096

// connKey identifies a TCP stream (client side).
type connKey struct {
	src [16]byte
	sp  uint16
	dst [16]byte
	dp  uint16
}

type connState struct {
	req    []byte // accumulated request
	resp   []byte // accumulated response
	sawReq bool
	sawRsp bool
	src    [16]byte
	sp     uint16
	dst    [16]byte
	dp     uint16
	last   time.Time
}

// HTTPParser is the phase-1 HTTP/1.x parser: passive TCP reassembly
// per stream, request/response pairing, one transaction per request.
// A parser bug only affects this protocol (docs: Protocol parsers).
type HTTPParser struct {
	mu    sync.Mutex
	conns map[connKey]*connState
	tx    []Transaction
}

func NewHTTPParser() *HTTPParser {
	return &HTTPParser{conns: map[connKey]*connState{}}
}

// Feed gives the parser the next bytes of a stream in one direction.
func (p *HTTPParser) Feed(src [16]byte, sp uint16, dst [16]byte, dp uint16, payload []byte) {
	if len(payload) == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ck := connKey{src, sp, dst, dp}
	ckb := connKey{dst, dp, src, sp}
	st := p.conns[ck]
	if st == nil {
		if s2, ok := p.conns[ckb]; ok {
			st = s2
		} else {
			st = &connState{src: src, sp: sp, dst: dst, dp: dp}
			p.conns[ck] = st
			p.conns[ckb] = st
		}
	}
	st.last = time.Now()
	if st.sawRsp {
		return // response in flight; the request was already parsed
	}
	if st.sawReq {
		// response direction
		st.resp = append(st.resp, payload...)
		if end := findRspEnd(st.resp); end > 0 {
			p.finishLocked(st, st.resp[:end], st.resp[end:])
			st.resp = st.resp[end:]
		}
		return
	}
	st.req = append(st.req, payload...)
	if end := findReqEnd(st.req); end > 0 {
		req, rest := st.req[:end], st.req[end:]
		if req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(req))); err == nil {
			tx := Transaction{
				TS:     st.last,
				Src:    st.src, Sport: st.sp, Dst: st.dst, Dport: st.dp,
				Method: req.Method,
				Host:   req.Host,
				Path:   req.URL.RequestURI(),
				Body:   string(firstN(reqBody(req), bodyCap)),
			}
			if tx.Body == "" {
				tx.Body = string(firstN(rest, bodyCap))
			}
			st.sawReq = true
			p.tx = append(p.tx, tx)
		}
		st.req = st.req[end:]
	}
}

// Finish returns complete transactions older than olderThan and prunes
// stale streams.
func (p *HTTPParser) Finish(olderThan time.Time) []Transaction {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []Transaction
	keep := map[connKey]bool{}
	for ck, st := range p.conns {
		if st.last.Before(olderThan) {
			delete(p.conns, ck)
			delete(p.conns, connKey{st.dst, st.dp, st.src, st.sp})
			continue
		}
		keep[ck] = true
	}
	for i := range p.tx {
		if p.tx[i].TS.Before(olderThan) {
			out = append(out, p.tx[i])
		}
	}
	if len(out) > 0 {
		p.tx = p.tx[len(out):]
	}
	return out
}

func firstN(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

// findReqEnd finds the end of the request headers + any Content-Length
// body.
func findReqEnd(b []byte) int {
	i := bytes.Index(b, []byte("\r\n\r\n"))
	if i < 0 {
		return 0
	}
	head, rest := b[:i+4], b[i+4:]
	cl := 0
	for _, line := range strings.Split(string(head), "\r\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Content-Length") {
			if n, err := parseUint(strings.TrimSpace(v)); err == nil {
				cl = n
			}
		}
	}
	if cl > len(rest) {
		return 0
	}
	return i + 4 + cl
}

// findRspEnd finds the end of the response headers + body (content
// length or the head alone for zero-length/unknown).
func findRspEnd(b []byte) int {
	i := bytes.Index(b, []byte("\r\n\r\n"))
	if i < 0 {
		return 0
	}
	head, rest := b[:i+4], b[i+4:]
	cl := -1
	for _, line := range strings.Split(string(head), "\r\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Content-Length") {
			if n, err := parseUint(strings.TrimSpace(v)); err == nil {
				cl = n
			}
		}
	}
	if cl >= 0 && cl > len(rest) {
		return 0
	}
	if cl < 0 {
		return i + 4 // no body to wait for
	}
	return i + 4 + cl
}

func parseUint(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errNotNum
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

var errNotNum = &parseErr{}

type parseErr struct{}

func (e *parseErr) Error() string { return "not a number" }

// finishLocked pairs a parsed response with the pending request.
func (p *HTTPParser) finishLocked(st *connState, rsp, rest []byte) {
	if len(p.tx) == 0 {
		return
	}
	idx := len(p.tx) - 1
	p.tx[idx].Resp = statusOf(rsp)
	p.tx[idx].RespHead = string(firstN(rsp, 256))
	p.tx[idx].Complete = true
	_ = rest
	st.sawRsp = false
	st.sawReq = false
	st.req = nil
	st.resp = nil
}

func statusOf(b []byte) int {
	// "HTTP/1.1 200 OK"
	parts := bytes.SplitN(b, []byte(" "), 3)
	if len(parts) < 2 {
		return 0
	}
	return parseUintFirst(parts[1])
}

func parseUintFirst(b []byte) int {
	n := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func reqBody(req *http.Request) []byte {
	if req.Body == nil {
		return nil
	}
	buf := make([]byte, bodyCap)
	n, _ := req.Body.Read(buf)
	return buf[:n]
}
