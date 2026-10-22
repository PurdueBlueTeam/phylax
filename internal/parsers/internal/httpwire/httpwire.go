// Package httpwire is a bounded, incremental HTTP/1.x message reader for one
// direction of a reassembled stream. It does not buffer bodies: it counts and
// hashes them as they pass. Used by the http and winrm parsers.
package httpwire

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"strconv"
	"strings"
	"time"
)

// Limits.
const (
	MaxHead     = 16 << 10 // header block
	MaxHeaders  = 100
	MaxBodyHash = 8 << 20 // bytes of each body folded into the hash
)

// Header is one header line, name case preserved, in wire order.
type Header struct{ Name, Value string }

// Message is a request or response head plus body summary.
type Message struct {
	Request bool
	Method  string
	Target  string
	Version string
	Status  int
	Reason  string
	Headers []Header
	Start   time.Time // time the head completed
	End     time.Time // time the body completed

	BodyLen       int64
	BodySHA256    string // hex of the first MaxBodyHash bytes; empty when no body
	BodyTruncated bool
	Chunked       bool
}

// Get returns the first header value with the given name (case-insensitive).
func (m *Message) Get(name string) (string, bool) {
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value, true
		}
	}
	return "", false
}

// Reader parses messages from one direction.
type Reader struct {
	// Request selects request or response start-line parsing.
	Request bool
	// OnHead is called when a head is complete. Return noBody=true for
	// responses to HEAD, 1xx, 204, 304. Return opaque=true to stop parsing
	// (CONNECT tunnel, 101 upgrade).
	OnHead func(m *Message) (noBody, opaque bool)
	// OnDone is called when the body is complete (or the connection ended
	// for read-until-close bodies).
	OnDone func(m *Message)

	state  int
	buf    []byte
	cur    *Message
	remain int64
	h      hash.Hash
	last   time.Time
}

const (
	stHead = iota
	stBodyLen
	stBodyEOF
	stChunkSize
	stChunkData
	stChunkCRLF
	stTrailer
	stDead
)

// Dead reports whether the reader gave up (not HTTP, oversized head, tunnel).
func (r *Reader) Dead() bool { return r.state == stDead }

// Write consumes bytes.
func (r *Reader) Write(b []byte, ts time.Time) {
	r.last = ts
	for len(b) > 0 && r.state != stDead {
		switch r.state {
		case stHead:
			b = r.head(b, ts)
		case stBodyLen:
			n := int64(len(b))
			if n > r.remain {
				n = r.remain
			}
			r.body(b[:n])
			r.remain -= n
			b = b[n:]
			if r.remain == 0 {
				r.finish(ts)
			}
		case stBodyEOF:
			r.body(b)
			b = nil
		case stChunkSize:
			b = r.chunkSize(b)
		case stChunkData:
			n := int64(len(b))
			if n > r.remain {
				n = r.remain
			}
			r.body(b[:n])
			r.remain -= n
			b = b[n:]
			if r.remain == 0 {
				r.state = stChunkCRLF
				r.remain = 2
			}
		case stChunkCRLF:
			for len(b) > 0 && r.remain > 0 {
				c := b[0]
				if c != '\r' && c != '\n' {
					r.remain = 0 // lenient: missing terminator
					break
				}
				b = b[1:]
				if c == '\n' {
					r.remain = 0
				} else {
					r.remain--
				}
			}
			if r.remain == 0 {
				r.state = stChunkSize
				r.buf = r.buf[:0]
			}
		case stTrailer:
			b = r.trailer(b, ts)
		}
	}
}

// Close signals end of stream; a read-until-close body completes here.
func (r *Reader) Close(ts time.Time) {
	if r.state == stBodyEOF {
		r.finish(ts)
	}
	r.state = stDead
}

func findHeadEnd(buf []byte, from int) int {
	if from < 0 {
		from = 0
	}
	for i := from; i < len(buf); i++ {
		if buf[i] != '\n' {
			continue
		}
		if i+1 < len(buf) && buf[i+1] == '\n' {
			return i + 2
		}
		if i+2 < len(buf) && buf[i+1] == '\r' && buf[i+2] == '\n' {
			return i + 3
		}
	}
	return -1
}

func (r *Reader) head(b []byte, ts time.Time) []byte {
	old := len(r.buf)
	n := len(b)
	if room := MaxHead + 4 - old; n > room {
		n = room
	}
	r.buf = append(r.buf, b[:n]...)
	e := findHeadEnd(r.buf, old-2)
	if e < 0 {
		if len(r.buf) >= MaxHead+4 {
			r.state = stDead
		}
		return b[n:]
	}
	headBytes := r.buf[:e]
	rest := b[e-old:]
	m := parseHead(headBytes, r.Request)
	r.buf = r.buf[:0]
	if m == nil {
		r.state = stDead
		return nil
	}
	m.Start = ts
	r.cur = m
	noBody, opaque := false, false
	if r.OnHead != nil {
		noBody, opaque = r.OnHead(m)
	}
	if opaque {
		r.state = stDead
		return nil
	}
	r.h = nil
	switch {
	case noBody:
		r.finish(ts)
	case isChunked(m):
		m.Chunked = true
		r.state = stChunkSize
	default:
		if v, ok := m.Get("Content-Length"); ok {
			cl, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil || cl < 0 {
				r.state = stDead
				return nil
			}
			if cl == 0 {
				r.finish(ts)
			} else {
				r.state, r.remain = stBodyLen, cl
			}
		} else if r.Request {
			r.finish(ts)
		} else {
			r.state = stBodyEOF
		}
	}
	return rest
}

func isChunked(m *Message) bool {
	v, ok := m.Get("Transfer-Encoding")
	return ok && strings.Contains(strings.ToLower(v), "chunked")
}

func (r *Reader) body(p []byte) {
	if len(p) == 0 || r.cur == nil {
		return
	}
	if r.h == nil {
		r.h = sha256.New()
	}
	if r.cur.BodyLen < MaxBodyHash {
		take := int64(len(p))
		if r.cur.BodyLen+take > MaxBodyHash {
			take = MaxBodyHash - r.cur.BodyLen
			r.cur.BodyTruncated = true
		}
		r.h.Write(p[:take])
	} else {
		r.cur.BodyTruncated = true
	}
	r.cur.BodyLen += int64(len(p))
}

func (r *Reader) finish(ts time.Time) {
	m := r.cur
	r.cur = nil
	r.state = stHead
	r.buf = r.buf[:0]
	if m == nil {
		return
	}
	if r.h != nil {
		m.BodySHA256 = hex.EncodeToString(r.h.Sum(nil))
		r.h = nil
	}
	m.End = ts
	if r.OnDone != nil {
		r.OnDone(m)
	}
}

func (r *Reader) chunkSize(b []byte) []byte {
	for i := 0; i < len(b); i++ {
		if b[i] != '\n' {
			if len(r.buf) >= 64 {
				r.state = stDead
				return nil
			}
			r.buf = append(r.buf, b[i])
			continue
		}
		line := strings.TrimSpace(string(r.buf))
		r.buf = r.buf[:0]
		if j := strings.IndexByte(line, ';'); j >= 0 {
			line = line[:j]
		}
		n, err := strconv.ParseUint(strings.TrimSpace(line), 16, 63)
		if err != nil {
			r.state = stDead
			return nil
		}
		if n == 0 {
			r.state = stTrailer
		} else {
			r.state, r.remain = stChunkData, int64(n)
		}
		return b[i+1:]
	}
	return nil
}

func (r *Reader) trailer(b []byte, ts time.Time) []byte {
	for i := 0; i < len(b); i++ {
		if b[i] != '\n' {
			if len(r.buf) < 1024 {
				r.buf = append(r.buf, b[i])
			}
			continue
		}
		line := strings.TrimRight(string(r.buf), "\r")
		r.buf = r.buf[:0]
		if line == "" {
			r.finish(ts)
			return b[i+1:]
		}
	}
	return nil
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte("()<>@,;:\\\"/[]?={}", c) >= 0 {
			return false
		}
	}
	return true
}

func parseHead(raw []byte, request bool) *Message {
	text := string(raw)
	lines := strings.Split(text, "\n")
	i := 0
	for i < len(lines) && strings.TrimRight(lines[i], "\r") == "" {
		i++
	}
	if i >= len(lines) {
		return nil
	}
	first := strings.TrimRight(lines[i], "\r")
	i++
	m := &Message{Request: request}
	if request {
		parts := strings.SplitN(first, " ", 3)
		if len(parts) != 3 || !isToken(parts[0]) || !strings.HasPrefix(parts[2], "HTTP/1.") || parts[1] == "" {
			return nil
		}
		m.Method, m.Target, m.Version = parts[0], parts[1], parts[2]
	} else {
		parts := strings.SplitN(first, " ", 3)
		if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/1.") {
			return nil
		}
		code, err := strconv.Atoi(parts[1])
		if err != nil || code < 100 || code > 999 {
			return nil
		}
		m.Version, m.Status = parts[0], code
		if len(parts) == 3 {
			m.Reason = parts[2]
		}
	}
	for ; i < len(lines) && len(m.Headers) < MaxHeaders; i++ {
		l := strings.TrimRight(lines[i], "\r")
		if l == "" {
			break
		}
		c := strings.IndexByte(l, ':')
		if c <= 0 || !isToken(l[:c]) {
			continue
		}
		m.Headers = append(m.Headers, Header{Name: l[:c], Value: strings.TrimSpace(l[c+1:])})
	}
	return m
}
