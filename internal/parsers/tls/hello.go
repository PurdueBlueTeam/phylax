package tls

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Extension types used here.
const (
	extSNI        = 0
	extGroups     = 10
	extPointFmts  = 11
	extSigAlgs    = 13
	extALPN       = 16
	extSuppVers   = 43
	maxHelloItems = 512
)

// ClientHello holds the fields fingerprints are computed from.
type ClientHello struct {
	LegacyVersion uint16
	Ciphers       []uint16
	Extensions    []uint16 // wire order, GREASE included
	SNI           string
	HasSNI        bool
	ALPN          []string
	SuppVersions  []uint16
	Groups        []uint16
	PointFmts     []uint8
	SigAlgs       []uint16
	SessionIDLen  int
	Len           int // handshake message length including its 4-byte header
}

// ErrTruncated means the hello body ended inside a field.
var ErrTruncated = errors.New("tls: truncated client hello")

type rd struct {
	b   []byte
	err error
}

func (r *rd) take(n int) []byte {
	if r.err != nil || n < 0 || n > len(r.b) {
		r.err = ErrTruncated
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}
func (r *rd) u8() int {
	v := r.take(1)
	if v == nil {
		return 0
	}
	return int(v[0])
}
func (r *rd) u16() int {
	v := r.take(2)
	if v == nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(v))
}

// ParseClientHello parses a ClientHello handshake body (after the 4-byte
// handshake header). total is the full message length including that header.
func ParseClientHello(body []byte, total int) (*ClientHello, error) {
	r := &rd{b: body}
	h := &ClientHello{Len: total}
	h.LegacyVersion = uint16(r.u16())
	r.take(32)
	h.SessionIDLen = r.u8()
	r.take(h.SessionIDLen)
	n := r.u16()
	cs := r.take(n)
	if r.err != nil {
		return nil, r.err
	}
	for i := 0; i+1 < len(cs) && len(h.Ciphers) < maxHelloItems; i += 2 {
		h.Ciphers = append(h.Ciphers, binary.BigEndian.Uint16(cs[i:]))
	}
	r.take(r.u8()) // compression
	if r.err != nil {
		return nil, r.err
	}
	if len(r.b) == 0 {
		return h, nil
	}
	el := r.u16()
	ext := r.take(el)
	if r.err != nil {
		// tolerate a hello cut short inside extensions: keep what parsed
		ext = r.b
		r.err = nil
	}
	er := &rd{b: ext}
	for len(er.b) >= 4 && len(h.Extensions) < maxHelloItems {
		t := er.u16()
		l := er.u16()
		d := er.take(l)
		if er.err != nil {
			break
		}
		h.Extensions = append(h.Extensions, uint16(t))
		h.parseExt(uint16(t), d)
	}
	return h, nil
}

func (h *ClientHello) parseExt(t uint16, d []byte) {
	r := &rd{b: d}
	switch t {
	case extSNI:
		h.HasSNI = true
		list := r.take(r.u16())
		lr := &rd{b: list}
		for len(lr.b) > 0 && lr.err == nil {
			typ := lr.u8()
			name := lr.take(lr.u16())
			if typ == 0 && name != nil && h.SNI == "" {
				h.SNI = string(name)
			}
		}
	case extALPN:
		list := r.take(r.u16())
		lr := &rd{b: list}
		for len(lr.b) > 0 && lr.err == nil && len(h.ALPN) < 32 {
			h.ALPN = append(h.ALPN, string(lr.take(lr.u8())))
		}
	case extSuppVers:
		list := r.take(r.u8())
		for i := 0; i+1 < len(list) && len(h.SuppVersions) < 64; i += 2 {
			h.SuppVersions = append(h.SuppVersions, binary.BigEndian.Uint16(list[i:]))
		}
	case extGroups:
		list := r.take(r.u16())
		for i := 0; i+1 < len(list) && len(h.Groups) < maxHelloItems; i += 2 {
			h.Groups = append(h.Groups, binary.BigEndian.Uint16(list[i:]))
		}
	case extPointFmts:
		list := r.take(r.u8())
		h.PointFmts = append(h.PointFmts, list...)
	case extSigAlgs:
		list := r.take(r.u16())
		for i := 0; i+1 < len(list) && len(h.SigAlgs) < maxHelloItems; i += 2 {
			h.SigAlgs = append(h.SigAlgs, binary.BigEndian.Uint16(list[i:]))
		}
	}
}

// IsGREASE reports RFC 8701 placeholder values.
func IsGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

// MaxVersion is the highest non-GREASE version offered.
func (h *ClientHello) MaxVersion() uint16 {
	v := h.LegacyVersion
	for _, s := range h.SuppVersions {
		if !IsGREASE(s) && s > v {
			v = s
		}
	}
	return v
}

func dec16(xs []uint16, skipGrease bool) string {
	var parts []string
	for _, x := range xs {
		if skipGrease && IsGREASE(x) {
			continue
		}
		parts = append(parts, strconv.Itoa(int(x)))
	}
	return strings.Join(parts, "-")
}

// JA3String is the pre-hash JA3 text.
func (h *ClientHello) JA3String() string {
	pf := make([]string, 0, len(h.PointFmts))
	for _, p := range h.PointFmts {
		pf = append(pf, strconv.Itoa(int(p)))
	}
	return fmt.Sprintf("%d,%s,%s,%s,%s", h.LegacyVersion,
		dec16(h.Ciphers, true), dec16(h.Extensions, true), dec16(h.Groups, true), strings.Join(pf, "-"))
}

// JA3 is the MD5 of JA3String.
func (h *ClientHello) JA3() string {
	s := md5.Sum([]byte(h.JA3String()))
	return hex.EncodeToString(s[:])
}

func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	}
	return "00"
}

func alnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func ja4ALPN(a []string) string {
	if len(a) == 0 || a[0] == "" {
		return "00"
	}
	s := a[0]
	f, l := s[0], s[len(s)-1]
	if alnum(f) && alnum(l) {
		return string([]byte{f, l})
	}
	return fmt.Sprintf("%x%x", f>>4, l&0xf)
}

func hex4(xs []uint16) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = fmt.Sprintf("%04x", x)
	}
	return out
}

func trunc12(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:12]
}

// JA4 returns the JA4 fingerprint (TCP transport).
func (h *ClientHello) JA4() string {
	var ciphers, exts []uint16
	for _, c := range h.Ciphers {
		if !IsGREASE(c) {
			ciphers = append(ciphers, c)
		}
	}
	nExt := 0
	for _, e := range h.Extensions {
		if IsGREASE(e) {
			continue
		}
		nExt++
		if e != extSNI && e != extALPN {
			exts = append(exts, e)
		}
	}
	sni := "i"
	if h.HasSNI && h.SNI != "" {
		sni = "d"
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", ja4Version(h.MaxVersion()), sni, min(len(ciphers), 99), min(nExt, 99), ja4ALPN(h.ALPN))
	b := "000000000000"
	if len(ciphers) > 0 {
		sorted := hex4(ciphers)
		sort.Strings(sorted)
		b = trunc12(strings.Join(sorted, ","))
	}
	c := "000000000000"
	if len(exts) > 0 {
		sorted := hex4(exts)
		sort.Strings(sorted)
		s := strings.Join(sorted, ",")
		if len(h.SigAlgs) > 0 {
			var sa []uint16
			for _, x := range h.SigAlgs {
				if !IsGREASE(x) {
					sa = append(sa, x)
				}
			}
			s += "_" + strings.Join(hex4(sa), ",")
		}
		c = trunc12(s)
	}
	return a + "_" + b + "_" + c
}
