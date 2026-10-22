// Package ntlm parses NTLMSSP messages (types 1, 2 and 3) found inside SMB2
// SPNEGO blobs and HTTP Authorization headers. Only metadata is extracted: the
// LM/NT responses and session key are never read.
package ntlm

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// Signature starts every NTLMSSP message.
var Signature = []byte("NTLMSSP\x00")

// Message is a decoded NTLMSSP message.
type Message struct {
	Type        uint32
	Flags       uint32
	Domain      string // type 3: domain; type 1: supplied domain if any
	User        string // type 3
	Workstation string // type 3 (or type 1 if supplied)
	Target      string // type 2 target name
	NbComputer  string // type 2 AV pair 1
	NbDomain    string // AV pair 2
	DNSComputer string // AV pair 3
	DNSDomain   string // AV pair 4
	Version     [8]byte
	HasVersion  bool
}

const flagUnicode = 0x1
const flagVersion = 0x02000000

// Find returns the NTLMSSP message inside b (for example a SPNEGO token), or nil.
func Find(b []byte) []byte {
	i := bytes.Index(b, Signature)
	if i < 0 {
		return nil
	}
	return b[i:]
}

// FromHeader decodes an Authorization/WWW-Authenticate value such as
// "NTLM TlRMTVNT..." or "Negotiate TlRMTVNT...". It returns nil unless the
// token holds an NTLMSSP message.
func FromHeader(v string) []byte {
	v = strings.TrimSpace(v)
	sp := strings.IndexByte(v, ' ')
	if sp < 0 {
		return nil
	}
	scheme := strings.ToLower(v[:sp])
	if scheme != "ntlm" && scheme != "negotiate" {
		return nil
	}
	tok := strings.TrimSpace(v[sp+1:])
	if len(tok) > 16384 {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(tok)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(tok)
		if err != nil {
			return nil
		}
	}
	return Find(raw)
}

type field struct{ n, off int }

func getField(b []byte, at int) (field, bool) {
	if at+8 > len(b) {
		return field{}, false
	}
	n := int(binary.LittleEndian.Uint16(b[at:]))
	off := int(binary.LittleEndian.Uint32(b[at+4:]))
	if off < 0 || off > len(b) || n > len(b)-off {
		return field{}, false
	}
	return field{n, off}, true
}

func str(b []byte, f field, unicode bool) string {
	raw := b[f.off : f.off+f.n]
	if !unicode {
		out := make([]rune, 0, len(raw))
		for _, c := range raw {
			out = append(out, rune(c))
		}
		return string(out)
	}
	if len(raw)%2 == 1 {
		raw = raw[:len(raw)-1]
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	return string(utf16.Decode(u))
}

// Parse decodes one message starting at its signature.
func Parse(b []byte) (Message, bool) {
	var m Message
	if len(b) < 16 || !bytes.HasPrefix(b, Signature) {
		return m, false
	}
	m.Type = binary.LittleEndian.Uint32(b[8:])
	switch m.Type {
	case 1:
		m.Flags = binary.LittleEndian.Uint32(b[12:])
		uni := m.Flags&flagUnicode != 0
		if f, ok := getField(b, 16); ok && f.n > 0 {
			m.Domain = str(b, f, uni)
		}
		if f, ok := getField(b, 24); ok && f.n > 0 {
			m.Workstation = str(b, f, uni)
		}
		if m.Flags&flagVersion != 0 && len(b) >= 40 {
			copy(m.Version[:], b[32:40])
			m.HasVersion = true
		}
	case 2:
		if len(b) < 32 {
			return m, false
		}
		m.Flags = binary.LittleEndian.Uint32(b[20:])
		uni := m.Flags&flagUnicode != 0
		if f, ok := getField(b, 12); ok {
			m.Target = str(b, f, uni)
		}
		if len(b) >= 48 {
			if f, ok := getField(b, 40); ok {
				parseAV(b[f.off:f.off+f.n], &m)
			}
		}
		if m.Flags&flagVersion != 0 && len(b) >= 56 {
			copy(m.Version[:], b[48:56])
			m.HasVersion = true
		}
	case 3:
		if len(b) < 64 {
			return m, false
		}
		m.Flags = binary.LittleEndian.Uint32(b[60:])
		uni := m.Flags&flagUnicode != 0
		if f, ok := getField(b, 28); ok {
			m.Domain = str(b, f, uni)
		}
		if f, ok := getField(b, 36); ok {
			m.User = str(b, f, uni)
		}
		if f, ok := getField(b, 44); ok {
			m.Workstation = str(b, f, uni)
		}
		if m.Flags&flagVersion != 0 && len(b) >= 72 {
			copy(m.Version[:], b[64:72])
			m.HasVersion = true
		}
	default:
		return m, false
	}
	return m, true
}

func parseAV(b []byte, m *Message) {
	for len(b) >= 4 {
		id := binary.LittleEndian.Uint16(b)
		n := int(binary.LittleEndian.Uint16(b[2:]))
		b = b[4:]
		if n > len(b) {
			return
		}
		v := b[:n]
		b = b[n:]
		if id == 0 {
			return
		}
		f := field{n: len(v)}
		s := ""
		if id >= 1 && id <= 4 {
			s = str(v, f, true)
		}
		switch id {
		case 1:
			m.NbComputer = s
		case 2:
			m.NbDomain = s
		case 3:
			m.DNSComputer = s
		case 4:
			m.DNSDomain = s
		}
	}
}

// ServerNames returns the lower-cased names the server called itself in a type 2.
func (m Message) ServerNames() []string {
	var out []string
	for _, s := range []string{m.NbComputer, m.DNSComputer, m.Target} {
		if s != "" {
			out = append(out, strings.ToLower(s))
		}
	}
	return out
}
