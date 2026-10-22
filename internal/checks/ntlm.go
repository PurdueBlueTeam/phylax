package checks

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:staticcheck // NTLM requires MD4
)

// NTLMSSP negotiate flags used by the scorer's client (0xe2888215).
const (
	ntlmUnicode     = 0x00000001
	ntlmReqTarget   = 0x00000004
	ntlmSign        = 0x00000010
	ntlmNTLM        = 0x00000200
	ntlmAlwaysSign  = 0x00008000
	ntlmTargetInfo  = 0x00800000
	ntlmExtSession  = 0x00080000
	ntlmVersion     = 0x02000000
	ntlmKeyExch     = 0x20000000
	ntlm128         = 0x40000000
	ntlm56          = 0x80000000
	ntlmScorerFlags = ntlm56 | ntlm128 | ntlmKeyExch | ntlmVersion | ntlmTargetInfo | ntlmExtSession | ntlmAlwaysSign | ntlmNTLM | ntlmSign | ntlmReqTarget | ntlmUnicode
)

var ntlmSig = []byte("NTLMSSP\x00")

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func fromUTF16LE(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

func hmacMD5(key []byte, parts ...[]byte) []byte {
	h := hmac.New(md5.New, key)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// NTOWFv2 per MS-NLMP 3.3.2.
func NTOWFv2(pass, user, domain string) []byte {
	h := md4.New()
	h.Write(utf16le(pass))
	return hmacMD5(h.Sum(nil), utf16le(strings.ToUpper(user)+domain))
}

// ntlmClient is the client half of an NTLMv2 exchange.
type ntlmClient struct {
	user, pass, domain string
	// UseServerTarget copies the challenge's TargetName into an empty domain,
	// as the SMB client does; WinRM keeps the empty domain.
	useServerTarget bool
	flags           uint32
	// SigningKey is the exported session key after Authenticate.
	signingKey []byte
	now        func() time.Time
}

func (n *ntlmClient) Negotiate() []byte {
	fl := n.flags
	if fl == 0 {
		fl = ntlmScorerFlags
	}
	b := make([]byte, 40)
	copy(b, ntlmSig)
	binary.LittleEndian.PutUint32(b[8:], 1)
	binary.LittleEndian.PutUint32(b[12:], fl)
	// empty domain and workstation fields point at the end of the fixed part
	binary.LittleEndian.PutUint32(b[20:], 40)
	binary.LittleEndian.PutUint32(b[28:], 40)
	b[32], b[33] = 10, 0 // Version 10.0
	b[39] = 15
	n.flags = fl
	return b
}

// avPair walks MS-NLMP AV_PAIRs.
func avPairs(b []byte) map[uint16][]byte {
	out := map[uint16][]byte{}
	for len(b) >= 4 {
		id, l := binary.LittleEndian.Uint16(b), int(binary.LittleEndian.Uint16(b[2:]))
		if id == 0 || 4+l > len(b) {
			break
		}
		out[id] = b[4 : 4+l]
		b = b[4+l:]
	}
	return out
}

func secBuf(msg []byte, off int) ([]byte, error) {
	if off+8 > len(msg) {
		return nil, errors.New("ntlm: short message")
	}
	l := int(binary.LittleEndian.Uint16(msg[off:]))
	o := int(binary.LittleEndian.Uint32(msg[off+4:]))
	if o+l > len(msg) {
		return nil, errors.New("ntlm: bad security buffer")
	}
	return msg[o : o+l], nil
}

// Authenticate consumes the server's CHALLENGE and returns the AUTHENTICATE message.
func (n *ntlmClient) Authenticate(challenge []byte) ([]byte, error) {
	if len(challenge) < 48 || !bytes.HasPrefix(challenge, ntlmSig) || binary.LittleEndian.Uint32(challenge[8:]) != 2 {
		return nil, errors.New("ntlm: not a challenge message")
	}
	target, err := secBuf(challenge, 12)
	if err != nil {
		return nil, err
	}
	sflags := binary.LittleEndian.Uint32(challenge[20:])
	srvChal := challenge[24:32]
	targetInfo, err := secBuf(challenge, 40)
	if err != nil {
		return nil, err
	}
	domain := n.domain
	if domain == "" && n.useServerTarget {
		if sflags&ntlmUnicode != 0 {
			domain = fromUTF16LE(target)
		} else {
			domain = string(target)
		}
	}
	nowf := n.now
	if nowf == nil {
		nowf = time.Now
	}
	ts := make([]byte, 8)
	av := avPairs(targetInfo)
	hasTS := false
	if t, ok := av[7]; ok && len(t) == 8 {
		copy(ts, t)
		hasTS = true
	} else {
		binary.LittleEndian.PutUint64(ts, uint64(nowf().UnixNano()/100)+116444736000000000)
	}
	cliChal := make([]byte, 8)
	_, _ = rand.Read(cliChal)
	ntowf := NTOWFv2(n.pass, n.user, domain)
	temp := append([]byte{1, 1, 0, 0, 0, 0, 0, 0}, ts...)
	temp = append(temp, cliChal...)
	temp = append(temp, 0, 0, 0, 0)
	temp = append(temp, targetInfo...)
	temp = append(temp, 0, 0, 0, 0)
	proof := hmacMD5(ntowf, srvChal, temp)
	ntResp := append(append([]byte{}, proof...), temp...)
	lm := make([]byte, 24)
	if !hasTS {
		lm = append(hmacMD5(ntowf, srvChal, cliChal), cliChal...)
	}
	base := hmacMD5(ntowf, proof)
	exported, encKey := base, []byte(nil)
	fl := n.flags & sflags
	if fl&ntlmKeyExch != 0 {
		exported = make([]byte, 16)
		_, _ = rand.Read(exported)
		c, _ := rc4.NewCipher(base)
		encKey = make([]byte, 16)
		c.XORKeyStream(encKey, exported)
	}
	n.signingKey = exported
	if sflags&ntlmUnicode == 0 {
		return nil, errors.New("ntlm: server did not negotiate unicode")
	}
	// Build with the fixed part (no MIC): sig 8, type 4, six fields 8 each, flags 4, version 8 = 72.
	dom, usr, ws := utf16le(domain), utf16le(n.user), utf16le("WORKSTATION")
	fields := [][]byte{lm, ntResp, dom, usr, ws, encKey}
	out := make([]byte, 72)
	copy(out, ntlmSig)
	binary.LittleEndian.PutUint32(out[8:], 3)
	off := 72
	for i, f := range fields {
		p := 12 + 8*i
		binary.LittleEndian.PutUint16(out[p:], uint16(len(f)))
		binary.LittleEndian.PutUint16(out[p+2:], uint16(len(f)))
		binary.LittleEndian.PutUint32(out[p+4:], uint32(off))
		off += len(f)
	}
	binary.LittleEndian.PutUint32(out[60:], fl)
	out[64], out[65], out[71] = 10, 0, 15
	for _, f := range fields {
		out = append(out, f...)
	}
	return out, nil
}

// ---- SPNEGO (just enough to carry NTLMSSP) ----

var (
	oidSPNEGO = []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	oidNTLM   = []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
)

func derLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

func der(tag byte, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	return append(append([]byte{tag}, derLen(len(body))...), body...)
}

func spnegoInit(ntlm []byte) []byte {
	mechs := der(0xa0, der(0x30, oidNTLM))
	tok := der(0xa2, der(0x04, ntlm))
	return der(0x60, oidSPNEGO, der(0xa0, der(0x30, mechs, tok)))
}

func spnegoResp(ntlm []byte) []byte {
	return der(0xa1, der(0x30, der(0xa2, der(0x04, ntlm))))
}

// findNTLM extracts the NTLMSSP message from a SPNEGO blob (or a raw one).
func findNTLM(b []byte) []byte {
	if i := bytes.Index(b, ntlmSig); i >= 0 {
		return b[i:]
	}
	return nil
}
