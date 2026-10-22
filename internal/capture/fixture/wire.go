package fixture

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"unicode/utf16"
)

func u16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

// ---- NTLM ----

// NTLMNegotiate builds a type 1 message.
func NTLMNegotiate(flags uint32) []byte {
	b := make([]byte, 40)
	copy(b, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(b[8:], 1)
	binary.LittleEndian.PutUint32(b[12:], flags)
	binary.LittleEndian.PutUint32(b[16+4:], 40) // empty domain field offset
	binary.LittleEndian.PutUint32(b[24+4:], 40)
	b[32], b[33] = 10, 0
	b[34], b[35] = 0x61, 0x4a // build 19041
	b[39] = 15
	return b
}

// NTLMChallenge builds a type 2 message naming the server.
func NTLMChallenge(target, nbComputer, dnsComputer string, flags uint32) []byte {
	tn := u16le(target)
	av := func(id uint16, v string) []byte {
		x := u16le(v)
		h := make([]byte, 4)
		binary.LittleEndian.PutUint16(h, id)
		binary.LittleEndian.PutUint16(h[2:], uint16(len(x)))
		return append(h, x...)
	}
	var ti []byte
	ti = append(ti, av(2, target)...)
	ti = append(ti, av(1, nbComputer)...)
	ti = append(ti, av(3, dnsComputer)...)
	ti = append(ti, 0, 0, 0, 0)
	b := make([]byte, 56)
	copy(b, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(b[8:], 2)
	binary.LittleEndian.PutUint16(b[12:], uint16(len(tn)))
	binary.LittleEndian.PutUint16(b[14:], uint16(len(tn)))
	binary.LittleEndian.PutUint32(b[16:], 56)
	binary.LittleEndian.PutUint32(b[20:], flags)
	binary.LittleEndian.PutUint16(b[40:], uint16(len(ti)))
	binary.LittleEndian.PutUint16(b[42:], uint16(len(ti)))
	binary.LittleEndian.PutUint32(b[44:], uint32(56+len(tn)))
	b[48], b[49] = 10, 0
	b = append(b, tn...)
	return append(b, ti...)
}

// NTLMAuthenticate builds a type 3 message. The LM/NT responses are filler.
func NTLMAuthenticate(domain, user, workstation string, flags uint32) []byte {
	d, u, w := u16le(domain), u16le(user), u16le(workstation)
	const hdr = 72
	b := make([]byte, hdr)
	copy(b, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(b[8:], 3)
	off := hdr
	put := func(at int, v []byte) {
		binary.LittleEndian.PutUint16(b[at:], uint16(len(v)))
		binary.LittleEndian.PutUint16(b[at+2:], uint16(len(v)))
		binary.LittleEndian.PutUint32(b[at+4:], uint32(off))
		off += len(v)
	}
	var body []byte
	nt := make([]byte, 24)
	put(12, nt[:0]) // LM empty
	put(20, nt)     // NT filler
	body = append(body, nt...)
	put(28, d)
	body = append(body, d...)
	put(36, u)
	body = append(body, u...)
	put(44, w)
	body = append(body, w...)
	put(52, nil)
	binary.LittleEndian.PutUint32(b[60:], flags)
	b[64], b[65] = 10, 0
	b[66], b[67] = 0x61, 0x4a
	b[71] = 15
	return append(b, body...)
}

// ---- SMB2 ----

// NB wraps an SMB message in a NetBIOS session header.
func NB(msg []byte) []byte {
	return append([]byte{0, byte(len(msg) >> 16), byte(len(msg) >> 8), byte(len(msg))}, msg...)
}

// SMB2Header builds the 64-byte header.
func SMB2Header(cmd uint16, resp bool, status uint32, msgID uint64, tree uint32, sess uint64) []byte {
	h := make([]byte, 64)
	copy(h, "\xfeSMB")
	binary.LittleEndian.PutUint16(h[4:], 64)
	binary.LittleEndian.PutUint32(h[8:], status)
	binary.LittleEndian.PutUint16(h[12:], cmd)
	binary.LittleEndian.PutUint16(h[14:], 1)
	if resp {
		binary.LittleEndian.PutUint32(h[16:], 1)
	}
	binary.LittleEndian.PutUint64(h[24:], msgID)
	binary.LittleEndian.PutUint32(h[36:], tree)
	binary.LittleEndian.PutUint64(h[40:], sess)
	return h
}

// SMB2NegotiateReq lists dialects.
func SMB2NegotiateReq(dialects ...uint16) []byte {
	b := make([]byte, 36+2*len(dialects))
	binary.LittleEndian.PutUint16(b, 36)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(dialects)))
	for i, d := range dialects {
		binary.LittleEndian.PutUint16(b[36+2*i:], d)
	}
	return NB(append(SMB2Header(0, false, 0, 0, 0, 0), b...))
}

// SMB2NegotiateResp selects a dialect.
func SMB2NegotiateResp(dialect uint16) []byte {
	b := make([]byte, 64)
	binary.LittleEndian.PutUint16(b, 65)
	binary.LittleEndian.PutUint16(b[4:], dialect)
	return NB(append(SMB2Header(0, true, 0, 0, 0, 0), b...))
}

// SPNEGOWrap prefixes an NTLM message with a fake GSS-API header; the parser
// finds the NTLMSSP signature rather than decoding ASN.1.
func SPNEGOWrap(ntlm []byte) []byte {
	return append([]byte{0x60, 0x82, 0x01, 0x00, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x30}, ntlm...)
}

// SMB2SessionSetup builds a request (resp=false) or response carrying a blob.
func SMB2SessionSetup(resp bool, status uint32, msgID uint64, sess uint64, blob []byte) []byte {
	b := make([]byte, 24)
	if !resp {
		binary.LittleEndian.PutUint16(b, 25)
		binary.LittleEndian.PutUint16(b[12:], 64+24)
		binary.LittleEndian.PutUint16(b[14:], uint16(len(blob)))
	} else {
		binary.LittleEndian.PutUint16(b, 9)
		binary.LittleEndian.PutUint16(b[4:], 64+8)
		binary.LittleEndian.PutUint16(b[6:], uint16(len(blob)))
		b = b[:8]
	}
	return NB(append(append(SMB2Header(1, resp, status, msgID, 0, sess), b...), blob...))
}

// SMB2TreeConnect requests a tree.
func SMB2TreeConnect(msgID uint64, sess uint64, path string) []byte {
	p := u16le(path)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint16(b, 9)
	binary.LittleEndian.PutUint16(b[4:], 64+8)
	binary.LittleEndian.PutUint16(b[6:], uint16(len(p)))
	return NB(append(append(SMB2Header(3, false, 0, msgID, 0, sess), b...), p...))
}

// SMB2Create requests a file open.
func SMB2Create(msgID uint64, tree uint32, sess uint64, name string) []byte {
	p := u16le(name)
	b := make([]byte, 56)
	binary.LittleEndian.PutUint16(b, 57)
	binary.LittleEndian.PutUint16(b[44:], 64+56)
	binary.LittleEndian.PutUint16(b[46:], uint16(len(p)))
	return NB(append(append(SMB2Header(5, false, 0, msgID, tree, sess), b...), p...))
}

// SMB2ReadResp is a successful read response carrying n data bytes.
func SMB2ReadResp(msgID uint64, tree uint32, sess uint64, n int) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint16(b, 17)
	b[2] = 64 + 16
	binary.LittleEndian.PutUint32(b[4:], uint32(n))
	return NB(append(append(SMB2Header(8, true, 0, msgID, tree, sess), b...), make([]byte, n)...))
}

// SMB2Logoff is a logoff response (resp=true) or request.
func SMB2Logoff(resp bool, msgID uint64, sess uint64) []byte {
	b := []byte{4, 0, 0, 0}
	return NB(append(SMB2Header(2, resp, 0, msgID, 0, sess), b...))
}

// ---- TDS ----

func tdsPacket(typ byte, payload []byte) []byte {
	h := []byte{typ, 1, 0, 0, 0, 0, 1, 0}
	binary.BigEndian.PutUint16(h[2:], uint16(8+len(payload)))
	return append(h, payload...)
}

// TDSPrelogin builds a pre-login packet (server=true gives the reply form).
func TDSPrelogin(server bool, ver [6]byte, enc byte, instance string) []byte {
	type opt struct {
		tok byte
		val []byte
	}
	opts := []opt{{0, ver[:]}, {1, []byte{enc}}, {2, append([]byte(instance), 0)}}
	hl := 5*len(opts) + 1
	var h, d []byte
	for _, o := range opts {
		h = append(h, o.tok, byte((hl+len(d))>>8), byte(hl+len(d)), byte(len(o.val)>>8), byte(len(o.val)))
		d = append(d, o.val...)
	}
	h = append(h, 0xFF)
	typ := byte(0x12)
	if server {
		typ = 0x04
	}
	return tdsPacket(typ, append(h, d...))
}

// TDSLogin7 builds a Login7 packet with a SQL (non-integrated) login.
func TDSLogin7(host, user, pass, app, server, lib, db string) []byte {
	strs := [][]byte{u16le(host), u16le(user), nil, u16le(app), u16le(server), nil, u16le(lib), nil, u16le(db)}
	pw := u16le(pass)
	for i, c := range pw {
		pw[i] = (c<<4 | c>>4) ^ 0xA5 // TDS obfuscation: swap nibbles, then XOR 0xA5
	}
	strs[2] = pw
	// order of offset/length pairs in the fixed part: host, user, pass, app, server, unused, lib, lang, db
	fixed := make([]byte, 94)
	binary.LittleEndian.PutUint32(fixed[4:], 0x74000004)
	binary.LittleEndian.PutUint32(fixed[8:], 4096)
	fixed[25] = 0x00
	off := len(fixed)
	var body []byte
	for i, s := range strs {
		at := 36 + 4*i
		binary.LittleEndian.PutUint16(fixed[at:], uint16(off+len(body)))
		binary.LittleEndian.PutUint16(fixed[at+2:], uint16(len(s)/2))
		body = append(body, s...)
	}
	m := append(fixed, body...)
	binary.LittleEndian.PutUint32(m, uint32(len(m)))
	return tdsPacket(0x10, m)
}

// TDSLoginAck is a successful login response.
func TDSLoginAck() []byte {
	ack := []byte{0xAD, 0x0B, 0x00, 1, 0x74, 0, 0, 4, 2, 'S', 0, 0, 0, 0, 0}
	ack[1] = byte(len(ack) - 3)
	done := append([]byte{0xFD}, make([]byte, 12)...)
	return tdsPacket(4, append(ack, done...))
}

// TDSLoginError is a failed login response (error 18456).
func TDSLoginError() []byte {
	body := make([]byte, 4+1+1+2+2*5+1+1)
	binary.LittleEndian.PutUint32(body, 18456)
	e := append([]byte{0xAA, byte(len(body)), 0}, body...)
	done := append([]byte{0xFD}, make([]byte, 12)...)
	return tdsPacket(4, append(e, done...))
}

// TDSBatch is a SQL batch with ALL_HEADERS.
func TDSBatch(sql string) []byte {
	h := make([]byte, 22)
	binary.LittleEndian.PutUint32(h, 22)
	return tdsPacket(1, append(h, u16le(sql)...))
}

// ---- DNS ----

func dnsName(n string) []byte {
	var b []byte
	for _, l := range strings.Split(strings.TrimSuffix(n, "."), ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

// DNSQuery builds a query with RD set and optional EDNS.
func DNSQuery(id uint16, name string, qtype uint16, edns bool) []byte {
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h, id)
	binary.BigEndian.PutUint16(h[2:], 0x0100)
	binary.BigEndian.PutUint16(h[4:], 1)
	if edns {
		binary.BigEndian.PutUint16(h[10:], 1)
	}
	q := append(dnsName(name), byte(qtype>>8), byte(qtype), 0, 1)
	b := append(h, q...)
	if edns {
		b = append(b, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0)
	}
	return b
}

// DNSResponseA answers an A query with one address using name compression.
func DNSResponseA(id uint16, name string, ip [4]byte) []byte {
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h, id)
	binary.BigEndian.PutUint16(h[2:], 0x8180)
	binary.BigEndian.PutUint16(h[4:], 1)
	binary.BigEndian.PutUint16(h[6:], 1)
	b := append(h, append(dnsName(name), 0, 1, 0, 1)...)
	b = append(b, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
	return append(b, ip[:]...)
}

// ---- SSH ----

// SSHPacket frames a payload as an unencrypted SSH binary packet.
func SSHPacket(payload []byte) []byte {
	pad := 8 - (len(payload)+5)%8
	if pad < 4 {
		pad += 8
	}
	b := make([]byte, 4, 5+len(payload)+pad)
	binary.BigEndian.PutUint32(b, uint32(1+len(payload)+pad))
	b = append(b, byte(pad))
	b = append(b, payload...)
	return append(b, make([]byte, pad)...)
}

// SSHKexInit builds a KEXINIT packet from comma-joined name lists in wire order:
// kex, hostkey, enc c2s, enc s2c, mac c2s, mac s2c, comp c2s, comp s2c.
func SSHKexInit(cookie byte, lists ...string) []byte {
	p := []byte{20}
	p = append(p, make([]byte, 16)...)
	for i := range p[1:17] {
		p[1+i] = cookie
	}
	for i := 0; i < 10; i++ {
		s := ""
		if i < len(lists) {
			s = lists[i]
		}
		p = binary.BigEndian.AppendUint32(p, uint32(len(s)))
		p = append(p, s...)
	}
	p = append(p, 0, 0, 0, 0, 0)
	return SSHPacket(p)
}

// SSHNewKeys is the NEWKEYS packet.
func SSHNewKeys() []byte { return SSHPacket([]byte{21}) }

// MD5Hex of a string.
func MD5Hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}
