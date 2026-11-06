package probe

import (
	"bytes"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// ntlmServer is a test-side NTLMv2 verifier written from MS-NLMP, separate
// from the client in ntlm.go (only the NTOWFv2 primitive is shared, and that
// is pinned to the spec's test vector below).
type ntlmServer struct {
	users      map[string]string // exact user name -> password
	targetName string
	// results of the last verification
	gotUser, gotDomain string
	sessionKey         []byte
}

var srvChallenge = []byte{1, 2, 3, 4, 5, 6, 7, 8}

func (s *ntlmServer) challenge(withTimestamp bool) []byte {
	tn := utf16le(s.targetName)
	av := func(id uint16, v []byte) []byte {
		b := make([]byte, 4, 4+len(v))
		binary.LittleEndian.PutUint16(b, id)
		binary.LittleEndian.PutUint16(b[2:], uint16(len(v)))
		return append(b, v...)
	}
	var ti []byte
	ti = append(ti, av(2, tn)...) // NbDomainName
	ti = append(ti, av(1, tn)...) // NbComputerName
	if withTimestamp {
		ti = append(ti, av(7, []byte{9, 9, 9, 9, 9, 9, 9, 9})...)
	}
	ti = append(ti, av(0, nil)...)
	out := make([]byte, 56)
	copy(out, ntlmSig)
	binary.LittleEndian.PutUint32(out[8:], 2)
	binary.LittleEndian.PutUint16(out[12:], uint16(len(tn)))
	binary.LittleEndian.PutUint16(out[14:], uint16(len(tn)))
	binary.LittleEndian.PutUint32(out[16:], 56)
	binary.LittleEndian.PutUint32(out[20:], ntlmScorerFlags)
	copy(out[24:], srvChallenge)
	binary.LittleEndian.PutUint16(out[40:], uint16(len(ti)))
	binary.LittleEndian.PutUint16(out[42:], uint16(len(ti)))
	binary.LittleEndian.PutUint32(out[44:], uint32(56+len(tn)))
	out[48], out[49], out[55] = 10, 0, 15
	return append(append(out, tn...), ti...)
}

func field(m []byte, off int) []byte {
	l := int(binary.LittleEndian.Uint16(m[off:]))
	o := int(binary.LittleEndian.Uint32(m[off+4:]))
	return m[o : o+l]
}

func (s *ntlmServer) verify(m []byte) bool {
	if len(m) < 72 || !bytes.HasPrefix(m, ntlmSig) || binary.LittleEndian.Uint32(m[8:]) != 3 {
		return false
	}
	nt := field(m, 20)
	s.gotDomain = fromUTF16LE(field(m, 28))
	s.gotUser = fromUTF16LE(field(m, 36))
	enc := field(m, 52)
	flags := binary.LittleEndian.Uint32(m[60:])
	pass, ok := s.users[s.gotUser]
	if !ok || len(nt) < 48 {
		return false
	}
	ntowf := NTOWFv2(pass, s.gotUser, s.gotDomain)
	proof := hmacMD5(ntowf, srvChallenge, nt[16:])
	if !bytes.Equal(proof, nt[:16]) {
		return false
	}
	base := hmacMD5(ntowf, proof)
	s.sessionKey = base
	if flags&ntlmKeyExch != 0 {
		c, _ := rc4.NewCipher(base)
		k := make([]byte, len(enc))
		c.XORKeyStream(k, enc)
		s.sessionKey = k
	}
	return true
}

func TestNTOWFv2SpecVector(t *testing.T) {
	// MS-NLMP 4.2.4.1.1: NTOWFv2("User", "Password", "Domain")
	got := hex.EncodeToString(NTOWFv2("Password", "User", "Domain"))
	if got != "0c868a403bfd7a93a3001ef22ef02e3f" {
		t.Fatalf("NTOWFv2 = %s", got)
	}
}

func TestNTLMClientAgainstServer(t *testing.T) {
	for _, ts := range []bool{true, false} {
		s := &ntlmServer{users: map[string]string{"alice": "pw"}, targetName: "SRV1"}
		c := &ntlmClient{user: "alice", pass: "pw", useServerTarget: true}
		neg := c.Negotiate()
		if binary.LittleEndian.Uint32(neg[12:]) != 0xe2888215 {
			t.Errorf("negotiate flags %#x, want the scorer's 0xe2888215", binary.LittleEndian.Uint32(neg[12:]))
		}
		auth, err := c.Authenticate(s.challenge(ts))
		if err != nil {
			t.Fatal(err)
		}
		if !s.verify(auth) {
			t.Fatalf("server rejected a correct NTLMv2 response (timestamp=%v)", ts)
		}
		if s.gotDomain != "SRV1" {
			t.Errorf("empty domain must become the server's TargetName, got %q", s.gotDomain)
		}
		if !bytes.Equal(s.sessionKey, c.signingKey) {
			t.Error("exported session key mismatch (KEY_EXCH)")
		}
		bad := &ntlmClient{user: "alice", pass: "wrong", useServerTarget: true}
		bad.Negotiate()
		a2, _ := bad.Authenticate(s.challenge(ts))
		if s.verify(a2) {
			t.Fatal("wrong password accepted")
		}
	}
	// WinRM keeps an empty domain
	s := &ntlmServer{users: map[string]string{"alice": "pw"}, targetName: "SRV1"}
	c := &ntlmClient{user: "alice", pass: "pw"}
	c.Negotiate()
	a, _ := c.Authenticate(s.challenge(true))
	if !s.verify(a) || s.gotDomain != "" {
		t.Errorf("domain %q", s.gotDomain)
	}
}
