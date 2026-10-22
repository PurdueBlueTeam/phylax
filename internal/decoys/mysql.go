package decoys

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/honeytokens"
	"github.com/PurdueBlueTeam/phylax/pools"
)

const maxMySQLPacket = 4096

func readMySQLPacket(c net.Conn) ([]byte, byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return nil, 0, err
	}
	n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	if n > maxMySQLPacket {
		return nil, 0, fmt.Errorf("mysql: packet too large")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(c, b)
	return b, h[3], err
}

func mysqlPacket(seq byte, payload []byte) []byte {
	n := len(payload)
	return append([]byte{byte(n), byte(n >> 8), byte(n >> 16), seq}, payload...)
}

// mysqlScramble computes the mysql_native_password response for a password.
func mysqlScramble(pw string, salt []byte) []byte {
	h1 := sha1.Sum([]byte(pw))
	h2 := sha1.Sum(h1[:])
	h := sha1.New()
	h.Write(salt)
	h.Write(h2[:])
	x := h.Sum(nil)
	out := make([]byte, 20)
	for i := range out {
		out[i] = h1[i] ^ x[i]
	}
	return out
}

type tokenLister interface{ Tokens() []honeytokens.Token }

// serveMySQL sends a protocol-10 handshake, records the username and auth
// response (cracking format $mysql$salt$response), recognises honey passwords
// by recomputing the scramble, and answers access denied.
func (m *Module) serveMySQL(s *sess, c net.Conn) {
	vers := pools.Lines("mysql_versions.txt")
	salt := make([]byte, 20)
	_, _ = rand.Read(salt)
	for i := range salt { // salt bytes must not be NUL
		salt[i] = salt[i]%94 + 33
	}
	var p []byte
	p = append(p, 0x0a)
	p = append(p, vers[m.bannerIdx%len(vers)]...)
	p = append(p, 0)
	p = binary.LittleEndian.AppendUint32(p, uint32(1000+m.bannerIdx%9000))
	p = append(p, salt[:8]...)
	p = append(p, 0)
	p = binary.LittleEndian.AppendUint16(p, 0xf7ff) // caps lower, no SSL
	p = append(p, 0x21)                             // utf8
	p = binary.LittleEndian.AppendUint16(p, 0x0002) // autocommit
	p = binary.LittleEndian.AppendUint16(p, 0x0008) // caps upper: PLUGIN_AUTH
	p = append(p, 21)
	p = append(p, make([]byte, 10)...)
	p = append(p, salt[8:]...)
	p = append(p, 0)
	p = append(p, "mysql_native_password\x00"...)
	if _, err := c.Write(mysqlPacket(0, p)); err != nil {
		return
	}
	s.idle()
	resp, seq, err := readMySQLPacket(c)
	if err != nil || len(resp) <= 32 { // SSLRequest or junk
		return
	}
	rest := resp[32:]
	i := indexNul(rest)
	if i < 0 {
		return
	}
	user := string(rest[:i])
	rest = rest[i+1:]
	var auth []byte
	if len(rest) > 0 {
		n := int(rest[0])
		if n <= len(rest)-1 {
			auth = rest[1 : 1+n]
		}
	}
	secret, method := "", "mysql_native_password"
	var matchedSecret string
	if l, ok := m.cfg.Tokens.(tokenLister); ok && len(auth) == 20 {
		for _, t := range l.Tokens() {
			if t.Secret == "" || (t.User != "" && !strings.EqualFold(t.User, user)) {
				continue
			}
			if string(mysqlScramble(t.Secret, salt)) == string(auth) {
				matchedSecret = t.Secret
				break
			}
		}
	}
	if matchedSecret != "" {
		secret = matchedSecret
	} else if len(auth) > 0 {
		secret = "$mysql$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(auth)
	}
	s.credential(user, secret, method)
	s.pause()
	host := s.src.String()
	using := "NO"
	if len(auth) > 0 {
		using = "YES"
	}
	msg := fmt.Sprintf("Access denied for user '%s'@'%s' (using password: %s)", clip(user), host, using)
	e := []byte{0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0'}
	e = append(e, msg...)
	_, _ = c.Write(mysqlPacket(seq+1, e))
}

func indexNul(b []byte) int {
	for i, x := range b {
		if x == 0 {
			return i
		}
	}
	return -1
}
