package decoys

import (
	"bufio"
	"net"

	"github.com/PurdueBlueTeam/phylax/pools"
)

// telnetFilter strips telnet IAC negotiation from the byte stream.
type telnetFilter struct{ r *bufio.Reader }

func (f telnetFilter) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if n > 0 && f.r.Buffered() == 0 {
			break
		}
		b, err := f.r.ReadByte()
		if err != nil {
			return n, err
		}
		if b != 0xff {
			p[n] = b
			n++
			continue
		}
		c, err := f.r.ReadByte()
		if err != nil {
			return n, err
		}
		switch {
		case c == 0xff:
			p[n] = 0xff
			n++
		case c >= 251 && c <= 254: // WILL WONT DO DONT + option
			if _, err := f.r.ReadByte(); err != nil {
				return n, err
			}
		case c == 250: // SB ... IAC SE
			for i := 0; i < 256; i++ {
				x, err := f.r.ReadByte()
				if err != nil {
					return n, err
				}
				if x == 0xff {
					if y, _ := f.r.ReadByte(); y == 240 {
						break
					}
				}
			}
		}
	}
	return n, nil
}

type rw struct {
	r *bufio.Reader
	c net.Conn
}

func (x rw) Read(p []byte) (int, error)  { return x.r.Read(p) }
func (x rw) Write(p []byte) (int, error) { return x.c.Write(p) }

// serveTelnet presents a login prompt; after AcceptAfter attempts (or on a
// honey credential) it hands over the fake shell.
func (m *Module) serveTelnet(s *sess, c net.Conn) {
	br := bufio.NewReaderSize(telnetFilter{bufio.NewReaderSize(c, 4096)}, 4096)
	banners := pools.Lines("telnet_banners.txt")
	_, _ = c.Write([]byte{255, 251, 1, 255, 251, 3}) // IAC WILL ECHO, WILL SGA: we echo
	_, _ = c.Write([]byte("\r\n" + banners[m.bannerIdx%len(banners)] + "\r\n\r\n"))
	for !s.tooManyAttempts() {
		_, _ = c.Write([]byte(m.cfg.Host + " login: "))
		s.idle()
		user, err := readLine(br, c, true)
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("Password: "))
		s.idle()
		pw, err := readLine(br, c, false)
		_, _ = c.Write([]byte("\r\n"))
		if err != nil {
			return
		}
		_, matched := s.credential(user, pw, "password")
		s.mu.Lock()
		n := s.attempts
		s.mu.Unlock()
		if matched || n >= m.cfg.AcceptAfter {
			sh := NewShell(m.cfg.Host, safeUser(user))
			_, _ = c.Write([]byte("\r\nLast login: Tue Mar  5 09:58:17 from 10.0.0.5\r\n"))
			m.shellLoop(s, rw{br, c}, sh)
			return
		}
		s.pause()
		_, _ = c.Write([]byte("Login incorrect\r\n\r\n"))
	}
}
