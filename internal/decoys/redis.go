package decoys

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/PurdueBlueTeam/phylax/pools"
)

// readRESP reads one command: a RESP array of bulk strings or an inline line.
func readRESP(r *bufio.Reader) ([]string, error) {
	line, err := readBounded(r, 1024)
	if err != nil {
		return nil, err
	}
	if line == "" {
		return nil, nil
	}
	if line[0] != '*' {
		return strings.Fields(line), nil
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil || n < 0 || n > 16 {
		return nil, fmt.Errorf("redis: bad array length")
	}
	args := make([]string, 0, n)
	for range n {
		h, err := readBounded(r, 32)
		if err != nil || len(h) == 0 || h[0] != '$' {
			return nil, fmt.Errorf("redis: bad bulk header")
		}
		l, err := strconv.Atoi(h[1:])
		if err != nil || l < 0 || l > 1024 {
			return nil, fmt.Errorf("redis: bad bulk length")
		}
		buf := make([]byte, l+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:l]))
	}
	return args, nil
}

func readBounded(r *bufio.Reader, max int) (string, error) {
	var b []byte
	for {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if c == '\n' {
			return strings.TrimRight(string(b), "\r"), nil
		}
		if len(b) >= max {
			return "", fmt.Errorf("line too long")
		}
		b = append(b, c)
	}
}

// serveRedis behaves like a Redis with requirepass: everything but AUTH gets
// NOAUTH; a honey password authenticates and then sees an empty server.
func (m *Module) serveRedis(s *sess, c net.Conn) {
	vers := pools.Lines("redis_versions.txt")
	version := vers[m.bannerIdx%len(vers)]
	r := bufio.NewReaderSize(c, 4096)
	authed := false
	for {
		s.idle()
		args, err := readRESP(r)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		cmd := strings.ToUpper(args[0])
		if cmd == "AUTH" {
			user, pw := "default", ""
			switch len(args) {
			case 2:
				pw = args[1]
			case 3:
				user, pw = args[1], args[2]
			}
			_, ok := s.credential(user, pw, "redis_auth")
			s.pause()
			if ok {
				authed = true
				_, _ = c.Write([]byte("+OK\r\n"))
			} else {
				_, _ = c.Write([]byte("-WRONGPASS invalid username-password pair or user is disabled.\r\n"))
			}
			if s.tooManyAttempts() {
				return
			}
			continue
		}
		if !s.command(strings.Join(args, " ")) {
			return
		}
		s.pause()
		switch {
		case cmd == "QUIT":
			_, _ = c.Write([]byte("+OK\r\n"))
			return
		case !authed:
			_, _ = c.Write([]byte("-NOAUTH Authentication required.\r\n"))
		case cmd == "PING":
			_, _ = c.Write([]byte("+PONG\r\n"))
		case cmd == "INFO":
			body := "# Server\r\nredis_version:" + version + "\r\nos:Linux 5.15.0 x86_64\r\ntcp_port:6379\r\nconnected_clients:1\r\n"
			_, _ = fmt.Fprintf(c, "$%d\r\n%s\r\n", len(body), body)
		case cmd == "KEYS" || cmd == "CONFIG" || cmd == "SCAN":
			_, _ = c.Write([]byte("*0\r\n"))
		case cmd == "GET":
			_, _ = c.Write([]byte("$-1\r\n"))
		default:
			_, _ = c.Write([]byte("+OK\r\n"))
		}
	}
}
