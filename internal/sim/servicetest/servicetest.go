// Package servicetest provides minimal in-test implementations of the
// services the scorer simulator and the check-discovery tests exercise:
// HTTP, HTTPS, SMTP + POP3, DNS (UDP), FTP, TFTP, NTP and a TCP banner
// server. Content is deterministic so ground truth is computable.
package servicetest

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Config customizes the served content. Zero fields use the defaults.
type Config struct {
	// HTTPBody is the body for GET <path> on the HTTP and HTTPS servers.
	// Default: "page:<path>\n".
	HTTPBody func(path string) string
	// FTPListing is the LIST/RETR data. Default: "a.txt 1\nb.txt 2\n".
	FTPListing string
	// TFTPFile is the file served by RRQ. Default: 720 bytes.
	TFTPFile string
	// Banner is written on connect by the TCP banner server.
	// Default: "SSH-2.0-OpenSSH_8.9\n".
	Banner string
	// DNSAnswer is the A record answered for any query. Default 10.2.3.4.
	DNSAnswer string
}

// Servers is the full in-test service set.
type Servers struct {
	HTTP   *httptest.Server
	HTTPS  *httptest.Server
	SMTP   string // host:port
	POP3   string // host:port
	DNS    string // host:port (UDP)
	FTP    string // host:port
	TFTP   string // host:port (UDP)
	NTP    string // host:port (UDP)
	Banner string // host:port

	cfg Config

	mu   sync.Mutex
	msgs []string
	reqs []Req
	clos []func()
}

// New starts all services on loopback with ephemeral ports.
func New(t testing.TB, cfg Config) *Servers {
	t.Helper()
	if cfg.HTTPBody == nil {
		cfg.HTTPBody = func(path string) string { return "page:" + path + "\n" }
	}
	if cfg.FTPListing == "" {
		cfg.FTPListing = "a.txt 1\nb.txt 2\n"
	}
	if cfg.TFTPFile == "" {
		cfg.TFTPFile = strings.Repeat("tftp-file-content-", 36) // 720 bytes
	}
	if cfg.Banner == "" {
		cfg.Banner = "SSH-2.0-OpenSSH_8.9\n"
	}
	if cfg.DNSAnswer == "" {
		cfg.DNSAnswer = "10.2.3.4"
	}
	s := &Servers{cfg: cfg}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.log("http", clientIP(r.RemoteAddr), portOf(r), map[string]any{
			"method": r.Method, "path": r.URL.Path,
		})
		w.Write([]byte(cfg.HTTPBody(r.URL.Path)))
	})
	s.HTTP = httptest.NewServer(h)
	s.HTTPS = httptest.NewUnstartedServer(h)
	s.HTTPS.StartTLS()

	// SMTP + POP3
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.SMTP, s.POP3 = l1.Addr().String(), l2.Addr().String()
	go s.serveSMTP(l1, portOfAddr(s.SMTP))
	go s.servePOP3(l2, portOfAddr(s.POP3))

	// DNS (UDP)
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.DNS = udp.LocalAddr().String()
	go s.serveDNS(udp, cfg.DNSAnswer, portOfAddr(s.DNS))
	s.clos = append(s.clos, func() { udp.Close() })

	// FTP
	l3, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.FTP = l3.Addr().String()
	go s.serveFTP(l3, cfg.FTPListing, portOfAddr(s.FTP))
	s.clos = append(s.clos, func() { l3.Close() })

	// TFTP (UDP)
	ut, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.TFTP = ut.LocalAddr().String()
	go s.serveTFTP(ut, cfg.TFTPFile, portOfAddr(s.TFTP))
	s.clos = append(s.clos, func() { ut.Close() })

	// NTP (UDP)
	un, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.NTP = un.LocalAddr().String()
	go s.serveNTP(un, portOfAddr(s.NTP))
	s.clos = append(s.clos, func() { un.Close() })

	// TCP banner
	l4, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.Banner = l4.Addr().String()
	go func() {
		for {
			c, err := l4.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte(cfg.Banner))
				io.Copy(io.Discard, c)
			}(c)
		}
	}()
	s.clos = append(s.clos, func() { l4.Close() })

	t.Cleanup(s.Close)
	return s
}

// Close stops all services.
func (s *Servers) Close() {
	for _, f := range s.clos {
		f()
	}
	s.HTTP.Close()
	s.HTTPS.Close()
}

// Body returns the body the HTTP/HTTPS servers answer for path.
func (s *Servers) Body(path string) string { return s.cfg.HTTPBody(path) }

// Listing returns the FTP listing content.
func (s *Servers) Listing() string { return s.cfg.FTPListing }

// TFTPContent returns the TFTP file content.
func (s *Servers) TFTPContent() string { return s.cfg.TFTPFile }

// DNSAnswer returns the answered A record.
func (s *Servers) DNSAnswer() string { return s.cfg.DNSAnswer }

// MailCount is the number of messages queued via SMTP.
func (s *Servers) MailCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.msgs)
}

// Messages returns the queued messages (headers + body, CRLF normalized).
func (s *Servers) Messages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.msgs...)
}

// Req is one request as seen by a test service server, in the shape the
// capture module's parsers emit (the T15 E2E feeds these to check
// discovery, standing in for capture on loopback — U-10).
type Req struct {
	Kind  string // http | smtp | pop3 | dns | ftp | tftp | ntp
	Src   string // peer address (IP)
	Port  int    // the server's port: the dport from the client's view
	T     time.Time
	Extra map[string]any // method, path, user, cmd, names, qtypes, file
}

func (s *Servers) log(kind, src string, port int, extra map[string]any) {
	s.mu.Lock()
	s.reqs = append(s.reqs, Req{Kind: kind, Src: src, Port: port, T: time.Now(), Extra: extra})
	s.mu.Unlock()
}

// Requests returns all requests since the start, oldest first.
func (s *Servers) Requests() []Req {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Req, len(s.reqs))
	copy(out, s.reqs)
	return out
}

func portOfAddr(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	p, _ := strconv.Atoi(port)
	return p
}

func clientIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}

func portOf(r *http.Request) int {
	_, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		return 0
	}
	p, _ := strconv.Atoi(port)
	return p
}

// DrainRequests returns the requests since the last drain, oldest first.
func (s *Servers) DrainRequests() []Req {
	s.mu.Lock()
	out := s.reqs
	s.reqs = nil
	s.mu.Unlock()
	return out
}

// ---------------------------------------------------------------- servers

type lineConn struct {
	c    net.Conn
	pend []byte
}

func (l *lineConn) writeLine(x string) { l.c.Write([]byte(x + "\r\n")) }

// readLine returns one CRLF-terminated line. Bytes beyond the first line
// in a segment are kept for the next call.
func (l *lineConn) readLine() (string, error) {
	tmp := make([]byte, 4096)
	for {
		if i := indexCRLF(l.pend); i >= 0 {
			line := string(l.pend[:i])
			l.pend = append([]byte(nil), l.pend[i+2:]...)
			return line, nil
		}
		n, err := l.c.Read(tmp)
		if n > 0 {
			l.pend = append(l.pend, tmp[:n]...)
		}
		if err != nil {
			return "", err
		}
	}
}

func indexCRLF(b []byte) int {
	for i := 0; i+1 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return i
		}
	}
	return -1
}

func splitCmd(s string) (string, string) {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], strings.TrimSpace(s[i+1:])
	}
	return s, ""
}

func (s *Servers) serveSMTP(l net.Listener, port int) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		src := clientIP(c.RemoteAddr().String())
		go func(c net.Conn) {
			defer c.Close()
			lc := &lineConn{c: c}
			lc.writeLine("220 mail.phylax.test ESMTP")
			for {
				line, err := lc.readLine()
				if err != nil {
					return
				}
				cmd, arg := splitCmd(line)
				switch strings.ToUpper(cmd) {
				case "EHLO", "HELO":
					lc.writeLine("250-mail.phylax.test")
					lc.writeLine("250 OK")
				case "MAIL":
					user := strings.TrimPrefix(arg, "FROM:")
					user = strings.Trim(user, " <>\t")
					s.log("smtp", src, port, map[string]any{"cmd": "MAIL", "user": user})
					lc.writeLine("250 OK")
				case "DATA":
					lc.writeLine("354 End data with <CR><LF>.<CR><LF>")
					var body []string
					for {
						bl, err := lc.readLine()
						if err != nil {
							return
						}
						if bl == "." {
							break
						}
						body = append(body, bl)
					}
					s.mu.Lock()
					s.msgs = append(s.msgs, strings.Join(body, "\n"))
					s.mu.Unlock()
					lc.writeLine("250 OK queued")
				case "QUIT":
					lc.writeLine("221 Bye")
					return
				default:
					lc.writeLine("250 OK")
				}
			}
		}(c)
	}
}

func (s *Servers) servePOP3(l net.Listener, port int) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		src := clientIP(c.RemoteAddr().String())
		go func(c net.Conn) {
			defer c.Close()
			lc := &lineConn{c: c}
			lc.writeLine("+OK POP3 ready")
			user := ""
			for {
				line, err := lc.readLine()
				if err != nil {
					return
				}
				cmd, arg := splitCmd(line)
				switch strings.ToUpper(cmd) {
				case "USER":
					user = arg
					lc.writeLine("+OK")
				case "STAT":
					s.mu.Lock()
					n := len(s.msgs)
					s.mu.Unlock()
					lc.writeLine(fmt.Sprintf("+OK %d 1234", n))
				case "RETR":
					idx := 1
					if arg != "" {
						if v, e := strconv.Atoi(arg); e == nil {
							idx = v
						}
					}
					s.log("pop3", src, port, map[string]any{"cmd": "RETR", "user": user})
					s.mu.Lock()
					if idx < 1 || idx > len(s.msgs) {
						s.mu.Unlock()
						lc.writeLine("-ERR no such message")
						continue
					}
					msg := s.msgs[idx-1]
					s.mu.Unlock()
					lc.writeLine("+OK message follows")
					for _, ml := range strings.Split(msg, "\n") {
						lc.writeLine(ml)
					}
					lc.writeLine(".")
				case "QUIT":
					lc.writeLine("+OK bye")
					return
				default:
					lc.writeLine("+OK")
				}
			}
		}(c)
	}
}

func (s *Servers) serveDNS(udp net.PacketConn, answer string, port int) {
	buf := make([]byte, 512)
	rip := net.ParseIP(answer)
	for {
		udp.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := udp.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if n < 12 {
			continue
		}
		q := buf[:n]
		// end of the single question: walk the name, skip type/class
		pos := 12
		for pos < n-4 {
			l := int(q[pos])
			if l&0xc0 == 0xc0 {
				break
			}
			pos += 1 + l
			if l == 0 {
				break
			}
		}
		pos += 4
		if pos > n {
			continue // malformed question; the test queries are well-formed
		}
		name := dnsName(q[12:pos])
		qtype := "A"
		if pos+2 <= n {
			switch binary.BigEndian.Uint16(q[pos : pos+2]) {
			case 28:
				qtype = "AAAA"
			case 33:
				qtype = "SRV"
			}
		}
		s.log("dns", clientIP(addr.String()), port, map[string]any{
			"names": []any{name}, "qtypes": []any{qtype},
		})
		resp := make([]byte, 0, 16+pos+14)
		resp = append(resp, q[0], q[1])
		resp = append(resp, 0x81, 0x80) // QR=1 RD=1 RA=1
		resp = append(resp, 0, 1, 0, 1, 0, 0, 0, 0)
		resp = append(resp, q[12:pos]...)
		resp = append(resp, 0xc0, 0x0c) // name pointer
		resp = append(resp, 0, 1, 0, 1) // A IN
		resp = append(resp, 0, 0, 0, 0) // ttl
		resp = append(resp, 0, 4)       // rdlen
		resp = append(resp, rip.To4()...)
		udp.WriteTo(resp, addr)
	}
}

// dnsName renders a wire-format DNS name (labels or pointer-terminated).
func dnsName(b []byte) string {
	var out []string
	pos := 0
	for pos < len(b) {
		l := int(b[pos])
		if l&0xc0 == 0xc0 {
			break
		}
		if l == 0 {
			break
		}
		pos++
		if pos+l > len(b) {
			break
		}
		out = append(out, string(b[pos:pos+l]))
		pos += l
	}
	return strings.Join(out, ".")
}

func (s *Servers) serveFTP(l net.Listener, listing string, port int) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		src := clientIP(c.RemoteAddr().String())
		go func(c net.Conn) {
			defer c.Close()
			lc := &lineConn{c: c}
			lc.writeLine("220 welcome")
			user := ""
			for {
				line, err := lc.readLine()
				if err != nil {
					return
				}
				cmd, arg := splitCmd(line)
				switch strings.ToUpper(cmd) {
				case "USER":
					user = arg
					lc.writeLine("331 need password")
				case "PASS":
					lc.writeLine("230 logged in")
				case "PASV":
					dl, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						return
					}
					dp := dl.Addr().(*net.TCPAddr)
					lc.writeLine(fmt.Sprintf("227 Entering Passive Mode (127,0,0,1,%d,%d)", dp.Port>>8, dp.Port&0xff))
					go func() {
						dc, err := dl.Accept()
						if err != nil {
							return
						}
						defer dc.Close()
						dc.Write([]byte(listing))
					}()
				case "LIST", "RETR":
					s.log("ftp", src, port, map[string]any{"cmd": cmd, "user": user})
					lc.writeLine("150 opening data connection")
					lc.writeLine("226 transfer complete")
				case "QUIT":
					lc.writeLine("221 bye")
					return
				default:
					lc.writeLine("200 OK")
				}
			}
		}(c)
	}
}

func (s *Servers) serveTFTP(udp net.PacketConn, content string, port int) {
	buf := make([]byte, 2048)
	for {
		n, addr, err := udp.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < 4 || buf[0] != 0 || buf[1] != 1 {
			continue // RRQ only
		}
		file := strings.SplitN(string(buf[4:]), "\x00", 2)[0]
		s.log("tftp", clientIP(addr.String()), port, map[string]any{"file": file})
		data := []byte(content)
		block := 1
		for {
			start := (block - 1) * 512
			if start >= len(data) {
				break
			}
			end := start + 512
			if end > len(data) {
				end = len(data)
			}
			chunk := data[start:end]
			pkt := make([]byte, 4+len(chunk))
			pkt[0], pkt[1] = 0, 3 // DATA
			binary.BigEndian.PutUint16(pkt[2:], uint16(block))
			copy(pkt[4:], chunk)
			udp.WriteTo(pkt, addr)
			if len(chunk) < 512 {
				break
			}
			// wait for the ACK, retransmitting the block on timeout
			for {
				udp.SetReadDeadline(time.Now().Add(time.Second))
				an, anaddr, e := udp.ReadFrom(buf)
				if e != nil {
					if ne, ok := e.(net.Error); ok && ne.Timeout() {
						udp.WriteTo(pkt, anaddr)
						continue
					}
					return
				}
				if an >= 4 && buf[0] == 0 && buf[1] == 4 {
					break
				}
			}
			block++
		}
	}
}

func (s *Servers) serveNTP(udp net.PacketConn, port int) {
	buf := make([]byte, 48)
	for {
		n, addr, err := udp.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < 48 {
			continue
		}
		s.log("ntp", clientIP(addr.String()), port, nil)
		resp := make([]byte, 48)
		resp[0] = 0x24 // LI=0 VN=3 mode=4 (server)
		now := time.Now()
		sec := uint32(now.Unix() + 2208988800)
		frac := uint32(float64(now.Nanosecond()) * (1 << 32) / 1e9)
		binary.BigEndian.PutUint32(resp[32:], sec)
		binary.BigEndian.PutUint32(resp[36:], frac)
		binary.BigEndian.PutUint32(resp[40:], sec)
		binary.BigEndian.PutUint32(resp[44:], frac)
		udp.WriteTo(resp, addr)
	}
}
