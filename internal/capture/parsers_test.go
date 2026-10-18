package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func client() [16]byte {
	a := [16]byte{}
	copy(a[12:], []byte{10, 1, 2, 3})
	return a
}

func server() [16]byte {
	a := [16]byte{}
	copy(a[12:], []byte{10, 1, 2, 4})
	return a
}

var t0 = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

// TestMailSMTP: a full SMTP session as observed on the wire, fed in
// two directions with the framing a capture module produces.
func TestMailSMTP(t *testing.T) {
	p := NewMailParser()
	c, s := client(), server()
	cport, sport := uint16(40000), uint16(25)

	give := func(clientDir bool, b string, dt time.Duration) {
		p.Feed("smtp", c, cport, s, sport, clientDir, []byte(b), t0.Add(dt))
	}
	// greeting first (server, no pending command: must not panic)
	give(false, "220 mail.example ESMTP Postfix\r\n", 0)
	give(true, "EHLO scanner.example\r\n", time.Millisecond)
	give(false, "250-mail.example\r\n250-PIPELINING\r\n250 8BITMIME\r\n", 2*time.Millisecond)
	give(true, "MAIL FROM:<scorer@scorer.example>\r\n", 3*time.Millisecond)
	give(false, "250 2.1.0 Ok\r\n", 4*time.Millisecond)
	give(true, "RCPT TO:<postmaster@example.com>\r\n", 5*time.Millisecond)
	give(false, "250 2.1.5 Ok\r\n", 6*time.Millisecond)
	give(true, "DATA\r\n", 7*time.Millisecond)
	give(false, "354 End data with <CR><LF>.<CR><LF>\r\n", 8*time.Millisecond)
	// the DATA command pairs with 354; the body lines are client-side
	// and must not create commands
	give(true, "Subject: score\r\nFrom: scorer@scorer.example\r\n\r\nhello\r\n.\r\n", 9*time.Millisecond)
	give(false, "250 2.0.0 Ok: queued as 12345\r\n", 10*time.Millisecond)
	give(true, "QUIT\r\n", 11*time.Millisecond)
	give(false, "221 Bye\r\n", 12*time.Millisecond)

	out := p.Finish(t0.Add(10 * time.Second))
	if len(out) != 5 {
		t.Fatalf("got %d exchanges, want 5: %+v", len(out), out)
	}
	want := []struct{ cmd string; code int }{
		{"EHLO", 250}, {"MAIL", 250}, {"RCPT", 250}, {"DATA", 354}, {"QUIT", 221},
	}
	for i, w := range want {
		if out[i].Cmd != w.cmd || out[i].Code != w.code {
			t.Errorf("exchange %d: got %s %d, want %s %d", i, out[i].Cmd, out[i].Code, w.cmd, w.code)
		}
		if out[i].Proto != "smtp" {
			t.Errorf("exchange %d proto: %s", i, out[i].Proto)
		}
	}
	if out[1].User != "scorer@scorer.example" {
		t.Errorf("user: %q", out[1].User)
	}
	if out[1].Arg != "FROM:<scorer@scorer.example>" {
		t.Errorf("arg: %q", out[1].Arg)
	}
}

// TestMailSMTPAuthPlain: AUTH PLAIN carries the account base64-encoded
// (\0user\0pass).
func TestMailSMTPAuthPlain(t *testing.T) {
	p := NewMailParser()
	c, s := client(), server()
	cport, sport := uint16(40001), uint16(2587)
	// \0jdoe\0s3cret base64
	b64 := "AGpkb2UAczNjcmV0"
	p.Feed("smtp", c, cport, s, sport, false, []byte("220 x ESMTP\r\n"), t0)
	p.Feed("smtp", c, cport, s, sport, true, []byte("EHLO a\r\n"), t0)
	p.Feed("smtp", c, cport, s, sport, false, []byte("250 x\r\n"), t0)
	p.Feed("smtp", c, cport, s, sport, true, []byte("AUTH PLAIN "+b64+"\r\n"), t0)
	p.Feed("smtp", c, cport, s, sport, false, []byte("235 2.7.0 Authentication successful\r\n"), t0)
	out := p.Finish(t0.Add(10 * time.Second))
	if len(out) != 2 {
		t.Fatalf("got %d exchanges: %+v", len(out), out)
	}
	if out[1].Cmd != "AUTH" || out[1].User != "jdoe" || out[1].Code != 235 {
		t.Errorf("AUTH exchange: %+v", out[1])
	}
}

// TestMailPOP3: USER/PASS/LIST (multi-line)/RETR/QUIT.
func TestMailPOP3(t *testing.T) {
	p := NewMailParser()
	c, s := client(), server()
	cport, sport := uint16(40002), uint16(110)
	p.Feed("pop3", c, cport, s, sport, false, []byte("+OK mail ready\r\n"), t0)
	p.Feed("pop3", c, cport, s, sport, true, []byte("USER jdoe\r\n"), t0)
	p.Feed("pop3", c, cport, s, sport, false, []byte("+OK\r\n"), t0)
	p.Feed("pop3", c, cport, s, sport, true, []byte("PASS secret\r\n"), t0)
	p.Feed("pop3", c, cport, s, sport, false, []byte("+OK logged in\r\n"), t0)
	p.Feed("pop3", c, cport, s, sport, true, []byte("LIST\r\n"), t0)
	p.Feed("pop3", c, cport, s, sport, false, []byte("+OK 2 messages\r\n1 1024\r\n2 2048\r\n.\r\n"), t0)
	p.Feed("pop3", c, cport, s, sport, true, []byte("RETR 1\r\n"), t0)
	p.Feed("pop3", c, cport, s, sport, false, []byte("+OK 1024 octets\r\nFrom: a@b\r\n.\r\n"), t0)
	p.Feed("pop3", c, cport, s, sport, true, []byte("QUIT\r\n"), t0)
	p.Feed("pop3", c, cport, s, sport, false, []byte("+OK bye\r\n"), t0)

	out := p.Finish(t0.Add(10 * time.Second))
	if len(out) != 5 {
		t.Fatalf("got %d exchanges: %+v", len(out), out)
	}
	if out[0].Cmd != "USER" || out[0].User != "jdoe" {
		t.Errorf("USER: %+v", out[0])
	}
	if out[2].Cmd != "LIST" || !strings.HasPrefix(out[2].Rsp, "+OK 2 messages") {
		t.Errorf("LIST: %+v", out[2])
	}
}

// TestMailIMAP: LOGIN/SELECT/FETCH/LOGOUT with tagged commands.
func TestMailIMAP(t *testing.T) {
	p := NewMailParser()
	c, s := client(), server()
	cport, sport := uint16(40003), uint16(143)
	p.Feed("imap", c, cport, s, sport, false, []byte("* OK IMAP4rev1\r\n"), t0)
	p.Feed("imap", c, cport, s, sport, true, []byte("a1 LOGIN jdoe secret\r\n"), t0)
	p.Feed("imap", c, cport, s, sport, false, []byte("a1 OK LOGIN completed\r\n"), t0)
	p.Feed("imap", c, cport, s, sport, true, []byte("a2 SELECT INBOX\r\n"), t0)
	p.Feed("imap", c, cport, s, sport, false, []byte("* 5 EXISTS\r\na2 OK [READ-WRITE] SELECT completed\r\n"), t0)
	p.Feed("imap", c, cport, s, sport, true, []byte("a3 LOGOUT\r\n"), t0)
	p.Feed("imap", c, cport, s, sport, false, []byte("* BYE\r\na3 OK LOGOUT completed\r\n"), t0)

	out := p.Finish(t0.Add(10 * time.Second))
	if len(out) != 3 {
		t.Fatalf("got %d exchanges: %+v", len(out), out)
	}
	if out[0].Cmd != "LOGIN" || out[0].User != "jdoe" {
		t.Errorf("LOGIN: %+v", out[0])
	}
	if out[1].Cmd != "SELECT" || out[1].Arg != "INBOX" {
		t.Errorf("SELECT: %+v", out[1])
	}
}

// TestFTPDataLinkage: passive-mode RETR with the data channel linked:
// the exchange carries the byte count and the sha256 of the data.
func TestFTPDataLinkage(t *testing.T) {
	p := NewFTPParser()
	c, s := client(), server()
	cport, sport := uint16(40004), uint16(21)
	dport := uint16(50123) // client's passive port

	fc := func(isClient bool, b string) {
		p.FeedControl(c, cport, s, sport, isClient, []byte(b), t0)
	}
	fc(false, "220 FTP ready\r\n")
	fc(true, "USER jdoe\r\n")
	fc(false, "331 Password required\r\n")
	fc(true, "PASS secret\r\n")
	fc(false, "230 Logged in\r\n")
	fc(true, "PASV\r\n")
	fc(false, "227 Entering Passive Mode (10,1,2,3,195,203)\r\n") // 195*256+203 = 50123

	// data connection: server (10.1.2.4:60000) -> client (10.1.2.3:50123)
	ds := server()
	var dsp [16]byte // server-side ephemeral
	dsp[15] = 0
	k := p.MatchData(ds, uint16(60000), c, dport, t0)
	if k == (dataKey{}) {
		t.Fatal("data connection not matched")
	}
	payload := []byte("the file content\r\nsecond line\r\n")
	p.FeedData(k, payload, t0)

	fc(true, "RETR score.txt\r\n")
	fc(false, "150 Opening data connection\r\n")
	fc(false, "226 Transfer complete\r\n")

	out := p.Finish(t0.Add(10 * time.Second))
	// USER, PASS, PASV, RETR
	if len(out) != 4 {
		t.Fatalf("got %d exchanges: %+v", len(out), out)
	}
	retr := out[3]
	if retr.Cmd != "RETR" || retr.Code != 226 {
		t.Fatalf("RETR: %+v", retr)
	}
	if retr.Bytes != len(payload) {
		t.Errorf("bytes: %d", retr.Bytes)
	}
	sum := sha256.Sum256(payload)
	if retr.Hash != hex.EncodeToString(sum[:]) {
		t.Errorf("hash: %s", retr.Hash)
	}
	if out[0].User != "jdoe" {
		t.Errorf("user: %q", out[0].User)
	}
}

// TestFTPOriginalData: the data may arrive before the 150 (the data
// connection opens as soon as the client issues RETR; the server's 150
// follows). The hash must still attach.
func TestFTPOriginalData(t *testing.T) {
	p := NewFTPParser()
	c, s := client(), server()
	cport, sport := uint16(40005), uint16(21)
	dport := uint16(50200)

	p.FeedControl(c, cport, s, sport, false, []byte("220 x\r\n"), t0)
	p.FeedControl(c, cport, s, sport, true, []byte("USER u\r\n"), t0)
	p.FeedControl(c, cport, s, sport, false, []byte("331 y\r\n"), t0)
	p.FeedControl(c, cport, s, sport, true, []byte("PASS p\r\n"), t0)
	p.FeedControl(c, cport, s, sport, false, []byte("230 ok\r\n"), t0)
	p.FeedControl(c, cport, s, sport, true, []byte("PASV\r\n"), t0)
	p.FeedControl(c, cport, s, sport, false, []byte("227 Entering Passive Mode (10,1,2,3,196,24)\r\n"), t0) // 196*256+24 = 50200

	k := p.MatchData(s, uint16(61000), c, dport, t0)
	if k == (dataKey{}) {
		t.Fatal("data not matched")
	}
	// RETR, then data, then 150, then 226
	p.FeedControl(c, cport, s, sport, true, []byte("RETR f\r\n"), t0)
	payload := []byte("abc")
	p.FeedData(k, payload, t0)
	p.FeedControl(c, cport, s, sport, false, []byte("150 Opening data connection\r\n"), t0)
	p.FeedControl(c, cport, s, sport, false, []byte("226 Transfer complete\r\n"), t0)

	out := p.Finish(t0.Add(10 * time.Second))
	if len(out) != 4 {
		t.Fatalf("got %d exchanges: %+v", len(out), out)
	}
	if out[3].Bytes != 3 || out[3].Hash != sha256hex(payload) {
		t.Errorf("RETR: %+v", out[3])
	}
}

// TestFTPErroneousRETR: 550 (file not found) completes immediately
// with no data.
func TestFTPErroneousRETR(t *testing.T) {
	p := NewFTPParser()
	c, s := client(), server()
	p.FeedControl(c, 40006, s, 21, false, []byte("220 x\r\n"), t0)
	p.FeedControl(c, 40006, s, 21, true, []byte("RETR missing.txt\r\n"), t0)
	p.FeedControl(c, 40006, s, 21, false, []byte("550 No such file\r\n"), t0)
	out := p.Finish(t0.Add(10 * time.Second))
	if len(out) != 1 || out[0].Cmd != "RETR" || out[0].Code != 550 {
		t.Fatalf("got %+v", out)
	}
	if out[0].Bytes != 0 {
		t.Errorf("bytes: %d", out[0].Bytes)
	}
}

// TestFTPCloseData: an aborted transfer (data closes, no 226) still
// completes the exchange.
func TestFTPCloseData(t *testing.T) {
	p := NewFTPParser()
	c, s := client(), server()
	cport, sport := uint16(40007), uint16(21)
	dport := uint16(50300)
	p.FeedControl(c, cport, s, sport, false, []byte("220 x\r\n"), t0)
	p.FeedControl(c, cport, s, sport, true, []byte("USER u\r\n"), t0)
	p.FeedControl(c, cport, s, sport, false, []byte("331 y\r\n"), t0)
	p.FeedControl(c, cport, s, sport, true, []byte("PASS p\r\n"), t0)
	p.FeedControl(c, cport, s, sport, false, []byte("230 ok\r\n"), t0)
	p.FeedControl(c, cport, s, sport, true, []byte("PASV\r\n"), t0)
	p.FeedControl(c, cport, s, sport, false, []byte("227 Entering Passive Mode (10,1,2,3,196,124)\r\n"), t0) // 196*256+124=50300
	p.FeedControl(c, cport, s, sport, true, []byte("RETR f\r\n"), t0)
	k := p.MatchData(s, uint16(62000), c, dport, t0)
	if k == (dataKey{}) {
		t.Fatal("data not matched")
	}
	p.FeedData(k, []byte("partial"), t0)
	p.CloseData(k, t0) // aborted: no 226

	out := p.Finish(t0.Add(10 * time.Second))
	// USER, PASS, PASV, RETR (aborted)
	if len(out) != 4 {
		t.Fatalf("got %d exchanges: %+v", len(out), out)
	}
	if out[3].Bytes != 7 || out[3].Hash != sha256hex([]byte("partial")) {
		t.Errorf("aborted RETR: %+v", out[3])
	}
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TestDNSUDP: an A query and answer over UDP.
func TestDNSUDP(t *testing.T) {
	p := NewDNSParser()
	c, s := client(), server()
	// query
	q := dnsWireQuery(0x1234, "www.example.com", "A")
	t2 := p.FeedUDP(c, 53000, s, 53, q, t0)
	if t2 == nil {
		t.Fatal("query not parsed")
	}
	if t2.Names[0] != "www.example.com" || t2.QTypes[0] != "A" {
		t.Errorf("query: %+v", t2)
	}
	// answer (reverse direction)
	a := dnsWireAnswer(0x1234, "www.example.com", "A", "10.9.8.7")
	t2 = p.FeedUDP(s, 53, c, 53000, a, t0)
	if t2 == nil || len(t2.Answers) != 1 || t2.Answers[0] != "10.9.8.7" {
		t.Fatalf("answer: %+v", t2)
	}
}

// TestDNSTCPSplit: a TCP message split across two segments (and two
// messages in one segment).
func TestDNSTCPSplit(t *testing.T) {
	p := NewDNSParser()
	c, s := client(), server()
	m1 := dnsWireQuery(0x0001, "one.example", "A")
	m2 := dnsWireQuery(0x0002, "two.example", "A")
	frame := append(u16(len(m1)), m1...)
	frame = append(frame, u16(len(m2))...)
	frame = append(frame, m2...)

	// first half of m1
	got := p.FeedTCP(c, 53001, s, 53, true, frame[:5], t0)
	if len(got) != 0 {
		t.Fatalf("premature: %+v", got)
	}
	got = p.FeedTCP(c, 53001, s, 53, true, frame[5:], t0)
	if len(got) != 2 {
		t.Fatalf("got %d messages, want 2: %+v", len(got), got)
	}
	if got[0].ID != 1 || got[0].Names[0] != "one.example" {
		t.Errorf("m1: %+v", got[0])
	}
	if got[1].ID != 2 || got[1].Names[0] != "two.example" {
		t.Errorf("m2: %+v", got[1])
	}
}

// TestDNSPointerName: compressed names (pointers) parse.
func TestDNSPointerName(t *testing.T) {
	// question for "a.example.com", answer with a pointer back to it
	msg := make([]byte, 0, 64)
	msg = append(msg, 0x00, 0x42)        // id
	msg = append(msg, 0x81, 0x80)        // flags: response, no error
	msg = append(msg, 0x00, 0x01)        // qd=1
	msg = append(msg, 0x00, 0x01)        // an=1
	msg = append(msg, 0, 0, 0, 0)      // ns, ar
	msg = append(msg, 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
	qnameStart := 12
	msg = append(msg, 0x00, 0x01) // type A
	msg = append(msg, 0x00, 0x01) // class IN
	// answer: pointer to qname, type A, class IN, ttl, rdlen 4
	msg = append(msg, 0xc0, byte(qnameStart))
	msg = append(msg, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0)
	msg = append(msg, 0x00, 0x04) // rdlen
	msg = append(msg, 10, 9, 8, 7)

	p := NewDNSParser()
	t2 := p.FeedUDP(client(), 1, server(), 53, msg, t0)
	if t2 == nil {
		t.Fatal("not parsed")
	}
	if t2.Names[0] != "a.example.com" {
		t.Errorf("name: %q", t2.Names[0])
	}
	if len(t2.Answers) != 1 || t2.Answers[0] != "10.9.8.7" {
		t.Errorf("answers: %v", t2.Answers)
	}
}

// TestDNSShort: garbage must not panic and produces nothing.
func TestDNSShort(t *testing.T) {
	p := NewDNSParser()
	for _, b := range [][]byte{nil, {1}, {1, 2, 3}, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}} {
		if t2 := p.FeedUDP(client(), 1, server(), 53, b, t0); t2 != nil {
			t.Fatalf("parsed garbage: %+v", t2)
		}
	}
}

func u16(v int) []byte { return []byte{byte(v >> 8), byte(v)} }


// dnsName encodes a dotted name.
func dnsName(s string) []byte {
	var out []byte
	for _, label := range strings.Split(s, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

func dnsWireQuery(id uint16, name, qtype string) []byte {
	msg := make([]byte, 12)
	msg[0], msg[1] = byte(id>>8), byte(id&0xff)
	msg[2] = 0x01 // RD
	msg[4], msg[5] = 0, 1 // qd
	msg = append(msg, dnsName(name)...)
	msg = append(msg, 0, 1) // type A
	return msg
}

func dnsWireAnswer(id uint16, name, qtype, a string) []byte {
	msg := make([]byte, 12)
	msg[0], msg[1] = byte(id>>8), byte(id&0xff)
	msg[2], msg[3] = 0x81, 0x80
	msg[4], msg[5] = 0, 1
	msg[6], msg[7] = 0, 1
	msg = append(msg, dnsName(name)...)
	msg = append(msg, 0, 1, 0, 1) // qtype A, qclass IN
	msg = append(msg, dnsName(name)...) // answer name
	msg = append(msg, 0, 1, 0, 1, 0, 0, 0, 0) // type A, class IN, ttl 0
	msg = append(msg, 0, 4) // rdlen
	msg = append(msg, netIPv4(a)...)
	return msg
}

func netIPv4(s string) []byte {
	parts := strings.Split(s, ".")
	out := make([]byte, 4)
	for i, p := range parts {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		out[i] = byte(n)
	}
	return out
}