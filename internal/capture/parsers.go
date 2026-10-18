package capture

// Phase-1 protocol parsers (docs: Protocol parsers): SMTP, POP3, IMAP,
// FTP (control channel with data-channel linkage) and DNS (UDP and
// TCP). Each parser is isolated: a bug in one parser only affects its
// own protocol (docs: "each is isolated so a parser bug only affects
// its own protocol").

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Exchange is one parsed command/response unit of a line protocol
// (SMTP, POP3, IMAP) or one FTP control command, with the data
// transfer attached for FTP. Shipped continuously to the agent spool
// (docs: Capture tiers — transactions).
type Exchange struct {
	Proto string    `json:"proto"` // "smtp" | "pop3" | "imap" | "ftp"
	TS    time.Time `json:"ts"`
	Src   [16]byte  `json:"src"`  // client
	Sport uint16    `json:"sport"`
	Dst   [16]byte  `json:"dst"`  // server
	Dport uint16    `json:"dport"`
	User  string    `json:"user,omitempty"` // authenticated/submitting account
	Cmd   string    `json:"cmd"`
	Arg   string    `json:"arg,omitempty"` // capped
	Rsp   string    `json:"rsp,omitempty"` // final response line, capped
	Code  int       `json:"code,omitempty"`
	Bytes int       `json:"data_bytes,omitempty"` // FTP data transfer
	Hash  string    `json:"data_hash,omitempty"`  // sha256 hex of FTP data
}

// DNSTransaction is one DNS question/answer pair (docs: Capture tiers).
type DNSTransaction struct {
	TS      time.Time  `json:"ts"`
	Src     [16]byte   `json:"src"`
	Sport   uint16     `json:"sport"`
	Dst     [16]byte   `json:"dst"`
	Dport   uint16     `json:"dport"`
	TCP     bool       `json:"tcp"`
	ID      uint16     `json:"id"`
	Names   []string   `json:"names"`
	QTypes  []string   `json:"qtypes"`
	Answers []string   `json:"answers,omitempty"` // A/AAAA rdata as IP strings
	Rcode   int        `json:"rcode"`
}

const argCap = 512

func capArg(s string) string {
	if len(s) > argCap {
		return s[:argCap]
	}
	return s
}

// ---------------------------------------------------------------- line protocols

// lineState is one connection of a line protocol (SMTP/POP3/IMAP).
type lineState struct {
	proto string
	src   [16]byte // client
	sp    uint16
	dst   [16]byte // server
	dp    uint16

	clientBuf []byte
	serverBuf []byte

	dataMode bool // SMTP DATA: client body lines until a lone "."
	pending  []pendingCmd
	user     string
	last     time.Time
}

type pendingCmd struct {
	cmd string
	arg string
}

// MailParser parses SMTP, POP3 and IMAP line protocols: passive
// reassembly per connection, command/response pairing, account
// extraction. A parser bug only affects its own protocol.
type MailParser struct {
	mu    sync.Mutex
	conns map[connKey]*lineState
	out   []Exchange
}

func NewMailParser() *MailParser {
	return &MailParser{conns: map[connKey]*lineState{}}
}

// Feed gives the parser bytes of one direction of one connection. The
// module resolves which side is the client (the side whose port is
// NOT the declared service port).
func (p *MailParser) Feed(proto string, csrc [16]byte, cport uint16, sdst [16]byte, sport uint16, clientDir bool, payload []byte, now time.Time) {
	if len(payload) == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	k := connKey{csrc, cport, sdst, sport}
	st := p.conns[k]
	if st == nil {
		st = &lineState{proto: proto, last: now, src: csrc, sp: cport, dst: sdst, dp: sport}
		p.conns[k] = st
	}
	st.last = now
	if clientDir {
		st.clientBuf = append(st.clientBuf, payload...)
	} else {
		st.serverBuf = append(st.serverBuf, payload...)
	}
	p.consumeLocked(st, now)
}

// consumeLocked pulls complete lines from both buffers.
func (p *MailParser) consumeLocked(st *lineState, now time.Time) {
	for {
		line, rest, ok := splitLine(st.clientBuf)
		if ok {
			st.clientBuf = rest
			p.ingestClientLineLocked(st, line, now)
			continue
		}
		line, rest, ok = splitLine(st.serverBuf)
		if ok {
			st.serverBuf = rest
			p.ingestServerLineLocked(st, line, now)
			continue
		}
		return
	}
}

// splitLine returns the first CRLF-terminated line.
func splitLine(buf []byte) (line, rest []byte, ok bool) {
	i := bytes.Index(buf, []byte("\r\n"))
	if i < 0 {
		return nil, nil, false
	}
	return buf[:i], buf[i+2:], true
}

func (p *MailParser) ingestClientLineLocked(st *lineState, line []byte, now time.Time) {
	s := string(line)
	if st.dataMode {
		if s == "." { // end of DATA
			st.dataMode = false
		}
		return
	}
	cmd, arg := splitCmd(s)
	if st.proto == "imap" && cmd != "" {
		// IMAP commands are tagged: "a2 SELECT INBOX" — the tag is
		// the first token, the verb the second.
		if c2, a2 := splitCmd(arg); c2 != "" {
			cmd, arg = c2, a2
		}
	}
	if cmd == "" {
		return
	}
	if st.proto == "smtp" && strings.EqualFold(cmd, "data") {
		st.dataMode = true
	}
	if user, ok := lineUser(st.proto, cmd, arg); ok {
		st.user = user
	}
	st.pending = append(st.pending, pendingCmd{cmd: strings.ToUpper(cmd), arg: capArg(arg)})
	if len(st.pending) > 64 { // bound: a stuck connection cannot grow
		st.pending = st.pending[1:]
	}
}

func (p *MailParser) ingestServerLineLocked(st *lineState, line []byte, now time.Time) {
	s := string(line)
	if continuation(s) {
		return // multi-line response: only the final line completes
	}
	// dataMode suppresses only client body lines; the server's 354
	// pairs with DATA immediately, and the 250 after the body arrives
	// with no pending command and is dropped.
	if len(st.pending) == 0 {
		return
	}
	code, _ := rspCode(s)
	pending := st.pending[0]
	st.pending = st.pending[1:]
	p.out = append(p.out, Exchange{
		Proto: st.proto,
		TS:    now,
		Src:   st.src,
		Sport: st.sp,
		Dst:   st.dst,
		Dport: st.dp,
		User:  st.user,
		Cmd:   pending.cmd,
		Arg:   pending.arg,
		Rsp:   capArg(s),
		Code:  code,
	})
}

// continuation reports a multi-line response line ("250-...").
func continuation(s string) bool {
	return len(s) >= 4 && s[3] == '-'
}

// rspCode returns the numeric code (0 if absent).
func rspCode(s string) (int, string) {
	if len(s) < 4 || s[3] != ' ' {
		return 0, s
	}
	n, err := strconv.Atoi(s[:3])
	if err != nil {
		return 0, s
	}
	return n, s
}

// splitCmd splits "USER foo" into ("USER", "foo").
func splitCmd(s string) (cmd, arg string) {
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimSpace(s[i+1:])
}

// lineUser extracts the account a line protocol authenticates or
// submits as (docs: check discovery — "any account the scorer
// authenticates with is marked scored").
func lineUser(proto, cmd, arg string) (string, bool) {
	switch strings.ToUpper(cmd) {
	case "USER":
		return arg, arg != ""
	case "LOGIN": // IMAP: LOGIN user pass
		if parts := strings.Fields(arg); len(parts) >= 1 {
			return parts[0], true
		}
	case "AUTH": // SMTP AUTH PLAIN base64(\0user\0pass)
		parts := strings.Fields(arg)
		if len(parts) >= 2 && strings.EqualFold(parts[0], "plain") {
			if b, err := base64.StdEncoding.DecodeString(parts[1]); err == nil {
				if f := strings.SplitN(string(b), "\x00", 3); len(f) == 3 && f[1] != "" {
					return f[1], true
				}
			}
			if b, err := base64.RawStdEncoding.DecodeString(parts[1]); err == nil {
				if f := strings.SplitN(string(b), "\x00", 3); len(f) == 3 && f[1] != "" {
					return f[1], true
				}
			}
		}
	case "MAIL": // MAIL FROM:<user@host>
		if i := strings.Index(arg, ":<"); i >= 0 {
			if j := strings.IndexByte(arg[i+2:], '>'); j >= 0 {
				return arg[i+2 : i+2+j], true
			}
		}
	}
	_ = proto
	return "", false
}

// Finish returns the accumulated exchanges and prunes idle
// connections (30 s past the reaping horizon).
func (p *MailParser) Finish(olderThan time.Time) []Exchange {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, st := range p.conns {
		if st.last.Before(olderThan.Add(-30 * time.Second)) {
			delete(p.conns, k)
		}
	}
	if len(p.out) == 0 {
		return nil
	}
	out := p.out
	p.out = nil
	return out
}

// ---------------------------------------------------------------- FTP

// dataKey identifies a TCP connection unordered.
type dataKey struct {
	a, b [16]byte
	ap, bp uint16
}

func ipLess(x, y [16]byte) bool { return bytes.Compare(x[:], y[:]) < 0 }

func makeDataKey(a, b [16]byte, ap, bp uint16) dataKey {
	if ipLess(a, b) || (a == b && ap <= bp) {
		return dataKey{a, b, ap, bp}
	}
	return dataKey{b, a, bp, ap}
}

// ftpState is one FTP control connection.
type ftpState struct {
	src, dst [16]byte // client, server
	sp, dp   uint16
	clientBuf, serverBuf []byte
	pending []pendingCmd
	user    string
	last    time.Time

	// data linkage: the endpoint (ip, port) the data transfer is
	// expected on, plus which side of the control conn is the peer.
	dataPeer [16]byte   // the data conn touches (dataIP:dataPort, dataPeer:*)
	dataIP   [16]byte
	dataPort uint16
	dataCmd  string // RETR | LIST | STOR
	opened   Exchange // command with its first response, awaiting 226
	hasOpen  bool
	transfer *ftpTransfer
}

// ftpTransfer is one in-flight data transfer.
type ftpTransfer struct {
	h     hash.Hash
	bytes int
	key   dataKey
	cmd   string
	last  time.Time
}

func (h *ftpTransfer) SumHex() string { return hex.EncodeToString(h.h.Sum(nil)) }

// FTPParser parses the FTP control channel and links the data channel
// (docs: Protocol parsers — "FTP control channel with data-channel
// linkage"). A client command pairs with its first response; when the
// transfer ends (226) the byte count and hash attach to that exchange.
type FTPParser struct {
	mu    sync.Mutex
	conns map[connKey]*ftpState
	data  map[dataKey]*ftpTransfer
	out   []Exchange
}

func NewFTPParser() *FTPParser {
	return &FTPParser{conns: map[connKey]*ftpState{}, data: map[dataKey]*ftpTransfer{}}
}

// HasPending reports whether any control connection currently has an
// expected data transfer; the module uses it as a fast path so the
// per-packet MatchData check is skipped while nothing is pending.
func (p *FTPParser) HasPending() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, st := range p.conns {
		if st.dataPort != 0 {
			return true
		}
	}
	return false
}
// FeedControl gives control-channel bytes.
func (p *FTPParser) FeedControl(csrc [16]byte, cport uint16, sdst [16]byte, sport uint16, clientDir bool, payload []byte, now time.Time) {
	if len(payload) == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	k := connKey{csrc, cport, sdst, sport}
	st := p.conns[k]
	if st == nil {
		st = &ftpState{last: now, src: csrc, sp: cport, dst: sdst, dp: sport}
		p.conns[k] = st
	}
	st.last = now
	if clientDir {
		st.clientBuf = append(st.clientBuf, payload...)
	} else {
		st.serverBuf = append(st.serverBuf, payload...)
	}
	for {
		line, rest, ok := splitLine(st.clientBuf)
		if ok {
			st.clientBuf = rest
			p.ftpClientLineLocked(st, string(line), now)
			continue
		}
		line, rest, ok = splitLine(st.serverBuf)
		if ok {
			st.serverBuf = rest
			p.ftpServerLineLocked(st, string(line), now)
			continue
		}
		return
	}
}

func (p *FTPParser) ftpClientLineLocked(st *ftpState, s string, now time.Time) {
	cmd, arg := splitCmd(s)
	if cmd == "" {
		return
	}
	if user, ok := lineUser("ftp", cmd, arg); ok {
		st.user = user
	}
	uc := strings.ToUpper(cmd)
	// PORT sets the expected active-mode data endpoint (server side)
	if uc == "PORT" {
		if ip, port, ok := parseHostPorts(arg); ok {
			_ = ip
			st.dataPeer = st.src
			st.dataIP = st.dst
			st.dataPort = port
		}
	}
	st.pending = append(st.pending, pendingCmd{cmd: uc, arg: capArg(arg)})
	if len(st.pending) > 64 {
		st.pending = st.pending[1:]
	}
}

func (p *FTPParser) ftpServerLineLocked(st *ftpState, s string, now time.Time) {
	if continuation(s) {
		return
	}
	code, _ := rspCode(s)
	// 227 (passive mode) pairs with PASV and sets the expected data
	// endpoint: the server connects to the client's passive port.
	if code == 227 {
		if ip, port, ok := parseHostPorts(s); ok {
			_ = ip
			st.dataPeer = st.dst
			st.dataIP = st.src
			st.dataPort = port
		}
		p.ftpPairLocked(st, s, code, now)
		return
	}
	// 150 / 125: opening data connection. The command's exchange is
	// held until 226 (or an error) so it can carry the data hash.
	if code == 150 || code == 125 {
		if len(st.pending) > 0 {
			pending := st.pending[0]
			st.pending = st.pending[1:]
			st.opened = Exchange{
				Proto: "ftp", TS: now,
				Src: st.src, Sport: st.sp, Dst: st.dst, Dport: st.dp,
				User: st.user, Cmd: pending.cmd, Arg: pending.arg,
				Rsp: capArg(s), Code: code,
			}
			st.hasOpen = true
			st.dataCmd = pending.cmd
			if st.dataPort != 0 && st.transfer == nil {
				st.transfer = &ftpTransfer{cmd: pending.cmd, last: now, h: sha256.New()}
			}
		}
		return
	}
	// 226: transfer complete — finish the held exchange with the hash.
	if code == 226 {
		if st.hasOpen {
			st.hasOpen = false
			opened := st.opened
			opened.Rsp = capArg(s)
			opened.Code = code
			if tr := st.transfer; tr != nil {
				opened.Bytes = tr.bytes
				opened.Hash = tr.SumHex()
				if k := tr.key; k != (dataKey{}) {
					delete(p.data, k)
				}
				st.transfer = nil
			}
			st.dataPort = 0
			st.dataCmd = ""
			p.out = append(p.out, opened)
		}
		return
	}
	// everything else (220, 230, 550, ...) pairs immediately
	p.ftpPairLocked(st, s, code, now)
}

func (p *FTPParser) ftpPairLocked(st *ftpState, s string, code int, now time.Time) {
	if len(st.pending) == 0 {
		return
	}
	pending := st.pending[0]
	st.pending = st.pending[1:]
	p.out = append(p.out, Exchange{
		Proto: "ftp",
		TS:    now,
		Src:   st.src,
		Sport: st.sp,
		Dst:   st.dst,
		Dport: st.dp,
		User:  st.user,
		Cmd:   pending.cmd,
		Arg:   pending.arg,
		Rsp:   capArg(s),
		Code:  code,
	})
}

// MatchData reports whether a new TCP connection (a:ap <-> b:bp) is a
// data transfer for a control connection with a pending expectation,
// and registers it. The module calls this when it first sees a
// connection.
func (p *FTPParser) MatchData(a [16]byte, ap uint16, b [16]byte, bp uint16, now time.Time) dataKey {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, st := range p.conns {
		if st.dataPort == 0 {
			continue
		}
		matches := (a == st.dataIP && ap == st.dataPort && b == st.dataPeer) ||
			(b == st.dataIP && bp == st.dataPort && a == st.dataPeer)
		if !matches {
			continue
		}
		// the data connection may arrive before or after the 150;
		// create the transfer on first contact if it does not exist
		if st.transfer == nil {
			cmd := st.dataCmd
			if cmd == "" && len(st.pending) > 0 {
				cmd = st.pending[len(st.pending)-1].cmd
			}
			st.transfer = &ftpTransfer{cmd: cmd, last: now, h: sha256.New()}
		}
		k := makeDataKey(a, b, ap, bp)
		st.transfer.key = k
		st.transfer.last = now
		p.data[k] = st.transfer
		return k
	}
	return dataKey{}
}

// FeedData gives data-channel bytes for a registered transfer.
func (p *FTPParser) FeedData(k dataKey, payload []byte, now time.Time) bool {
	if len(payload) == 0 {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	tr := p.data[k]
	if tr == nil {
		return false
	}
	tr.last = now
	n, _ := tr.h.Write(payload)
	tr.bytes += n
	return true
}

// CloseData is called when a data connection ends: if 226 never
// arrived (aborted transfer), the held exchange completes anyway so it
// is not lost.
func (p *FTPParser) CloseData(k dataKey, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	tr := p.data[k]
	if tr == nil {
		return
	}
	delete(p.data, k)
	for _, st := range p.conns {
		if st.transfer == tr {
			if st.hasOpen {
				st.hasOpen = false
				opened := st.opened
				opened.Bytes = tr.bytes
				opened.Hash = tr.SumHex()
				p.out = append(p.out, opened)
			} else if tr.cmd != "" {
				// aborted before the 150: emit the pending command
				// with whatever data arrived
				for i, pc := range st.pending {
					if pc.cmd == tr.cmd {
						st.pending = append(st.pending[:i], st.pending[i+1:]...)
						p.out = append(p.out, Exchange{
							Proto: "ftp", TS: now,
							Src: st.src, Sport: st.sp, Dst: st.dst, Dport: st.dp,
							User: st.user, Cmd: pc.cmd, Arg: pc.arg,
							Bytes: tr.bytes, Hash: tr.SumHex(),
						})
						break
					}
				}
			}
			st.transfer = nil
			st.dataPort = 0
		}
	}
}

// Finish returns completed exchanges and prunes idle state.
func (p *FTPParser) Finish(olderThan time.Time) []Exchange {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, st := range p.conns {
		if st.last.Before(olderThan.Add(-30 * time.Second)) {
			delete(p.conns, k)
		}
	}
	for k, tr := range p.data {
		if tr.last.Before(olderThan.Add(-30 * time.Second)) {
			delete(p.data, k)
		}
	}
	if len(p.out) == 0 {
		return nil
	}
	out := p.out
	p.out = nil
	return out
}

// parseHostPorts parses "h1,h2,h3,h4,p1,p2" (from PASV text or a PORT
// argument).
func parseHostPorts(s string) ([16]byte, uint16, bool) {
	// take the last parenthesized group if present (227 responses)
	if i := strings.LastIndex(s, "("); i >= 0 {
		if j := strings.LastIndex(s, ")"); j > i {
			s = s[i+1 : j]
		}
	}
	parts := strings.Split(strings.TrimSpace(s), ",")
	if len(parts) != 6 {
		return [16]byte{}, 0, false
	}
	var ip [16]byte
	for n := 0; n < 4; n++ {
		v, err := strconv.Atoi(strings.TrimSpace(parts[n]))
		if err != nil || v < 0 || v > 255 {
			return [16]byte{}, 0, false
		}
		ip[12+n] = byte(v)
	}
	p1, err1 := strconv.Atoi(strings.TrimSpace(parts[4]))
	p2, err2 := strconv.Atoi(strings.TrimSpace(parts[5]))
	if err1 != nil || err2 != nil || p1 < 0 || p2 > 255 {
		return [16]byte{}, 0, false
	}
	return ip, uint16(p1<<8 | p2), true
}

// ---------------------------------------------------------------- DNS

// DNSParser parses DNS messages on UDP (one datagram = one message)
// and TCP (2-byte length prefix + message). A parse failure produces
// nothing — a DNS parser bug must not break the module.
type DNSParser struct {
	mu    sync.Mutex
	conns map[connKey][]byte // TCP: partial message buffer
}

func NewDNSParser() *DNSParser {
	return &DNSParser{conns: map[connKey][]byte{}}
}

// FeedUDP gives one UDP datagram; returns the parsed message or nil.
func (p *DNSParser) FeedUDP(src [16]byte, sp uint16, dst [16]byte, dp uint16, payload []byte, now time.Time) *DNSTransaction {
	return parseDNS(payload, now, src, sp, dst, dp, false)
}

// FeedTCP gives TCP bytes for one connection; returns complete
// messages parsed from them.
func (p *DNSParser) FeedTCP(csrc [16]byte, cport uint16, sdst [16]byte, sport uint16, clientDir bool, payload []byte, now time.Time) []*DNSTransaction {
	p.mu.Lock()
	defer p.mu.Unlock()
	k := connKey{csrc, cport, sdst, sport}
	src, sp, dst, dp := csrc, cport, sdst, sport
	if !clientDir {
		src, sp, dst, dp = sdst, sport, csrc, cport
	}
	buf := append(p.conns[k], payload...)
	var out []*DNSTransaction
	for len(buf) >= 2 {
		n := int(buf[0])<<8 | int(buf[1])
		if len(buf) < 2+n {
			break
		}
		msg := buf[2 : 2+n]
		buf = buf[2+n:]
		if t := parseDNS(msg, now, src, sp, dst, dp, true); t != nil {
			out = append(out, t)
		}
	}
	if len(buf) > 65536 { // corrupt framing
		buf = nil
	}
	p.conns[k] = buf
	return out
}

// parseDNS parses one DNS message. Returns nil on parse failure.
func parseDNS(b []byte, now time.Time, src [16]byte, sp uint16, dst [16]byte, dp uint16, tcp bool) *DNSTransaction {
	if len(b) < 12 {
		return nil
	}
	id := uint16(b[0])<<8 | uint16(b[1])
	questions := int(b[4])<<8 | int(b[5])
	answers := int(b[6])<<8 | int(b[7])
	if questions == 0 {
		return nil
	}
	t := &DNSTransaction{
		TS: now, Src: src, Sport: sp, Dst: dst, Dport: dp,
		TCP: tcp, ID: id, Rcode: int(b[3] & 0x0f),
	}
	pos := 12
	for i := 0; i < questions && pos < len(b); i++ {
		name, np, ok := parseName(b, pos)
		if !ok || np+2 > len(b) {
			return nil
		}
		qt := uint16(b[np])<<8 | uint16(b[np+1])
		t.Names = append(t.Names, name)
		t.QTypes = append(t.QTypes, dnsTypeName(qt))
		pos = np + 2
	}
	// skip questions to reach the answers
	pos = 12
	for i := 0; i < questions && pos < len(b); i++ {
		_, np, ok := parseName(b, pos)
		if !ok {
			return t
		}
		pos = np + 4
	}
	for i := 0; i < answers && pos < len(b); i++ {
		_, np, ok := parseName(b, pos)
		if !ok || np+10 > len(b) {
			break
		}
		at := uint16(b[np])<<8 | uint16(b[np+1])
		rdlen := int(b[np+8])<<8 | int(b[np+9])
		pos = np + 10
		if pos+rdlen > len(b) {
			break
		}
		switch at {
		case 1: // A
			if rdlen == 4 {
				t.Answers = append(t.Answers, net.IP(b[pos:pos+4]).String())
			}
		case 28: // AAAA
			if rdlen == 16 {
				t.Answers = append(t.Answers, net.IP(b[pos:pos+16]).String())
			}
		}
		pos += rdlen
	}
	if len(t.Names) == 0 {
		return nil
	}
	return t
}

// parseName reads a DNS name with compression pointers.
func parseName(b []byte, pos int) (string, int, bool) {
	var parts []string
	jumpBack := 0
	for i := 0; i < 32; i++ { // bound: 32 label hops max
		if pos >= len(b) {
			return "", 0, false
		}
		l := int(b[pos])
		if l&0xc0 == 0xc0 { // pointer
			if pos+1 >= len(b) {
				return "", 0, false
			}
			ptr := (l & 0x3f)<<8 | int(b[pos+1])
			if jumpBack == 0 {
				jumpBack = pos + 2
			}
			pos = ptr
			continue
		}
		pos++
		if pos+l > len(b) {
			return "", 0, false
		}
		if l == 0 {
			break
		}
		parts = append(parts, string(b[pos:pos+l]))
		pos += l
	}
	if jumpBack != 0 {
		pos = jumpBack
	}
	return strings.Join(parts, "."), pos, len(parts) > 0
}

func dnsTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 65:
		return "HTTPS"
	case 255:
		return "ANY"
	default:
		return strconv.Itoa(int(t))
	}
}
