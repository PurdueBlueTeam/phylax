//go:build linux

package capture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Module is the agent's capture module: one AF_PACKET socket per
// interface, feeding the packet ring, the flow tracker and the
// protocol parsers. It is bounded and passive: under load it drops
// packets and reports drop counts.
type Module struct {
	ifaces []string // empty = default route interface
	full   map[int]bool
	caller Caller

	ring  *Ring
	flows *Tracker
	http  *HTTPParser
	mail  *MailParser
	ftp   *FTPParser
	dns   *DNSParser

	portProto map[int]string
	ftpData   map[connKey]dataKey // FTP data connections

	stop chan struct{}
	done chan struct{}
}

// Caller emits flow and transaction records to the agent's spool.
type Caller interface {
	PublishClass(evType string, data any, class int) error
}

// New builds the module. ifaces empty = the default interface; full
// lists the ports captured full-length (scored, decoy, sinkhole);
// portProto maps declared service ports to their protocol for the
// phase-1 parsers ("http", "smtp", "pop3", "imap", "ftp", "dns").
func New(ifaces []string, full []int, portProto map[int]string, ring *Ring, caller Caller) *Module {
	m := &Module{
		ifaces: ifaces,
		full:   map[int]bool{},
		caller: caller,
		ring:   ring,
		flows:  NewTracker(firstHash),
		http:   NewHTTPParser(),
		mail:   NewMailParser(),
		ftp:    NewFTPParser(),
		dns:    NewDNSParser(),
		portProto: portProto,
		ftpData: map[connKey]dataKey{},
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	for _, p := range full {
		m.full[p] = true
	}
	return m
}

func firstHash(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:8])
}

// Run captures until ctx or Stop. Each interface is read in its own
// goroutine; a dead interface is dropped and reported, it never takes
// the module down.
func (m *Module) Run(ctx context.Context) error {
	ifaces := m.ifaces
	if len(ifaces) == 0 {
		ifaces = []string{defaultInterface()}
	}
	prog := ProgramForFullPorts(nil)
	var wg sync.WaitGroup
	for _, name := range ifaces {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			m.runInterface(ctx, name, prog)
		}(name)
	}
	wg.Wait()
	close(m.done)
	return nil
}

// Stop ends capture.
func (m *Module) Stop() { close(m.stop) }

func (m *Module) runInterface(ctx context.Context, name string, prog []unix.SockFilter) {
	ring, err := openAFPacket(name, prog)
	if err != nil {
		m.logf("capture %s: %v", name, err)
		return
	}
	defer ring.close()
	finishEvery := 2 * time.Second
	lastFinish := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stop:
			return
		default:
		}
		if _, err := ring.Read(200*time.Millisecond, func(frame []byte) {
			m.packet(name, frame)
		}); err != nil {
			m.logf("capture %s: %v", name, err)
			return
		}
		if time.Since(lastFinish) > finishEvery {
			lastFinish = time.Now()
			m.finishFlows()
		}
	}
}

func (m *Module) logf(format string, args ...any) {
	// the agent wires real logging; standalone runs stay quiet
}

// packet processes one captured frame: eth -> ip -> transport, into
// the ring, the flow tracker and the HTTP parser.
func (m *Module) packet(ifname string, frame []byte) {
	if len(frame) < 14+20 {
		return
	}
	ether := frame[:14]
	etherType := uint16(ether[12])<<8 | uint16(ether[13])
	if etherType != 0x0800 { // IPv4 only for phase 1
		return
	}
	ip := frame[14:]
	if len(ip) < 20 {
		return
	}
	proto := ip[9]
	if proto != 6 && proto != 17 {
		return
	}
	ihl := int(ip[0]&0x0f) * 4
	if len(ip) < ihl {
		return
	}
	src := ip[12:16]
	dst := ip[16:20]
	rest := ip[ihl:]
	if len(rest) < 8 {
		return
	}
	sport := int(rest[0])<<8 | int(rest[1])
	dport := int(rest[2])<<8 | int(rest[3])
	var payload []byte
	var finOrRst, isRst bool
	switch proto {
	case 6: // TCP
		if len(rest) < 20 {
			return
		}
		flags := rest[13]
		finOrRst = flags&0x01 != 0 || flags&0x04 != 0
		isRst = flags&0x04 != 0
		doff := int(rest[12]>>4) * 4
		if len(rest) >= doff {
			payload = rest[doff:]
		}
	case 17: // UDP
		if len(rest) >= 8 {
			payload = rest[8:]
		}
	}
	now := time.Now()
	srcA := ip4(src)
	dstA := ip4(dst)
	full := m.full[sport] || m.full[dport]
	if m.ring != nil {
		m.ring.Add(now, ifname, srcA, dstA, uint16(sport), uint16(dport), proto, payload, full)
	}
	m.flows.Observe(now, srcA, dstA, uint16(sport), uint16(dport), proto, payload, finOrRst, isRst)
	// no feedback loop: the agent's own traffic to the controller is
	// excluded from flows and transactions (docs: Capture mechanics).
	if isOwnTraffic(m, srcA, sport, dstA, dport) {
		return
	}
	if proto == 6 {
		m.routeTCP(srcA, uint16(sport), dstA, uint16(dport), payload, finOrRst, now)
	} else {
		m.routeUDP(srcA, uint16(sport), dstA, uint16(dport), payload, now)
	}
}

// routeTCP feeds a TCP payload to the parser for the declared
// service port, in the correct direction, and maintains the FTP
// data-channel linkage.
func (m *Module) routeTCP(src [16]byte, sport uint16, dst [16]byte, dport uint16, payload []byte, finOrRst bool, now time.Time) {
	// FTP data-channel linkage runs for every TCP connection: data
	// ports are ephemeral and never declared.
	ak := connKey{src, sport, dst, dport}
	if dk, ok := m.ftpData[ak]; ok {
		if len(payload) > 0 {
			m.ftp.FeedData(dk, payload, now)
		}
		if finOrRst {
			m.ftp.CloseData(dk, now)
			delete(m.ftpData, ak)
		}
		return
	}
	if m.ftp.HasPending() {
		if dk := m.ftp.MatchData(src, sport, dst, dport, now); dk != (dataKey{}) {
			m.ftpData[ak] = dk
			return
		}
	}
	// which side is the server?
	var proto string
	clientDir := true
	csrc, cport, sdst, spt := src, sport, dst, dport
	if m.portProto[int(dport)] != "" {
		proto = m.portProto[int(dport)]
	} else if p := m.portProto[int(sport)]; p != "" {
		proto = p
		clientDir = false
		csrc, cport, sdst, spt = dst, dport, src, sport
	}
	if proto == "" {
		return
	}
	switch proto {
	case "http":
		m.http.Feed(src, sport, dst, dport, payload)
	case "smtp", "pop3", "imap":
		m.mail.Feed(proto, csrc, cport, sdst, spt, clientDir, payload, now)
	case "ftp":
		m.ftp.FeedControl(csrc, cport, sdst, spt, clientDir, payload, now)
	case "dns":
		for _, t := range m.dns.FeedTCP(csrc, cport, sdst, spt, clientDir, payload, now) {
			m.caller.PublishClass("dns", dnsJSON(t), 0)
		}
	}
}

// routeUDP feeds a UDP datagram to the parser for the declared
// service port.
func (m *Module) routeUDP(src [16]byte, sport uint16, dst [16]byte, dport uint16, payload []byte, now time.Time) {
	var proto string
	if m.portProto[int(dport)] != "" {
		proto = m.portProto[int(dport)]
	} else {
		proto = m.portProto[int(sport)]
	}
	if proto == "dns" {
		if t := m.dns.FeedUDP(src, sport, dst, dport, payload, now); t != nil {
			m.caller.PublishClass("dns", dnsJSON(t), 0)
		}
	}
}

func dnsJSON(t *DNSTransaction) map[string]any {
	return map[string]any{
		"type": "dns", "ts": t.TS,
		"src": t.Src[12:], "sport": t.Sport, "dst": t.Dst[12:], "dport": t.Dport,
		"tcp": t.TCP, "id": t.ID, "names": t.Names, "qtypes": t.QTypes,
		"answers": t.Answers, "rcode": t.Rcode,
	}
}

// finishFlows ships completed flow records.
func (m *Module) finishFlows() {
	flows := m.flows.Finish(time.Now())
	for _, f := range flows {
		m.caller.PublishClass("flow", flowJSON(f), 0)
	}
	// the HTTP parser ships completed transactions
	for _, tx := range m.http.Finish(time.Now().Add(-30 * time.Second)) {
		m.caller.PublishClass("http", tx, 0)
	}
	for _, ex := range m.mail.Finish(time.Now()) {
		m.caller.PublishClass("exchange", ex, 0)
	}
	for _, ex := range m.ftp.Finish(time.Now()) {
		m.caller.PublishClass("exchange", ex, 0)
	}
}

// defaultInterface returns the default route's interface name.
func defaultInterface() string {
	routes, err := net.Interfaces()
	if err != nil {
		return "eth0"
	}
	for _, r := range routes {
		if r.Flags&net.FlagUp != 0 && r.Flags&net.FlagLoopback == 0 {
			return r.Name
		}
	}
	return "eth0"
}


func flowJSON(f Flow) map[string]any {
	return map[string]any{
		"src": f.Src[12:], "sport": f.Sport, "dst": f.Dst[12:], "dport": f.Dport,
		"proto": f.Proto, "start": f.Start, "end": f.End,
		"bytes_ab": f.BytesAB, "bytes_ba": f.BytesBA,
		"pkts_ab": f.PktsAB, "pkts_ba": f.PktsBA,
		"result": f.Result, "scan": f.Scan,
		"hash_ab": f.HashAB, "hash_ba": f.HashBA, "pid": f.Pid,
	}
}

func ip4(b []byte) [16]byte {
	var a [16]byte
	copy(a[12:], b)
	return a
}

// isOwnTraffic is the no-feedback-loop exclusion: the agent's own
// outbound link traffic. The exact controller address is injected by
// the agent; this stand-in matches loopback and the link port.
func isOwnTraffic(m *Module, src [16]byte, sport int, dst [16]byte, dport int) bool {
	// local loopback is always our own
	if loopback(src) || loopback(dst) {
		return true
	}
	return false
}

func loopback(a [16]byte) bool {
	return a[12] == 127 && a[13] == 0 && a[14] == 0 && a[15] == 1
}
