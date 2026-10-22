// Package capture is the host packet capture module: a bounded in-memory
// packet ring with freeze/pull of a time window as pcap, flow tracking with
// Community IDs, bounded TCP reassembly, and dispatch of reassembled streams to
// the protocol parsers in internal/parsers.
//
// The Engine is platform independent and fed by a Source: AF_PACKET
// TPACKET_V3 on Linux (source_linux.go), a pcap stream for fixtures, or nothing
// on Windows yet (ErrUnsupported; see docs/capture.md).
package capture

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	netmod "github.com/PurdueBlueTeam/phylax/internal/collect/net"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/dns"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/ftp"
	phttp "github.com/PurdueBlueTeam/phylax/internal/parsers/http"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/icmp"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/imap"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/pop3"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/smb2"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/smtp"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/ssh"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/tcp"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/tds"
	ptls "github.com/PurdueBlueTeam/phylax/internal/parsers/tls"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/winrm"
)

// DefaultServices maps well-known service ports to parser names. A port
// absent from Config.Services and from ScoredPorts gets no parser; a scored
// port absent from Services is sniffed from its first bytes.
var DefaultServices = map[uint16]string{
	21: "ftp", 22: "ssh", 25: "smtp", 587: "smtp", 53: "dns",
	80: "http", 8000: "http", 8080: "http",
	110: "pop3", 143: "imap",
	443: "tls", 465: "tls", 993: "tls", 995: "tls", 8089: "tls", 8443: "tls", 5986: "tls",
	445: "smb", 5985: "winrm", 1433: "tds",
}

type parserCtor func(txn.Meta, txn.Emit) txn.Stream

var parserRegistry = map[string]parserCtor{
	"http": phttp.New, "tls": ptls.New, "ssh": ssh.New, "ftp": ftp.New, "smtp": smtp.New,
	"imap": imap.New, "pop3": pop3.New, "dns": dns.New, "smb": smb2.New, "winrm": winrm.New, "tds": tds.New,
}

// Config tunes an Engine. Zero values take the defaults noted.
type Config struct {
	// ScoredPorts are scored, decoy and sinkhole ports: captured at full
	// length and sniffed for a parser when not in Services.
	ScoredPorts []uint16
	// Services maps port to parser name; nil uses DefaultServices.
	Services map[uint16]string
	// Exclude drops the agent's own traffic (controller link) before it
	// reaches the ring, so capture cannot feed back on itself.
	Exclude []netip.AddrPort

	Ring      RingConfig
	SnapOther int   // bytes kept of packets on unscored ports; default 128
	SnapFull  int   // default 65535
	FlowBytes int64 // per-flow bytes kept in full before falling back to SnapOther; default 1 MiB

	MaxFlows    int           // default 65536
	TCPIdle     time.Duration // default 60s
	UDPIdle     time.Duration // default 30s
	ICMPIdle    time.Duration // default 10s
	CloseLinger time.Duration // after FIN/RST, default 3s
	Reasm       ReasmLimits

	ScanThreshold int           // distinct targets that make a scan; default 20
	ScanWindow    time.Duration // default 10s

	OnTxn  func(txn.Txn)
	OnFlow func(Flow)
	OnScan func(Scan)
}

// EngineStats are cumulative counters.
type EngineStats struct {
	Packets, NonIP, DecodeErrors, Excluded uint64
	FlowsStarted, FlowsEnded, FlowsEvicted uint64
	Txns                                   uint64
	ParserPanics                           uint64
	ReasmGaps, ReasmCapped                 uint64
	FlowsActive                            int
	Ring                                   RingStats
}

type flowKey struct {
	proto  uint8
	a, b   netip.Addr
	pa, pb uint16
}

func makeKey(proto uint8, s, d netip.Addr, sp, dp uint16) flowKey {
	if c := s.Compare(d); c > 0 || (c == 0 && sp > dp) {
		s, d, sp, dp = d, s, dp, sp
	}
	return flowKey{proto, s, d, sp, dp}
}

type expectation struct {
	parent string
	note   string
	until  time.Time
}

type flowState struct {
	Flow
	key     flowKey
	elem    *list.Element
	lingerE *list.Element
	last    time.Time
	closing time.Time

	sawSyn, sawSynAck bool
	midstream         bool
	finC, finS        bool
	rstFrom           string
	keepalives        int

	firstN  [2]int
	firstH  [2]*sha256Acc
	firstOK [2]bool
	firstNx [2]uint32

	re        [2]*Reassembler
	stream    txn.Stream
	sniff     bool // parser not chosen yet
	parserEnd bool
	cutoff    bool
}

type sha256Acc struct{ b []byte }

// Engine turns packets into ring entries, flow records and transactions. It is
// safe to call Ring methods from other goroutines; Process, Expire and Flush
// must be called from one goroutine at a time (the Engine serialises them and
// Stats with a mutex). Callbacks run with that mutex held and must not call
// back into the Engine.
type Engine struct {
	cfg  Config
	ring *Ring

	mu       sync.Mutex
	svc      map[uint16]string
	scored   map[uint16]bool
	flows    map[flowKey]*flowState
	active   *list.List
	lingerL  *list.List
	expect   map[netip.AddrPort]expectation
	scans    *scanTracker
	stats    EngineStats
	now      time.Time
	lastExp  time.Time
	dec      decoder
	excluded map[netip.AddrPort]bool
}

// NewEngine builds an Engine and its Ring.
func NewEngine(cfg Config) *Engine {
	if cfg.Services == nil {
		cfg.Services = DefaultServices
	}
	if cfg.SnapOther <= 0 {
		cfg.SnapOther = SnapOther
	}
	if cfg.SnapFull <= 0 {
		cfg.SnapFull = 65535
	}
	if cfg.FlowBytes <= 0 {
		cfg.FlowBytes = 1 << 20
	}
	if cfg.MaxFlows <= 0 {
		cfg.MaxFlows = 65536
	}
	if cfg.TCPIdle <= 0 {
		cfg.TCPIdle = 60 * time.Second
	}
	if cfg.UDPIdle <= 0 {
		cfg.UDPIdle = 30 * time.Second
	}
	if cfg.ICMPIdle <= 0 {
		cfg.ICMPIdle = 10 * time.Second
	}
	if cfg.CloseLinger <= 0 {
		cfg.CloseLinger = 3 * time.Second
	}
	if cfg.ScanThreshold <= 0 {
		cfg.ScanThreshold = 20
	}
	if cfg.ScanWindow <= 0 {
		cfg.ScanWindow = 10 * time.Second
	}
	e := &Engine{
		cfg: cfg, svc: cfg.Services, scored: map[uint16]bool{}, flows: map[flowKey]*flowState{},
		active: list.New(), lingerL: list.New(), expect: map[netip.AddrPort]expectation{},
		scans: newScanTracker(cfg.ScanThreshold, cfg.ScanWindow), excluded: map[netip.AddrPort]bool{},
	}
	for _, p := range cfg.ScoredPorts {
		e.scored[p] = true
	}
	for p := range cfg.Services {
		e.scored[p] = true
	}
	for _, x := range cfg.Exclude {
		e.excluded[netip.AddrPortFrom(x.Addr().Unmap(), x.Port())] = true
	}
	e.ring = NewRing(cfg.Ring)
	e.dec = newDecoder()
	return e
}

// Ring returns the engine's packet ring.
func (e *Engine) Ring() *Ring { return e.ring }

// Stats snapshots the counters.
func (e *Engine) Stats() EngineStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.stats
	s.FlowsActive = len(e.flows)
	s.Ring = e.ring.Stats()
	return s
}

// Run reads src until ctx ends or the source is exhausted (io.EOF returns
// nil), then flushes open flows. A live source should be closed by the caller.
func Run(ctx context.Context, src Source, e *Engine) error {
	e.mu.Lock()
	e.dec.setLink(src.LinkType())
	e.ring.mu.Lock()
	e.ring.link = src.LinkType()
	e.ring.mu.Unlock()
	e.mu.Unlock()
	for ctx.Err() == nil {
		err := src.ReadPackets(func(ci gopacket.CaptureInfo, data []byte) { e.Process(ci, data) })
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		// Live sources idle out on the wall clock even when no packet arrives;
		// replays use the packet clock so old captures are not expired at once.
		e.mu.Lock()
		if l, ok := src.(interface{ Live() bool }); ok && l.Live() {
			e.expireLocked(time.Now())
		} else {
			e.expireLocked(e.now)
		}
		e.mu.Unlock()
	}
	e.Flush(e.lastPacketTime())
	return nil
}

func (e *Engine) lastPacketTime() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

// Process handles one captured packet.
func (e *Engine) Process(ci gopacket.CaptureInfo, data []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stats.Packets++
	ts := ci.Timestamp
	if ts.After(e.now) {
		e.now = ts
	}
	if e.lastExp.IsZero() || ts.Sub(e.lastExp) >= time.Second {
		e.expireLocked(ts)
	}
	p, err := e.dec.decode(data)
	if err != nil && !p.ok {
		e.stats.DecodeErrors++
	}
	if !p.ok {
		e.stats.NonIP++
		e.ring.Add(ts, ci.Length, clip(data, e.cfg.SnapOther), netip.Addr{}, netip.Addr{})
		return
	}
	if len(e.excluded) > 0 && (e.excluded[netip.AddrPortFrom(p.src, p.sport)] || e.excluded[netip.AddrPortFrom(p.dst, p.dport)]) {
		e.stats.Excluded++
		return
	}
	wire := ci.Length
	if wire == 0 {
		wire = len(data)
	}
	switch p.proto {
	case netmod.ProtoTCP:
		if p.tcp == nil { // fragment or undecodable header
			e.ring.Add(ts, wire, clip(data, e.cfg.SnapOther), p.src, p.dst)
			return
		}
		e.tcpPacket(ts, ci, data, p, wire)
	case netmod.ProtoUDP:
		e.udpPacket(ts, ci, data, p, wire)
	case netmod.ProtoICMP, netmod.ProtoICMPv6:
		e.icmpPacket(ts, ci, data, p, wire)
	default:
		e.ring.Add(ts, wire, clip(data, e.cfg.SnapOther), p.src, p.dst)
	}
}

func clip(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

func (e *Engine) isScoredPort(p ...uint16) bool {
	for _, x := range p {
		if e.scored[x] {
			return true
		}
	}
	return false
}

func (e *Engine) emitTxn(t txn.Txn, fs *flowState) {
	e.stats.Txns++
	if fs != nil {
		fs.Txns++
	}
	if e.cfg.OnTxn != nil {
		e.cfg.OnTxn(t)
	}
}

// store puts the packet in the ring, in full for scored/related flows until
// the per-flow cutoff, else truncated.
func (e *Engine) store(ts time.Time, wire int, data []byte, p parsed, full bool, fs *flowState) {
	snap := e.cfg.SnapOther
	if full {
		snap = e.cfg.SnapFull
		if fs != nil {
			if fs.Stored >= e.cfg.FlowBytes {
				snap = e.cfg.SnapOther
				fs.cutoff = true
			} else {
				fs.Stored += int64(min(len(data), snap))
			}
		}
	}
	e.ring.Add(ts, wire, clip(data, snap), p.src, p.dst)
}

// ---- flows ----

func (e *Engine) newFlow(key flowKey, proto uint8, ts time.Time) *flowState {
	if len(e.flows) >= e.cfg.MaxFlows {
		if back := e.active.Back(); back != nil {
			e.endFlow(back.Value.(*flowState), ts, "evicted")
			e.stats.FlowsEvicted++
		}
	}
	fs := &flowState{key: key, last: ts}
	fs.Proto, fs.Start, fs.End = proto, ts, ts
	fs.elem = e.active.PushFront(fs)
	e.flows[key] = fs
	e.stats.FlowsStarted++
	return fs
}

func (e *Engine) touch(fs *flowState, ts time.Time) {
	fs.last, fs.End = ts, ts
	if fs.elem != nil {
		e.active.MoveToFront(fs.elem)
	}
}

func (e *Engine) startLinger(fs *flowState, ts time.Time) {
	if fs.lingerE != nil {
		return
	}
	fs.closing = ts
	if fs.elem != nil {
		e.active.Remove(fs.elem)
		fs.elem = nil
	}
	fs.lingerE = e.lingerL.PushFront(fs)
}

func (e *Engine) expireLocked(now time.Time) {
	e.lastExp = now
	for el := e.lingerL.Back(); el != nil; el = e.lingerL.Back() {
		fs := el.Value.(*flowState)
		if now.Sub(fs.closing) < e.cfg.CloseLinger {
			break
		}
		e.endFlow(fs, fs.End, fs.endReason())
	}
	for el := e.active.Back(); el != nil; el = e.active.Back() {
		fs := el.Value.(*flowState)
		if now.Sub(fs.last) < e.idle(fs) {
			break
		}
		e.endFlow(fs, fs.End, "idle")
	}
	for ap, x := range e.expect {
		if now.After(x.until) {
			delete(e.expect, ap)
		}
	}
	e.scans.expire(now, e.emitScan)
}

func (e *Engine) idle(fs *flowState) time.Duration {
	switch fs.Proto {
	case netmod.ProtoUDP:
		return e.cfg.UDPIdle
	case netmod.ProtoICMP, netmod.ProtoICMPv6:
		return e.cfg.ICMPIdle
	}
	return e.cfg.TCPIdle
}

func (fs *flowState) endReason() string {
	if fs.Resets > 0 {
		return "rst"
	}
	return "fin"
}

// Expire ends flows idle at now and reports closed scan windows.
func (e *Engine) Expire(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.expireLocked(now)
}

// Flush ends every open flow (shutdown).
func (e *Engine) Flush(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, fs := range e.flows {
		reason := "shutdown"
		if fs.lingerE != nil { // already closed on the wire: report how
			reason = fs.endReason()
		}
		e.endFlow(fs, fs.End, reason)
	}
	e.scans.flush(e.emitScan)
}

func (e *Engine) emitScan(s Scan) {
	if e.cfg.OnScan != nil {
		e.cfg.OnScan(s)
	}
}

func (e *Engine) endFlow(fs *flowState, ts time.Time, reason string) {
	if _, ok := e.flows[fs.key]; !ok {
		return
	}
	delete(e.flows, fs.key)
	if fs.elem != nil {
		e.active.Remove(fs.elem)
	}
	if fs.lingerE != nil {
		e.lingerL.Remove(fs.lingerE)
	}
	e.stats.FlowsEnded++
	if fs.stream != nil && !fs.parserEnd {
		fs.parserEnd = true
		e.safe(fs, func() { fs.stream.End(ts) })
	}
	f := fs.Flow
	f.End, f.EndReason = fs.End, reason
	if f.Proto == netmod.ProtoTCP {
		f.Handshake = fs.handshake()
		f.ResetBy = fs.rstFrom
		for d := 0; d < 2; d++ {
			if fs.re[d] != nil && fs.re[d].State() == ReasmGap {
				f.Truncated = true
			}
		}
		if fs.cutoff {
			f.Truncated = true
		}
		sum := tcp.Summary{
			Client: f.Client, Server: f.Server, CommunityID: f.CommunityID, Start: f.Start, End: f.End,
			Result: f.Handshake, BytesC2S: f.PayloadC2S, BytesS2C: f.PayloadS2C, ResetBy: f.ResetBy, Keepalives: fs.keepalives,
		}
		probe := f.Handshake == tcp.Refused || f.Handshake == tcp.Timeout || (f.Handshake == tcp.Established && f.PayloadC2S+f.PayloadS2C == 0)
		if probe {
			if sc, scanning := e.scans.note(f.Client.Addr(), f.Server, f.End); sc != nil {
				e.emitScan(*sc)
				f.Scan = true
			} else if scanning {
				f.Scan = true
			}
		}
		if t, ok := tcp.Transaction(sum); ok && !f.Scan {
			e.emitTxn(t, nil)
			f.Txns++
		}
	}
	f.FirstC2S, f.FirstS2C = fs.firstHex(0), fs.firstHex(1)
	if e.cfg.OnFlow != nil {
		e.cfg.OnFlow(f)
	}
}

func (fs *flowState) handshake() string {
	switch {
	case fs.midstream:
		return tcp.MidStream
	case fs.sawSynAck:
		return tcp.Established
	case fs.rstFrom == "server":
		return tcp.Refused
	default:
		return tcp.Timeout
	}
}

func (fs *flowState) firstHex(d int) string {
	if fs.firstH[d] == nil || len(fs.firstH[d].b) == 0 {
		return ""
	}
	h := sha256.Sum256(fs.firstH[d].b)
	return hex.EncodeToString(h[:])
}

func (e *Engine) safe(fs *flowState, f func()) {
	defer func() {
		if r := recover(); r != nil {
			e.stats.ParserPanics++
			fs.parserEnd = true // isolate: this flow gets no more parsing
		}
	}()
	f()
}

// ---- TCP ----

func (e *Engine) tcpPacket(ts time.Time, ci gopacket.CaptureInfo, data []byte, p parsed, wire int) {
	t := p.tcp
	key := makeKey(netmod.ProtoTCP, p.src, p.dst, p.sport, p.dport)
	fs := e.flows[key]
	if fs != nil && !fs.closing.IsZero() && t.SYN && !t.ACK {
		e.endFlow(fs, fs.End, fs.endReason()) // port reuse
		fs = nil
	}
	if fs == nil {
		fs = e.newFlow(key, netmod.ProtoTCP, ts)
		e.initTCPFlow(fs, p, ts)
	}
	dir := txn.C2S
	if p.src != fs.Client.Addr() || p.sport != fs.Client.Port() {
		dir = txn.S2C
	}
	full := e.isScoredPort(fs.Server.Port()) || fs.RelatedTo != ""
	e.store(ts, wire, data, p, full, fs)
	if fs.closing.IsZero() {
		e.touch(fs, ts)
	} else {
		fs.End = ts
	}

	ipBytes := int64(p.ipLen)
	pl := int64(p.payloadWire)
	if dir == txn.C2S {
		fs.PktsC2S++
		fs.BytesC2S += ipBytes
		fs.PayloadC2S += pl
	} else {
		fs.PktsS2C++
		fs.BytesS2C += ipBytes
		fs.PayloadS2C += pl
	}
	switch {
	case t.SYN && !t.ACK:
		fs.sawSyn = true
	case t.SYN && t.ACK:
		fs.sawSynAck = true
	}
	payload := t.Payload
	if len(payload) > 0 {
		e.recordFirst(fs, int(dir), t.Seq, payload)
	}
	// keepalive: zero-length ACK carrying the previous sequence number
	if len(payload) == 0 && t.ACK && !t.SYN && !t.FIN && !t.RST && fs.re[dir] != nil && fs.re[dir].init &&
		seqDiff(t.Seq, fs.re[dir].next) == -1 {
		fs.keepalives++
	}
	e.reassemble(fs, dir, ts, t, payload, p.payloadWire)

	if t.RST {
		fs.Resets++
		if dir == txn.C2S {
			fs.rstFrom = "client"
		} else {
			fs.rstFrom = "server"
		}
		e.endParser(fs, ts)
		e.startLinger(fs, ts)
	}
	if t.FIN {
		if dir == txn.C2S {
			fs.finC = true
		} else {
			fs.finS = true
		}
		if fs.finC && fs.finS {
			e.endParser(fs, ts)
			e.startLinger(fs, ts)
		}
	}
}

func (e *Engine) initTCPFlow(fs *flowState, p parsed, ts time.Time) {
	t := p.tcp
	src := netip.AddrPortFrom(p.src, p.sport)
	dst := netip.AddrPortFrom(p.dst, p.dport)
	switch {
	case t.SYN && !t.ACK:
		fs.Client, fs.Server = src, dst
	case t.SYN && t.ACK:
		fs.Client, fs.Server = dst, src
	default:
		fs.midstream = true
		srcSvc := e.isScoredPort(p.sport)
		dstSvc := e.isScoredPort(p.dport)
		switch {
		case dstSvc && !srcSvc, !srcSvc && !dstSvc && p.dport < p.sport:
			fs.Client, fs.Server = src, dst
		case srcSvc && !dstSvc, !srcSvc && !dstSvc && p.sport < p.dport:
			fs.Client, fs.Server = dst, src
		default:
			fs.Client, fs.Server = src, dst
		}
	}
	fs.CommunityID = netmod.CommunityID(0, netmod.ProtoTCP, fs.Client, fs.Server)
	if x, ok := e.expect[fs.Server]; ok && !ts.After(x.until) {
		fs.RelatedTo, fs.Service = x.parent, x.note
		delete(e.expect, fs.Server)
	}
	if fs.Service != "" {
		return
	}
	name := e.svc[fs.Server.Port()]
	switch {
	case name != "":
		e.attachParser(fs, name)
	case e.scored[fs.Server.Port()]:
		fs.sniff = true
		fs.re[0], fs.re[1] = NewReassembler(e.cfg.Reasm), NewReassembler(e.cfg.Reasm)
	}
}

func (e *Engine) attachParser(fs *flowState, name string) {
	ctor, ok := parserRegistry[name]
	if !ok {
		return
	}
	meta := txn.Meta{Client: fs.Client, Server: fs.Server, CommunityID: fs.CommunityID, Start: fs.Start}
	cid := fs.CommunityID
	meta.Expect = func(server netip.AddrPort, note string) {
		if len(e.expect) >= 256 {
			return
		}
		e.expect[netip.AddrPortFrom(server.Addr().Unmap(), server.Port())] = expectation{parent: cid, note: note, until: e.now.Add(2 * time.Minute)}
	}
	fs.Service = name
	fs.sniff = false
	e.safe(fs, func() {
		fs.stream = ctor(meta, func(t txn.Txn) { e.emitTxn(t, fs) })
	})
	if fs.re[0] == nil {
		fs.re[0], fs.re[1] = NewReassembler(e.cfg.Reasm), NewReassembler(e.cfg.Reasm)
	}
}

func (e *Engine) recordFirst(fs *flowState, d int, seq uint32, payload []byte) {
	if fs.firstN[d] >= 64 {
		return
	}
	if !fs.firstOK[d] {
		fs.firstOK[d], fs.firstNx[d] = true, seq
		fs.firstH[d] = &sha256Acc{}
	}
	if seq != fs.firstNx[d] {
		return
	}
	n := min(len(payload), 64-fs.firstN[d])
	fs.firstH[d].b = append(fs.firstH[d].b, payload[:n]...)
	fs.firstN[d] += n
	fs.firstNx[d] += uint32(len(payload))
}

func (e *Engine) reassemble(fs *flowState, dir txn.Dir, ts time.Time, t *layers.TCP, payload []byte, wirePayload int) {
	if fs.re[dir] == nil || fs.parserEnd {
		return
	}
	if fs.stream == nil && !fs.sniff {
		return
	}
	r := fs.re[dir]
	if r.State() != ReasmOK {
		return
	}
	if len(payload) < wirePayload { // snapped: the bytes are not all here
		r.state = ReasmGap
		e.stats.ReasmGaps++
		e.endParser(fs, ts)
		return
	}
	deliver := func(b []byte) { e.feed(fs, dir, ts, b) }
	if st := r.Add(t.Seq, t.SYN, payload, deliver); st != ReasmOK {
		if st == ReasmGap {
			e.stats.ReasmGaps++
		} else {
			e.stats.ReasmCapped++
		}
		e.endParser(fs, ts)
	}
}

func (e *Engine) feed(fs *flowState, dir txn.Dir, ts time.Time, b []byte) {
	if fs.parserEnd {
		return
	}
	if fs.sniff {
		name := sniffProto(dir, b)
		if name == "" {
			fs.sniff = false // unknown protocol: flow record only
			fs.parserEnd = true
			return
		}
		e.attachParser(fs, name)
	}
	if fs.stream != nil {
		e.safe(fs, func() { fs.stream.Data(dir, b, ts) })
	}
}

func (e *Engine) endParser(fs *flowState, ts time.Time) {
	if fs.stream != nil && !fs.parserEnd {
		fs.parserEnd = true
		e.safe(fs, func() { fs.stream.End(ts) })
	}
}

func sniffProto(d txn.Dir, b []byte) string {
	if d == txn.C2S {
		switch {
		case phttp.Sniff(b):
			return "http"
		case ptls.Sniff(b):
			return "tls"
		case ssh.Sniff(b):
			return "ssh"
		case smb2.Sniff(b):
			return "smb"
		case tds.Sniff(b):
			return "tds"
		}
		return ""
	}
	switch {
	case ssh.Sniff(b):
		return "ssh"
	case len(b) >= 3 && string(b[:3]) == "+OK":
		return "pop3"
	case len(b) >= 4 && string(b[:4]) == "* OK":
		return "imap"
	case len(b) >= 4 && string(b[:4]) == "220 ":
		s := string(clip(b, 200))
		switch {
		case containsFold(s, "ftp"):
			return "ftp"
		case containsFold(s, "smtp"):
			return "smtp"
		}
	}
	return ""
}

func containsFold(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			c := s[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			if c != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// ---- UDP and ICMP ----

func (e *Engine) udpPacket(ts time.Time, ci gopacket.CaptureInfo, data []byte, p parsed, wire int) {
	key := makeKey(netmod.ProtoUDP, p.src, p.dst, p.sport, p.dport)
	fs := e.flows[key]
	if fs == nil {
		fs = e.newFlow(key, netmod.ProtoUDP, ts)
		src, dst := netip.AddrPortFrom(p.src, p.sport), netip.AddrPortFrom(p.dst, p.dport)
		// the lower-numbered port is the service when it is a known one
		if e.isScoredPort(p.sport) && !e.isScoredPort(p.dport) {
			fs.Client, fs.Server = dst, src
		} else {
			fs.Client, fs.Server = src, dst
		}
		fs.CommunityID = netmod.CommunityID(0, netmod.ProtoUDP, fs.Client, fs.Server)
	}
	e.touch(fs, ts)
	full := e.isScoredPort(p.sport, p.dport)
	e.store(ts, wire, data, p, full, fs)
	c2s := p.src == fs.Client.Addr() && p.sport == fs.Client.Port()
	if c2s {
		fs.PktsC2S++
		fs.BytesC2S += int64(p.ipLen)
		fs.PayloadC2S += int64(p.payloadWire)
	} else {
		fs.PktsS2C++
		fs.BytesS2C += int64(p.ipLen)
		fs.PayloadS2C += int64(p.payloadWire)
	}
	if (p.sport == 53 || p.dport == 53) && len(p.payload) > 0 && e.svc[53] == "dns" {
		fs.Service = "dns"
		e.safe(fs, func() {
			if t, ok := dns.Datagram(fs.CommunityID, netip.AddrPortFrom(p.src, p.sport), netip.AddrPortFrom(p.dst, p.dport), p.payload, ts); ok {
				e.emitTxn(t, fs)
			}
		})
	}
}

func (e *Engine) icmpPacket(ts time.Time, ci gopacket.CaptureInfo, data []byte, p parsed, wire int) {
	v6 := p.proto == netmod.ProtoICMPv6
	msg := p.icmpMsg
	if len(msg) < 8 {
		e.ring.Add(ts, wire, clip(data, e.cfg.SnapOther), p.src, p.dst)
		return
	}
	typ := msg[0]
	isEcho := (!v6 && (typ == icmp.V4Request || typ == icmp.V4Reply)) || (v6 && (typ == icmp.V6Request || typ == icmp.V6Reply))
	if !isEcho {
		e.ring.Add(ts, wire, clip(data, e.cfg.SnapFull), p.src, p.dst)
		return
	}
	id := uint16(msg[4])<<8 | uint16(msg[5])
	key := makeKey(p.proto, p.src, p.dst, id, id)
	fs := e.flows[key]
	if fs == nil {
		fs = e.newFlow(key, p.proto, ts)
		req := typ == icmp.V4Request || typ == icmp.V6Request
		if req {
			fs.Client, fs.Server = netip.AddrPortFrom(p.src, 0), netip.AddrPortFrom(p.dst, 0)
		} else {
			fs.Client, fs.Server = netip.AddrPortFrom(p.dst, 0), netip.AddrPortFrom(p.src, 0)
		}
		fs.CommunityID = netmod.CommunityIDICMP(0, p.proto, fs.Client.Addr(), fs.Server.Addr(), icmpReqType(v6), 0)
		fs.Service = "icmp"
	}
	e.touch(fs, ts)
	e.store(ts, wire, data, p, true, fs)
	if p.src == fs.Client.Addr() {
		fs.PktsC2S++
		fs.BytesC2S += int64(p.ipLen)
		fs.PayloadC2S += int64(len(msg) - 8)
	} else {
		fs.PktsS2C++
		fs.BytesS2C += int64(p.ipLen)
		fs.PayloadS2C += int64(len(msg) - 8)
	}
	e.safe(fs, func() {
		if t, ok := icmp.Echo(fs.CommunityID, p.src, p.dst, v6, msg, ts); ok {
			e.emitTxn(t, fs)
		}
	})
}

func icmpReqType(v6 bool) uint8 {
	if v6 {
		return icmp.V6Request
	}
	return icmp.V4Request
}
