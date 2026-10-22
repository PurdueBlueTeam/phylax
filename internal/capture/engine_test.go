package capture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"

	"github.com/PurdueBlueTeam/phylax/internal/capture/fixture"
	netmod "github.com/PurdueBlueTeam/phylax/internal/collect/net"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
	"github.com/PurdueBlueTeam/phylax/internal/scorer"
)

type result struct {
	txns  []txn.Txn
	flows []Flow
	scans []Scan
	eng   *Engine
}

func (r result) byProto(p string) []txn.Txn {
	var out []txn.Txn
	for _, t := range r.txns {
		if t.Proto == p {
			out = append(out, t)
		}
	}
	return out
}

func (r result) flow(t *testing.T, server string) Flow {
	t.Helper()
	for _, f := range r.flows {
		if f.Server.String() == server {
			return f
		}
	}
	t.Fatalf("no flow to %s in %d flows", server, len(r.flows))
	return Flow{}
}

func run(t *testing.T, c *fixture.Capture, cfg Config) result {
	t.Helper()
	var r result
	cfg.OnTxn = func(x txn.Txn) { r.txns = append(r.txns, x) }
	cfg.OnFlow = func(f Flow) { r.flows = append(r.flows, f) }
	cfg.OnScan = func(s Scan) { r.scans = append(r.scans, s) }
	r.eng = NewEngine(cfg)
	src, err := NewPCAPSource(bytes.NewReader(c.PCAP()))
	if err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), src, r.eng); err != nil {
		t.Fatal(err)
	}
	return r
}

func newCap() *fixture.Capture { return fixture.New(time.Unix(1700000000, 0)) }

const quotientReq = "GET /index.php HTTP/1.1\r\nHost: 66.35.250.204:80\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0)\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n"
const okResp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello"

func TestHTTPEndToEndFlowRingAndCommunityID(t *testing.T) {
	c := newCap()
	cn := c.TCP(ap("128.232.110.120:34855"), ap("66.35.250.204:80")).Handshake()
	cn.Send(true, []byte(quotientReq))
	cn.Send(false, []byte(okResp))
	cn.Close()
	r := run(t, c, Config{})

	h := r.byProto("http")
	if len(h) != 1 || h[0].Attr["http.status"] != "200" {
		t.Fatalf("http txns: %+v", h)
	}
	cl, _ := scorer.NewClassifier(scorer.DefaultTable())
	if res := cl.Classify(h[0].Features()); !res.HasEvidence("http.header_set") {
		t.Fatalf("classifier: %+v", res)
	}
	if len(r.flows) != 1 {
		t.Fatalf("%d flows", len(r.flows))
	}
	f := r.flows[0]
	// the Community ID spec's own example flow
	if f.CommunityID != "1:LQU9qZlK+B5F3KDmev6m5PMibrg=" || f.CommunityID != netmod.CommunityID(0, netmod.ProtoTCP, f.Client, f.Server) {
		t.Fatalf("community id %s", f.CommunityID)
	}
	if h[0].CommunityID != f.CommunityID {
		t.Fatal("txn and flow disagree on community id")
	}
	if f.Client.String() != "128.232.110.120:34855" || f.Handshake != "established" || f.Service != "http" || f.EndReason != "fin" ||
		f.PayloadC2S != int64(len(quotientReq)) || f.PayloadS2C != int64(len(okResp)) || f.PktsC2S+f.PktsS2C != int64(len(c.Frames)) {
		t.Fatalf("flow %+v", f)
	}
	if f.FirstC2S != sha64(quotientReq) || f.FirstS2C != sha64(okResp) {
		t.Fatalf("first-bytes hashes %s %s", f.FirstC2S, f.FirstS2C)
	}
	if f.FirstC2S == "" || f.FirstS2C == "" {
		t.Fatalf("first bytes hashes missing: %+v", f)
	}
	// every frame is in the ring and exports as a pcap
	var out bytes.Buffer
	n, err := r.eng.Ring().WriteSlice(&out, time.Unix(0, 0), time.Unix(1<<40, 0), nil)
	if err != nil || n != len(c.Frames) {
		t.Fatalf("ring has %d of %d", n, len(c.Frames))
	}
	if st := r.eng.Stats(); st.FlowsActive != 0 || st.Packets != uint64(len(c.Frames)) || st.FlowsEnded != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestReorderedAndLostSegments(t *testing.T) {
	// request in three segments; the second arrives before the first
	c := newCap()
	cn := c.TCP(ap("10.0.0.5:40000"), ap("10.0.0.9:80")).Handshake()
	req := []byte(quotientReq)
	a, b, d := req[:20], req[20:60], req[60:]
	cn.Segment(true, len(a), b, false)
	cn.Segment(true, 0, a, true)
	cn.Segment(true, len(b), d, true)
	cn.Segment(true, 0, a, false) // retransmission
	cn.Send(false, []byte(okResp))
	cn.Close()
	r := run(t, c, Config{})
	if len(r.byProto("http")) != 1 || r.byProto("http")[0].Attr["http.path"] != "/index.php" {
		t.Fatalf("reordered request not reassembled: %+v", r.txns)
	}

	// a lost segment: the hole cannot be bridged, so the parser is ended (its
	// partial state flushed) and the flow is marked truncated
	c = newCap()
	cn = c.TCP(ap("10.0.0.5:40001"), ap("10.0.0.9:80")).Handshake()
	cn.Segment(true, 0, req[:30], true)
	cn.Skip(true, 25)
	for i := 0; i < 100; i++ { // enough later data to exceed the parked-segment bound
		cn.Segment(true, 0, req[:10], true)
		cn.Skip(true, 1)
	}
	cn.Close()
	r = run(t, c, Config{Reasm: ReasmLimits{MaxSegments: 8}})
	if r.eng.Stats().ReasmGaps != 1 {
		t.Fatalf("gaps: %+v", r.eng.Stats())
	}
	if !r.flow(t, "10.0.0.9:80").Truncated {
		t.Fatal("flow not marked truncated")
	}
}

func TestSnapPolicyAndPerFlowCutoff(t *testing.T) {
	c := newCap()
	big := bytes.Repeat([]byte("A"), 1400)
	// unscored port: truncated to 128
	u := c.TCP(ap("10.0.0.5:40000"), ap("10.0.0.9:8123")).Handshake()
	u.Send(true, big)
	// scored port: full length until the per-flow cutoff
	s := c.TCP(ap("10.0.0.5:40001"), ap("10.0.0.9:80")).Handshake()
	for i := 0; i < 30; i++ {
		s.Send(true, bytes.Repeat([]byte("B"), 1400))
	}
	r := run(t, c, Config{FlowBytes: 10_000})
	var out bytes.Buffer
	_, _ = r.eng.Ring().WriteSlice(&out, time.Unix(0, 0), time.Unix(1<<40, 0), nil)
	_, _, _, datas := readPCAP(t, out.Bytes())
	var full8123, trunc8123, full80, trunc80 int
	for _, d := range datas {
		isBig := len(d) > 1000
		switch d[len(d)-1] {
		case 'A':
			if isBig {
				full8123++
			} else {
				trunc8123++
			}
		case 'B':
			if isBig {
				full80++
			} else {
				trunc80++
			}
		}
	}
	if full8123 != 0 || trunc8123 != 1 {
		t.Fatalf("unscored port: full=%d truncated=%d", full8123, trunc8123)
	}
	if full80 < 7 || full80 > 9 || trunc80 < 20 {
		t.Fatalf("cutoff: full=%d truncated=%d (cutoff 10000 bytes of 1454-byte frames)", full80, trunc80)
	}
	if !r.flow(t, "10.0.0.9:80").Truncated || r.flow(t, "10.0.0.9:80").Stored < 10_000 {
		t.Fatalf("%+v", r.flow(t, "10.0.0.9:80"))
	}
	// flow accounting still sees the real byte counts of truncated packets
	if f := r.flow(t, "10.0.0.9:8123"); f.PayloadC2S != 1400 {
		t.Fatalf("payload accounting from IP length: %d", f.PayloadC2S)
	}
}

func TestBareConnectHoldRefusedAndTimeout(t *testing.T) {
	c := newCap()
	rdp := c.TCP(ap("10.0.0.5:40000"), ap("10.0.0.100:3389")).Handshake()
	for i := 0; i < 2; i++ {
		c.Sleep(15 * time.Second)
		rdp.Keepalive(true)
	}
	c.Sleep(2 * time.Second)
	rdp.Close()
	c.TCP(ap("10.0.0.5:40001"), ap("10.0.0.100:81")).Refuse()
	c.TCP(ap("10.0.0.5:40002"), ap("10.0.0.100:82")).SYNOnly()
	r := run(t, c, Config{ScoredPorts: []uint16{3389}})

	rd := r.byProto("rdp")
	if len(rd) != 1 || rd[0].Attr["tcp.zero_payload"] != "true" || rd[0].Attr["tcp.keepalives"] != "2" {
		t.Fatalf("rdp: %+v", rd)
	}
	if ms := rd[0].Attr["tcp.hold_ms"]; ms < "32000" || ms > "33000" {
		t.Fatalf("hold %s", ms)
	}
	cl, _ := scorer.NewClassifier(scorer.DefaultTable())
	if !cl.Classify(rd[0].Features()).HasEvidence("rdp.zero_payload") {
		t.Fatal("classifier")
	}
	tc := r.byProto("tcp")
	results := map[string]bool{}
	for _, x := range tc {
		results[x.Attr["tcp.result"]] = true
	}
	if !results["refused"] || !results["timeout"] {
		t.Fatalf("tcp txns: %+v", tc)
	}
	if r.flow(t, "10.0.0.100:81").Handshake != "refused" || r.flow(t, "10.0.0.100:82").Handshake != "timeout" {
		t.Fatal("handshake results")
	}
}

func TestScanAggregation(t *testing.T) {
	c := newCap()
	for p := 1; p <= 60; p++ {
		c.TCP(ap(fmt.Sprintf("10.0.0.66:%d", 50000+p)), ap(fmt.Sprintf("10.0.0.9:%d", p))).Refuse()
		c.Sleep(10 * time.Millisecond)
	}
	r := run(t, c, Config{ScanThreshold: 20})
	if len(r.scans) != 2 || r.scans[0].Final || !r.scans[1].Final || r.scans[1].Targets != 60 || r.scans[1].Hosts != 1 ||
		r.scans[1].Src != netip.MustParseAddr("10.0.0.66") {
		t.Fatalf("scans: %+v", r.scans)
	}
	// individual refusals stop being reported once the source is a known scanner
	if n := len(r.byProto("tcp")); n >= 20 || n == 0 {
		t.Fatalf("tcp txns before suppression: %d", n)
	}
	scanFlows := 0
	for _, f := range r.flows {
		if f.Scan {
			scanFlows++
		}
	}
	if scanFlows < 40 {
		t.Fatalf("scan flows %d", scanFlows)
	}
}

func TestFTPDataChannelLinkage(t *testing.T) {
	c := newCap()
	ctl := c.TCP(ap("10.0.0.5:40000"), ap("10.0.0.9:21")).Handshake()
	ctl.Send(false, []byte("220 FTP ready\r\n"))
	ctl.Send(true, []byte("EPSV\r\n"))
	ctl.Send(false, []byte("229 Entering Extended Passive Mode (|||40123|)\r\n"))
	data := c.TCP(ap("10.0.0.5:40010"), ap("10.0.0.9:40123")).Handshake()
	ctl.Send(true, []byte("RETR /sop.txt\r\n"))
	data.Send(false, []byte("file contents"))
	data.Close()
	ctl.Send(false, []byte("150 ok\r\n226 done\r\n"))
	ctl.Send(true, []byte("QUIT\r\n"))
	ctl.Send(false, []byte("221 bye\r\n"))
	ctl.Close()
	r := run(t, c, Config{})
	f := r.byProto("ftp")
	if len(f) != 1 || strings.Join(f[0].List["ftp.cmds"], " ") != "EPSV RETR QUIT" {
		t.Fatalf("ftp: %+v", f)
	}
	df := r.flow(t, "10.0.0.9:40123")
	if df.RelatedTo != f[0].CommunityID || !strings.HasPrefix(df.Service, "ftp-data") {
		t.Fatalf("data flow not linked to control: %+v (control %s)", df, f[0].CommunityID)
	}
	// the data connection is captured in full even though 40123 is not a scored port
	if df.Stored == 0 {
		t.Fatal("related flow not stored in full")
	}
}

func TestUDPDNSAndICMP(t *testing.T) {
	c := newCap()
	c.UDP(ap("10.0.0.5:51000"), ap("10.0.0.100:53"), fixture.DNSQuery(9, "www.team21.local", 1, false))
	c.UDP(ap("10.0.0.100:53"), ap("10.0.0.5:51000"), fixture.DNSResponseA(9, "www.team21.local", [4]byte{172, 20, 240, 10}))
	c.Echo(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.0.9"), false, 77, 0, make([]byte, 24))
	c.Echo(netip.MustParseAddr("10.0.0.9"), netip.MustParseAddr("10.0.0.5"), true, 77, 0, make([]byte, 24))
	c.Echo(netip.MustParseAddr("fd00::5"), netip.MustParseAddr("fd00::9"), false, 5, 1, make([]byte, 56))
	r := run(t, c, Config{})
	d := r.byProto("dns")
	if len(d) != 2 || d[0].Type != "query" || d[1].Type != "response" || d[0].CommunityID != d[1].CommunityID || d[0].CommunityID == "" {
		t.Fatalf("dns: %+v", d)
	}
	ic := r.byProto("icmp")
	if len(ic) != 3 || ic[0].Attr["icmp.payload_len"] != "24" || ic[1].Type != "echo_reply" || ic[0].CommunityID != ic[1].CommunityID {
		t.Fatalf("icmp: %+v", ic)
	}
	fl := r.flow(t, "10.0.0.9:0")
	want := netmod.CommunityIDICMP(0, netmod.ProtoICMP, netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.0.9"), 8, 0)
	if fl.CommunityID != want || fl.PktsC2S != 1 || fl.PktsS2C != 1 {
		t.Fatalf("icmp flow %+v want %s", fl, want)
	}
	if v6 := ic[2]; v6.Attr["icmp.v6"] != "true" || v6.Attr["icmp.payload_len"] != "56" {
		t.Fatalf("%+v", v6)
	}
}

func TestIPv6VLANAndRawLinkType(t *testing.T) {
	for _, mode := range []string{"v6", "vlan", "raw", "raw-v6"} {
		c := newCap()
		cl, sv := ap("10.0.0.5:40000"), ap("10.0.0.9:80")
		switch mode {
		case "v6", "raw-v6":
			cl, sv = ap("[fd00::5]:40000"), ap("[fd00::9]:80")
		}
		c.VLAN = map[bool]uint16{true: 42}[mode == "vlan"]
		c.Raw = strings.HasPrefix(mode, "raw")
		cn := c.TCP(cl, sv).Handshake()
		cn.Send(true, []byte(quotientReq))
		cn.Send(false, []byte(okResp))
		cn.Close()
		r := run(t, c, Config{})
		h := r.byProto("http")
		if len(h) != 1 || h[0].Attr["http.status"] != "200" {
			t.Fatalf("%s: %+v", mode, r.txns)
		}
		if len(r.flows) != 1 || r.flows[0].Handshake != "established" || r.flows[0].PayloadC2S != int64(len(quotientReq)) {
			t.Fatalf("%s: flow %+v", mode, r.flows)
		}
	}
}

func TestMidstreamPickupAndSniffOnUnmappedScoredPort(t *testing.T) {
	// no handshake seen, server on an unmapped but scored port: sniffed as HTTP
	c := newCap()
	cn := c.TCP(ap("10.0.0.5:40000"), ap("10.0.0.9:8123"))
	cn.Send(true, []byte(quotientReq))
	cn.Send(false, []byte(okResp))
	r := run(t, c, Config{ScoredPorts: []uint16{8123}})
	if len(r.byProto("http")) != 1 {
		t.Fatalf("sniffed http missing: %+v", r.txns)
	}
	f := r.flow(t, "10.0.0.9:8123")
	if f.Handshake != "midstream" || f.Service != "http" {
		t.Fatalf("%+v", f)
	}
	// unknown protocol on a scored port: no transaction, but the opening bytes are fingerprinted
	c = newCap()
	cn = c.TCP(ap("10.0.0.5:40000"), ap("10.0.0.9:8123")).Handshake()
	cn.Send(true, []byte("\x01\x02custom protocol hello"))
	cn.Send(false, []byte("\x01\x02custom protocol reply"))
	cn.Close()
	r = run(t, c, Config{ScoredPorts: []uint16{8123}})
	f = r.flow(t, "10.0.0.9:8123")
	if len(r.txns) != 0 || f.Service != "" || f.FirstC2S == "" || f.FirstS2C == "" || f.FirstC2S == f.FirstS2C {
		t.Fatalf("generic fingerprint: txns=%v flow=%+v", r.txns, f)
	}
}

type boomStream struct{}

func (boomStream) Data(txn.Dir, []byte, time.Time) { panic("parser bug") }
func (boomStream) End(time.Time)                   {}

func TestParserPanicIsIsolated(t *testing.T) {
	parserRegistry["boom"] = func(txn.Meta, txn.Emit) txn.Stream { return boomStream{} }
	defer delete(parserRegistry, "boom")
	c := newCap()
	b := c.TCP(ap("10.0.0.5:40000"), ap("10.0.0.9:9999")).Handshake()
	b.Send(true, []byte("anything"))
	b.Send(true, []byte("more"))
	b.Close()
	h := c.TCP(ap("10.0.0.5:40001"), ap("10.0.0.9:80")).Handshake()
	h.Send(true, []byte(quotientReq))
	h.Send(false, []byte(okResp))
	h.Close()
	r := run(t, c, Config{Services: map[uint16]string{9999: "boom", 80: "http"}})
	if r.eng.Stats().ParserPanics == 0 {
		t.Fatal("panic not counted")
	}
	if len(r.byProto("http")) != 1 {
		t.Fatalf("the http parser was affected by another protocol's bug: %+v", r.txns)
	}
	if len(r.flows) != 2 {
		t.Fatalf("flows lost: %d", len(r.flows))
	}
}

func TestExcludeAgentTraffic(t *testing.T) {
	c := newCap()
	ctl := c.TCP(ap("10.0.0.5:40000"), ap("172.20.240.50:9443")).Handshake()
	ctl.Send(true, []byte("agent to controller"))
	c.TCP(ap("10.0.0.5:40001"), ap("10.0.0.9:80")).Handshake()
	r := run(t, c, Config{Exclude: []netip.AddrPort{ap("172.20.240.50:9443")}})
	if len(r.flows) != 1 || r.flows[0].Server.Port() != 80 {
		t.Fatalf("excluded traffic tracked: %+v", r.flows)
	}
	st := r.eng.Stats()
	if st.Excluded != uint64(len(c.Frames)-3) || st.Ring.Packets != 3 {
		t.Fatalf("%+v", st)
	}
}

func TestFlowTableBoundedAndIdleExpiry(t *testing.T) {
	c := newCap()
	for i := 0; i < 50; i++ {
		c.TCP(ap(fmt.Sprintf("10.0.0.5:%d", 40000+i)), ap("10.0.0.9:8123")).SYNOnly()
	}
	r := run(t, c, Config{MaxFlows: 10})
	st := r.eng.Stats()
	if st.FlowsEvicted != 40 || st.FlowsActive != 0 || len(r.flows) != 50 {
		t.Fatalf("%+v flows=%d", st, len(r.flows))
	}
	// idle expiry on the packet clock
	c = newCap()
	c.TCP(ap("10.0.0.5:40000"), ap("10.0.0.9:8123")).Handshake()
	var flows []Flow
	e := NewEngine(Config{TCPIdle: 30 * time.Second, OnFlow: func(f Flow) { flows = append(flows, f) }})
	for _, fr := range c.Frames {
		e.Process(gopacket.CaptureInfo{Timestamp: fr.TS, CaptureLength: len(fr.Data), Length: len(fr.Data)}, fr.Data)
	}
	e.Expire(c.Now.Add(10 * time.Second))
	if len(flows) != 0 {
		t.Fatal("expired too early")
	}
	e.Expire(c.Now.Add(31 * time.Second))
	if len(flows) != 1 || flows[0].EndReason != "idle" {
		t.Fatalf("%+v", flows)
	}
}

func TestLingerThenPortReuse(t *testing.T) {
	c := newCap()
	a := c.TCP(ap("10.0.0.5:40000"), ap("10.0.0.9:80")).Handshake()
	a.Send(true, []byte(quotientReq))
	a.Send(false, []byte(okResp))
	a.Close()
	// the same four-tuple reused right away is a new flow, not a continuation
	b := c.TCP(ap("10.0.0.5:40000"), ap("10.0.0.9:80")).Handshake()
	b.Send(true, []byte(quotientReq))
	b.Send(false, []byte(okResp))
	b.Close()
	r := run(t, c, Config{})
	if len(r.flows) != 2 || len(r.byProto("http")) != 2 {
		t.Fatalf("flows=%d http=%d", len(r.flows), len(r.byProto("http")))
	}
}

func TestSnappedServicePacketsEndParserWithoutPanic(t *testing.T) {
	// a capture truncated by snaplen on a service port cannot be reassembled:
	// the flow is still recorded with true byte counts and the parser is ended
	c := newCap()
	c.Snap = 100
	cn := c.TCP(ap("10.0.0.5:40000"), ap("10.0.0.9:80")).Handshake()
	cn.Send(true, []byte("GET /"+strings.Repeat("a", 1300)+" HTTP/1.1\r\nHost: h\r\n\r\n"))
	cn.Close()
	r := run(t, c, Config{})
	f := r.flow(t, "10.0.0.9:80")
	if f.PayloadC2S < 1300 || !f.Truncated || r.eng.Stats().ReasmGaps != 1 {
		t.Fatalf("%+v %+v", f, r.eng.Stats())
	}
}

// sha64 is the flow record's first-bytes digest: SHA-256 of the first 64 bytes.
func sha64(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func ip4(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestReplayOfOldCaptureIsNotExpiredByWallClock(t *testing.T) {
	// more than one read batch (256 packets) of a 2023 capture: flows must stay
	// open until the packet clock says otherwise
	c := newCap()
	cn := c.TCP(ap("10.0.0.5:40000"), ap("10.0.0.9:80")).Handshake()
	for i := 0; i < 400; i++ {
		cn.Send(true, []byte("GET /"+strings.Repeat("x", i%7)+" HTTP/1.1\r\nHost: h\r\n\r\n"))
		cn.Send(false, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	}
	cn.Close()
	r := run(t, c, Config{})
	if len(r.flows) != 1 || len(r.byProto("http")) != 400 {
		t.Fatalf("flows=%d http=%d", len(r.flows), len(r.byProto("http")))
	}
}
