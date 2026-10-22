package vantage

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	h1 = netip.MustParseAddr("127.0.0.1")
	h2 = netip.MustParseAddr("127.0.0.2")
)

func TestDiffExposure(t *testing.T) {
	decl := Exposure{}
	decl.Declare(h1, "tcp", 22, "ssh")
	decl.Declare(h1, "tcp", 80, "web")
	decl.Declare(h2, "tcp", 443, "https")
	obs := Observed{
		h1: {{"tcp", 22}: true, {"tcp", 80}: true, {"tcp", 135}: true, {"udp", 161}: true},
		h2: {{"tcp", 445}: true},
	}
	d := DiffExposure(decl, obs, []netip.Addr{h1, h2})
	if d.Unchanged != 2 {
		t.Errorf("unchanged %d", d.Unchanged)
	}
	var got []string
	for _, f := range d.NewlyOpen {
		got = append(got, f.Host.String()+" "+f.Port.String())
	}
	if strings.Join(got, ",") != "127.0.0.1 tcp/135,127.0.0.1 udp/161,127.0.0.2 tcp/445" {
		t.Errorf("newly open %v", got)
	}
	if len(d.Missing) != 1 || d.Missing[0].Host != h2 || d.Missing[0].Port.Port != 443 || d.Missing[0].Label != "https" {
		t.Errorf("missing %+v", d.Missing)
	}
	// an unscanned host is not reported as all-closed
	d = DiffExposure(decl, obs, []netip.Addr{h1})
	if len(d.Missing) != 0 {
		t.Errorf("%+v", d.Missing)
	}
	// nil declared exposure: everything open is undeclared
	if d = DiffExposure(nil, obs, []netip.Addr{h2}); len(d.NewlyOpen) != 1 {
		t.Errorf("%+v", d)
	}
}

func TestScannerRejectsNonAllowlisted(t *testing.T) {
	a, _ := ParseAllowlist("127.0.0.1")
	if _, err := NewScanner(ScanConfig{Allow: a, Hosts: []netip.Addr{h1, netip.MustParseAddr("192.0.2.1")}}); err == nil {
		t.Fatal("a host outside the allowlist was accepted")
	}
	if _, err := NewScanner(ScanConfig{Allow: a}); err == nil {
		t.Fatal("no hosts accepted")
	}
}

// pipeDial is a fake network: open[hostport] decides if a connect works, and
// every attempt is recorded (with the fake clock's reading when it happened).
type pipeDial struct {
	mu    sync.Mutex
	open  map[string]bool
	tries []string
	max   int
	cur   int
}

func (p *pipeDial) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	p.mu.Lock()
	p.tries = append(p.tries, network+" "+addr)
	p.cur++
	p.max = max(p.max, p.cur)
	ok := p.open[addr]
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.cur--; p.mu.Unlock() }()
	if !ok {
		return nil, &net.OpError{Op: "dial", Err: errRefused}
	}
	a, b := net.Pipe()
	go b.Close()
	return a, nil
}

type refused struct{}

func (refused) Error() string { return "connection refused" }

var errRefused = refused{}

func TestScannerRateLimitAndRandomOrder(t *testing.T) {
	a, _ := ParseAllowlist("127.0.0.0/8")
	fc := newFakeClock()
	pd := &pipeDial{open: map[string]bool{"127.0.0.1:22": true, "127.0.0.1:80": true, "127.0.0.1:135": true}}
	sc, err := NewScanner(ScanConfig{Allow: a, Hosts: []netip.Addr{h1}, TCPFrom: 1, TCPTo: 200, Rate: 50, Concurrency: 5,
		UDP: []UDPProbe{}, Dial: pd.dial, clock: fc.clock()})
	if err != nil {
		t.Fatal(err)
	}
	rep := sc.Scan(context.Background())
	if len(pd.tries) != 200 {
		t.Fatalf("%d connect attempts for 200 ports", len(pd.tries))
	}
	// 200 attempts at 50/s with a burst of 5 take (200-5)/50 = 3.9 s of virtual time
	if el := fc.total(); el < 3800*time.Millisecond || el > 4000*time.Millisecond {
		t.Errorf("rate limit: %v of pacing for 200 attempts at 50/s", el)
	}
	if pd.max > 5 {
		t.Errorf("concurrency %d exceeded the bound", pd.max)
	}
	inOrder := true
	for i, s := range pd.tries {
		if s != "tcp 127.0.0.1:"+itoa(i+1) {
			inOrder = false
			break
		}
	}
	if inOrder {
		t.Error("ports were scanned in ascending order; the order should be randomized")
	}
	if !rep.Open[h1][PortKey{"tcp", 22}] || !rep.Open[h1][PortKey{"tcp", 135}] || len(rep.Open[h1]) != 3 {
		t.Errorf("open %v", rep.Open)
	}
}

func itoa(i int) string { return fmtInt(i) }

func fmtInt(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

func TestScanOnceEmitsTransitionsOnce(t *testing.T) {
	a, _ := ParseAllowlist("127.0.0.0/8")
	fc := newFakeClock()
	pd := &pipeDial{open: map[string]bool{"127.0.0.1:22": true, "127.0.0.1:135": true}}
	decl := Exposure{}
	decl.Declare(h1, "tcp", 22, "ssh")
	decl.Declare(h1, "tcp", 80, "web")
	sc, _ := NewScanner(ScanConfig{Allow: a, Hosts: []netip.Addr{h1}, TCPFrom: 1, TCPTo: 200, Rate: 1e6, UDP: []UDPProbe{},
		Declared: func() Exposure { return decl }, Dial: pd.dial, clock: fc.clock()})
	s := &sink{}
	sc.ScanOnce(context.Background(), s.emit)
	ch := s.kind(KindExposureChange)
	byChange := map[string][]string{}
	for _, e := range ch {
		byChange[e.Fields["change"].(string)] = append(byChange[e.Fields["change"].(string)], e.Fields["host"].(string)+":"+fmtInt(e.Fields["port"].(int)))
	}
	if strings.Join(byChange["newly_open"], ",") != "127.0.0.1:135" || strings.Join(byChange["declared_closed"], ",") != "127.0.0.1:80" {
		t.Fatalf("first scan: %v", byChange)
	}
	for _, e := range ch {
		if e.Fields["change"] == "newly_open" && e.Priority != 1 {
			t.Errorf("V2 priority %v", e.Priority)
		}
	}
	scan := s.kind(KindScan)
	if len(scan) != 1 || scan[0].Fields["undeclared"] != 1 || !strings.Contains(scan[0].Fields["evidence"].(string), "135/tcp\topen\tUNDECLARED") {
		t.Fatalf("scan summary: %+v", scan)
	}
	// second scan: the same undeclared port is not re-alerted
	n := len(s.kind(KindExposureChange))
	sc.ScanOnce(context.Background(), s.emit)
	newly := 0
	for _, e := range s.kind(KindExposureChange) {
		if e.Fields["change"] == "newly_open" {
			newly++
		}
	}
	if newly != 1 {
		t.Errorf("newly_open repeated (%d)", newly)
	}
	_ = n
	// the port closes: a closed transition; reopening alerts again
	pd.mu.Lock()
	delete(pd.open, "127.0.0.1:135")
	pd.mu.Unlock()
	sc.ScanOnce(context.Background(), s.emit)
	closed := 0
	for _, e := range s.kind(KindExposureChange) {
		if e.Fields["change"] == "closed" {
			closed++
		}
	}
	if closed != 1 {
		t.Errorf("closed transitions: %d", closed)
	}
	pd.mu.Lock()
	pd.open["127.0.0.1:135"] = true
	pd.mu.Unlock()
	sc.ScanOnce(context.Background(), s.emit)
	newly = 0
	for _, e := range s.kind(KindExposureChange) {
		if e.Fields["change"] == "newly_open" {
			newly++
		}
	}
	if newly != 2 {
		t.Errorf("reopened port should alert again, newly_open=%d", newly)
	}
	if rep, ok := sc.Last(); !ok || !strings.Contains(rep.Text(), "Host 127.0.0.1") {
		t.Error("last report")
	}
}

func TestScanCancelledDoesNotReportClosures(t *testing.T) {
	a, _ := ParseAllowlist("127.0.0.0/8")
	pd := &pipeDial{open: map[string]bool{}}
	decl := Exposure{}
	decl.Declare(h1, "tcp", 22, "ssh")
	sc, _ := NewScanner(ScanConfig{Allow: a, Hosts: []netip.Addr{h1}, TCPFrom: 1, TCPTo: 100, UDP: []UDPProbe{},
		Declared: func() Exposure { return decl }, Dial: pd.dial})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &sink{}
	sc.ScanOnce(ctx, s.emit)
	if len(s.all()) != 0 {
		t.Fatalf("a cancelled scan emitted %v", s.all())
	}
}

func TestScannerRealLoopback(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	// UDP responder on its own port plus a closed UDP port
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 600)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], from)
		}
	}()
	up := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	cl, _ := net.ListenPacket("udp", "127.0.0.1:0")
	closedUDP := uint16(cl.LocalAddr().(*net.UDPAddr).Port)
	cl.Close()
	a, _ := ParseAllowlist("127.0.0.1")
	sc, _ := NewScanner(ScanConfig{Allow: a, Hosts: []netip.Addr{h1}, TCPFrom: port - 3, TCPTo: port + 3, Rate: 1000,
		UDP: []UDPProbe{{up, "echo", []byte("x")}, {closedUDP, "closed", []byte("x")}}, UDPWait: 300 * time.Millisecond, ConnectTimeout: time.Second})
	rep := sc.Scan(context.Background())
	if !rep.Open[h1][PortKey{"tcp", port}] || !rep.Open[h1][PortKey{"udp", up}] || rep.Open[h1][PortKey{"udp", closedUDP}] {
		t.Fatalf("open: %v", rep.Open)
	}
}

func TestDefaultUDPProbes(t *testing.T) {
	ps := DefaultUDPProbes()
	want := map[uint16]string{53: "dns", 123: "ntp", 161: "snmp", 69: "tftp", 500: "ike"}
	for _, p := range ps {
		if want[p.Port] != p.Name || len(p.Payload) == 0 {
			t.Errorf("%+v", p)
		}
		delete(want, p.Port)
	}
	if len(want) != 0 {
		t.Errorf("missing %v", want)
	}
}
