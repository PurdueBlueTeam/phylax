package vantage

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// PortKey identifies a port on a host.
type PortKey struct {
	Proto string // "tcp" or "udp"
	Port  uint16
}

func (k PortKey) String() string { return fmt.Sprintf("%s/%d", k.Proto, k.Port) }

// Exposure is the declared exposure of our public addresses: the services
// marked scored plus declared decoys. The value is a label for reports.
type Exposure map[netip.Addr]map[PortKey]string

// Declare records an expected-open port.
func (e Exposure) Declare(host netip.Addr, proto string, port uint16, label string) {
	if e[host] == nil {
		e[host] = map[PortKey]string{}
	}
	e[host][PortKey{proto, port}] = label
}

// Observed is what a scan found open.
type Observed map[netip.Addr]map[PortKey]bool

// Finding is one port in a diff.
type Finding struct {
	Host  netip.Addr
	Port  PortKey
	Label string // declared label, for Missing
}

// Diff is the comparison of a scan with the declared exposure.
type Diff struct {
	NewlyOpen []Finding // open but not declared: V2
	Missing   []Finding // declared but not seen open
	Unchanged int
}

// DiffExposure compares observed open ports with the declared exposure. Only
// hosts that were scanned are considered (a host missing from observed because
// it was not scanned would otherwise report everything missing).
func DiffExposure(declared Exposure, observed Observed, scanned []netip.Addr) Diff {
	var d Diff
	for _, h := range scanned {
		for k := range observed[h] {
			if _, ok := declared[h][k]; ok {
				d.Unchanged++
			} else {
				d.NewlyOpen = append(d.NewlyOpen, Finding{Host: h, Port: k})
			}
		}
		for k, label := range declared[h] {
			if !observed[h][k] {
				d.Missing = append(d.Missing, Finding{Host: h, Port: k, Label: label})
			}
		}
	}
	sortFindings(d.NewlyOpen)
	sortFindings(d.Missing)
	return d
}

func sortFindings(f []Finding) {
	sort.Slice(f, func(i, j int) bool {
		if f[i].Host != f[j].Host {
			return f[i].Host.Less(f[j].Host)
		}
		if f[i].Port.Proto != f[j].Port.Proto {
			return f[i].Port.Proto < f[j].Port.Proto
		}
		return f[i].Port.Port < f[j].Port.Port
	})
}

// UDPProbe is a protocol-specific payload for a UDP port.
type UDPProbe struct {
	Port    uint16
	Name    string
	Payload []byte
}

// DefaultUDPProbes are the common UDP services with payloads that elicit a reply:
// DNS, NTP, SNMP, TFTP, IKE.
func DefaultUDPProbes() []UDPProbe {
	dns := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1} // query for "." NS
	ntp := make([]byte, 48)
	ntp[0] = 0x1b // v3 client
	snmp := []byte{0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', 0xa0, 0x19, 0x02, 0x04, 0x70, 0x68, 0x79, 0x6c,
		0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00}
	tftp := append(append([]byte{0, 1}, []byte("phylax-probe")...), 0, 'o', 'c', 't', 'e', 't', 0)
	ike := make([]byte, 28) // ISAKMP header: initiator cookie, zero responder, version 1.0, exchange identity protection
	copy(ike, []byte{0x70, 0x68, 0x79, 0x6c, 0x61, 0x78, 0x21, 0x21})
	ike[16], ike[17], ike[18], ike[19] = 0, 0x10, 2, 0
	ike[27] = 28
	return []UDPProbe{{53, "dns", dns}, {123, "ntp", ntp}, {161, "snmp", snmp}, {69, "tftp", tftp}, {500, "ike", ike}}
}

// ScanConfig tunes the external scanner.
type ScanConfig struct {
	Allow    Allowlist
	Hosts    []netip.Addr // our public IPs; each must be allowlisted
	Declared func() Exposure
	// TCP: connect scan of [TCPFrom, TCPTo] (default 1-65535) in random order
	// at no more than Rate connection attempts per second (default 100).
	TCPFrom, TCPTo uint16
	Rate           float64
	Concurrency    int           // default 32
	ConnectTimeout time.Duration // default 1s
	// UDP probes (nil = DefaultUDPProbes; empty non-nil slice disables UDP).
	UDP     []UDPProbe
	UDPWait time.Duration // default 1s
	UDPRate float64       // default 20/s
	// Interval between scans (default 15m). The first scan starts after Delay.
	Interval time.Duration
	Gate     Gate // quiet-window alignment; nil = none
	// Dial and DialUDP override the network (tests).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	Rand *rand.Rand
	clock
}

// Report is the result of one scan.
type Report struct {
	Started, Finished time.Time
	Hosts             []netip.Addr
	Open              Observed
	TCPScanned        int
	UDPProbed         int
	Rate              float64
	Diff              Diff
}

// Text renders the report in an nmap-like form, usable as perimeter-scan
// inject evidence.
func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Phylax external perimeter scan\nstarted %s, finished %s (%s)\n", r.Started.UTC().Format(time.RFC3339), r.Finished.UTC().Format(time.RFC3339), r.Finished.Sub(r.Started).Round(time.Second))
	fmt.Fprintf(&b, "%d TCP ports connect-scanned per host at <= %.0f/s, %d UDP probes\n\n", r.TCPScanned, r.Rate, r.UDPProbed)
	for _, h := range r.Hosts {
		fmt.Fprintf(&b, "Host %s\nPORT\tSTATE\tNOTE\n", h)
		var ks []PortKey
		for k := range r.Open[h] {
			ks = append(ks, k)
		}
		sort.Slice(ks, func(i, j int) bool {
			if ks[i].Proto != ks[j].Proto {
				return ks[i].Proto < ks[j].Proto
			}
			return ks[i].Port < ks[j].Port
		})
		if len(ks) == 0 {
			b.WriteString("(no open ports)\n")
		}
		undeclared := map[PortKey]bool{}
		for _, f := range r.Diff.NewlyOpen {
			if f.Host == h {
				undeclared[f.Port] = true
			}
		}
		for _, k := range ks {
			note := "declared"
			if undeclared[k] {
				note = "UNDECLARED"
			}
			fmt.Fprintf(&b, "%d/%s\topen\t%s\n", k.Port, k.Proto, note)
		}
		b.WriteString("\n")
	}
	for _, f := range r.Diff.Missing {
		fmt.Fprintf(&b, "declared but closed: %s %s (%s)\n", f.Host, f.Port, f.Label)
	}
	return b.String()
}

// Scanner is the agent module for the `scanner` role.
type Scanner struct {
	cfg ScanConfig
	rng *rand.Rand

	mu      sync.Mutex
	alerted map[netip.Addr]map[PortKey]bool
	last    *Report
}

var _ agent.Module = (*Scanner)(nil)

// NewScanner validates the configuration; every host must be allowlisted.
func NewScanner(cfg ScanConfig) (*Scanner, error) {
	if len(cfg.Hosts) == 0 {
		return nil, fmt.Errorf("vantage: scanner needs hosts")
	}
	for _, h := range cfg.Hosts {
		if !cfg.Allow.Allows(h.String()) {
			return nil, fmt.Errorf("vantage: scan target %s is not in the public-address allowlist", h)
		}
	}
	cfg.clock.defaults()
	if cfg.TCPFrom == 0 {
		cfg.TCPFrom = 1
	}
	if cfg.TCPTo == 0 {
		cfg.TCPTo = 65535
	}
	if cfg.TCPTo < cfg.TCPFrom {
		return nil, fmt.Errorf("vantage: bad TCP range")
	}
	if cfg.Rate <= 0 {
		cfg.Rate = 100
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 32
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = time.Second
	}
	if cfg.UDP == nil {
		cfg.UDP = DefaultUDPProbes()
	}
	if cfg.UDPWait <= 0 {
		cfg.UDPWait = time.Second
	}
	if cfg.UDPRate <= 0 {
		cfg.UDPRate = 20
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Minute
	}
	rng := cfg.Rand
	if rng == nil {
		rng = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	}
	return &Scanner{cfg: cfg, rng: rng, alerted: map[netip.Addr]map[PortKey]bool{}}, nil
}

// Name implements agent.Module.
func (s *Scanner) Name() string { return "vantage.scanner" }

// Last returns the most recent report, if any.
func (s *Scanner) Last() (Report, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last == nil {
		return Report{}, false
	}
	return *s.last, true
}

// Start implements agent.Module: scan, wait Interval, repeat.
func (s *Scanner) Start(ctx context.Context, emit agent.Emit) error {
	for {
		if waitSafe(ctx, s.cfg.Gate, s.cfg.clock, 30*time.Second, s.cfg.Interval) {
			s.ScanOnce(ctx, emit)
		}
		if !s.cfg.Sleep(ctx, s.cfg.Interval) {
			return nil
		}
	}
}

func (s *Scanner) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.cfg.Dial != nil {
		return s.cfg.Dial(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// Scan runs one scan without emitting events.
func (s *Scanner) Scan(ctx context.Context) Report {
	rep := Report{Started: s.cfg.Now(), Hosts: append([]netip.Addr(nil), s.cfg.Hosts...), Open: Observed{}, Rate: s.cfg.Rate}
	var mu sync.Mutex
	mark := func(h netip.Addr, k PortKey) {
		mu.Lock()
		if rep.Open[h] == nil {
			rep.Open[h] = map[PortKey]bool{}
		}
		rep.Open[h][k] = true
		mu.Unlock()
	}
	// TCP: random port order per host; one shared limiter bounds the rate.
	lim := newLimiter(s.cfg.Rate, s.cfg.Concurrency, s.cfg.clock)
	type job struct {
		h netip.Addr
		p uint16
	}
	jobs := make(chan job)
	var wg sync.WaitGroup
	for range s.cfg.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				cctx, cancel := context.WithTimeout(ctx, s.cfg.ConnectTimeout)
				c, err := s.dial(cctx, "tcp", net.JoinHostPort(j.h.String(), fmt.Sprint(j.p)))
				cancel()
				if err == nil {
					_ = c.Close()
					mark(j.h, PortKey{"tcp", j.p})
				}
			}
		}()
	}
	n := int(s.cfg.TCPTo) - int(s.cfg.TCPFrom) + 1
	rep.TCPScanned = n
outer:
	for _, h := range s.cfg.Hosts {
		s.mu.Lock()
		perm := s.rng.Perm(n)
		s.mu.Unlock()
		for _, i := range perm {
			if !lim.Wait(ctx) {
				break outer
			}
			select {
			case jobs <- job{h, s.cfg.TCPFrom + uint16(i)}:
			case <-ctx.Done():
				break outer
			}
		}
	}
	close(jobs)
	wg.Wait()
	// UDP: one payload per port per host, a reply means open; ICMP port
	// unreachable (a read error on the connected socket) means closed; silence
	// is open|filtered and is not reported.
	ulim := newLimiter(s.cfg.UDPRate, 1, s.cfg.clock)
	for _, h := range s.cfg.Hosts {
		for _, p := range s.cfg.UDP {
			if !ulim.Wait(ctx) {
				break
			}
			rep.UDPProbed++
			if s.udpProbe(ctx, h, p) {
				mark(h, PortKey{"udp", p.Port})
			}
		}
	}
	rep.Finished = s.cfg.Now()
	var declared Exposure
	if s.cfg.Declared != nil {
		declared = s.cfg.Declared()
	}
	rep.Diff = DiffExposure(declared, rep.Open, rep.Hosts)
	return rep
}

func (s *Scanner) udpProbe(ctx context.Context, h netip.Addr, p UDPProbe) bool {
	cctx, cancel := context.WithTimeout(ctx, s.cfg.UDPWait)
	defer cancel()
	c, err := s.dial(cctx, "udp", net.JoinHostPort(h.String(), fmt.Sprint(p.Port)))
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(s.cfg.UDPWait))
	if _, err := c.Write(p.Payload); err != nil {
		return false
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	return err == nil && n > 0
}

// ScanOnce scans, then emits the summary and the transitions: a V2
// exposure_change for every port that is newly open and undeclared (once, until
// it closes again) and a change event when a previously alerted port closes.
func (s *Scanner) ScanOnce(ctx context.Context, emit agent.Emit) Report {
	rep := s.Scan(ctx)
	if ctx.Err() != nil {
		return rep // a partial scan must not look like a closed port
	}
	s.mu.Lock()
	s.last = &rep
	var fresh, closed []Finding
	cur := map[netip.Addr]map[PortKey]bool{}
	for _, f := range rep.Diff.NewlyOpen {
		if cur[f.Host] == nil {
			cur[f.Host] = map[PortKey]bool{}
		}
		cur[f.Host][f.Port] = true
		if !s.alerted[f.Host][f.Port] {
			fresh = append(fresh, f)
		}
	}
	for h, ports := range s.alerted {
		for k := range ports {
			if !cur[h][k] {
				closed = append(closed, Finding{Host: h, Port: k})
			}
		}
	}
	s.alerted = cur
	s.mu.Unlock()
	sortFindings(closed)

	now := s.cfg.Now()
	for _, f := range fresh {
		_ = emit(newEvent(KindExposureChange, event.PriorityHigh, now, map[string]any{
			"change": "newly_open", "host": f.Host.String(), "proto": f.Port.Proto, "port": int(f.Port.Port)}))
	}
	for _, f := range closed {
		_ = emit(newEvent(KindExposureChange, event.PriorityNormal, now, map[string]any{
			"change": "closed", "host": f.Host.String(), "proto": f.Port.Proto, "port": int(f.Port.Port)}))
	}
	for _, f := range rep.Diff.Missing {
		_ = emit(newEvent(KindExposureChange, event.PriorityNormal, now, map[string]any{
			"change": "declared_closed", "host": f.Host.String(), "proto": f.Port.Proto, "port": int(f.Port.Port), "label": f.Label}))
	}
	text := rep.Text()
	if len(text) > 16<<10 {
		text = text[:16<<10]
	}
	open := 0
	for _, m := range rep.Open {
		open += len(m)
	}
	_ = emit(newEvent(KindScan, event.PriorityBulk, now, map[string]any{
		"hosts": len(rep.Hosts), "open": open, "undeclared": len(rep.Diff.NewlyOpen), "declared_closed": len(rep.Diff.Missing),
		"tcp_scanned": rep.TCPScanned, "udp_probed": rep.UDPProbed, "rate": rep.Rate,
		"duration_ms": rep.Finished.Sub(rep.Started).Milliseconds(), "evidence": text}))
	return rep
}
