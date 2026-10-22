package checks

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// probeTCP: dial and discard; the scorer never even closes the socket. We
// close it (a leaked connection per probe would be rude to our own service).
func probeTCP(ctx context.Context, p *probe) error {
	c, err := p.dialSpec(ctx)
	if err != nil {
		return err
	}
	p.step("connect")
	return c.Close()
}

// probeRDP is a bare connect, like the scorer. Strict mode additionally sends
// an X.224 Connection Request and expects a TPKT/X.224 Connection Confirm, so
// a listener that accepts but is not RDP is caught.
func probeRDP(ctx context.Context, p *probe) error {
	c, err := p.dialSpec(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	p.step("connect")
	if !p.strict() {
		return nil
	}
	// TPKT(4) X.224 CR: len=14, 0xE0, dst/src ref, class 0, RDP neg req (selected protocol: standard).
	cr := []byte{3, 0, 0, 19, 14, 0xE0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 0, 0, 0, 0}
	if _, err := c.Write(cr); err != nil {
		p.strictIssue("write X.224 request: %v", err)
		return nil
	}
	buf := make([]byte, 11)
	n, _ := readFull(c, buf)
	if n < 6 || buf[0] != 3 || buf[5] != 0xD0 {
		p.strictIssue("no X.224 connection confirm from the RDP port")
	}
	p.step("x224")
	return nil
}

func readFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// probeDNS: one UDP query for one record, RD set, no EDNS; if the first
// exchange hits a deadline the same query is sent again.
func probeDNS(ctx context.Context, p *probe) error {
	name := p.item.Name
	if name == "" {
		return fail(ClassConfig, "dns check has no record")
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	kind := dnsmessage.TypeA
	isMX := strings.EqualFold(p.item.Kind, "MX")
	if isMX {
		kind = dnsmessage.TypeMX
	}
	dn, err := dnsmessage.NewName(name)
	if err != nil {
		return fail(ClassConfig, "bad dns name: %v", err)
	}
	id := uint16(p.rng.IntN(1 << 16))
	q := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dn, Type: kind, Class: dnsmessage.ClassINET}},
	}
	wire, err := q.Pack()
	if err != nil {
		return fail(ClassConfig, "pack: %v", err)
	}
	// Quotient uses Timeout-1 per exchange; keep a useful share when the
	// whole budget is small (tests, tight runners).
	dl, _ := ctx.Deadline()
	per := max(time.Until(dl)/2, time.Until(dl)-time.Second)
	var resp dnsmessage.Message
	var lastErr error
	for attempt := range 2 {
		c, err := p.dial(ctx, "udp", p.spec.addr())
		if err != nil {
			return classify(err, "error sending query")
		}
		_ = c.SetDeadline(time.Now().Add(per))
		_, werr := c.Write(wire)
		buf := make([]byte, 4096)
		var n int
		if werr == nil {
			n, werr = c.Read(buf)
		}
		_ = c.Close()
		if werr != nil {
			lastErr = werr
			var ne net.Error
			if errors.As(werr, &ne) && ne.Timeout() && attempt == 0 && ctx.Err() == nil {
				continue // the duplicate query after a deadline
			}
			return classify(werr, "error sending query")
		}
		if err := resp.Unpack(buf[:n]); err != nil || resp.ID != id {
			lastErr = errors.New("malformed or mismatched dns response")
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		return classify(lastErr, "error sending query")
	}
	p.step("exchange")
	if len(resp.Answers) == 0 {
		return fail(ClassContent, "no records received")
	}
	want := map[netip.Addr]bool{}
	for _, a := range p.item.Answers {
		if ip, err := netip.ParseAddr(strings.TrimSpace(a)); err == nil {
			want[ip.Unmap()] = true
		}
	}
	// Quotient only compares *A answers, so an MX check can never pass.
	gotA := false
	var seen []string
	for _, a := range resp.Answers {
		if ar, ok := a.Body.(*dnsmessage.AResource); ok {
			ip := netip.AddrFrom4(ar.A)
			seen = append(seen, ip.String())
			if want[ip] {
				gotA = true
			}
		}
	}
	if isMX {
		p.scorerLimit("MX checks cannot pass in Quotient (only A answers are compared)")
		if p.strict() {
			checkMX(p, resp)
		}
		return nil
	}
	if !gotA {
		return failDebug(ClassContent, "received "+strings.Join(seen, ","), "incorrect answer(s) received from DNS")
	}
	if p.strict() {
		// every expected address should be present, and the rcode clean
		for a := range want {
			found := false
			for _, s := range seen {
				if s == a.String() {
					found = true
				}
			}
			if !found {
				p.strictIssue("expected address %s missing from the answer", a)
			}
		}
		if resp.RCode != dnsmessage.RCodeSuccess {
			p.strictIssue("rcode %v", resp.RCode)
		}
	}
	return nil
}

func checkMX(p *probe, resp dnsmessage.Message) {
	norm := func(s string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")) }
	want := map[string]bool{}
	for _, a := range p.item.Answers {
		f := strings.Fields(a)
		if len(f) > 0 {
			want[norm(f[len(f)-1])] = true // "10 mail.x." or "mail.x."
		}
	}
	got := map[string]bool{}
	for _, a := range resp.Answers {
		if mx, ok := a.Body.(*dnsmessage.MXResource); ok {
			got[norm(mx.MX.String())] = true
		}
	}
	for w := range want {
		if !got[w] {
			p.strictIssue("MX %s missing from the answer", w)
		}
	}
	if len(got) == 0 {
		p.strictIssue("no MX records in the answer")
	}
}

// probePing: an unprivileged (or raw, if permitted) ICMP echo with a 24-byte
// payload (8-byte UnixNano timestamp + 16 tracker bytes), seq 0, random id.
func probePing(ctx context.Context, p *probe) error {
	ip, err := netip.ParseAddr(p.spec.Host)
	if err != nil || !ip.Is4() {
		return fail(ClassConfig, "ping needs an IPv4 address")
	}
	network, laddr := "udp4", "0.0.0.0"
	pc, err := icmp.ListenPacket(network, laddr)
	if err != nil {
		network = "ip4:icmp"
		pc, err = icmp.ListenPacket(network, laddr)
		if err != nil {
			return fail(ClassConfig, "cannot open an ICMP socket: %v", err)
		}
	}
	defer pc.Close()
	payload := make([]byte, 24)
	binary.BigEndian.PutUint64(payload, uint64(time.Now().UnixNano()))
	for i := 8; i < 24; i++ {
		payload[i] = byte(p.rng.IntN(256))
	}
	id := p.rng.IntN(1 << 16)
	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: id, Seq: 0, Data: payload}}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return fail(ClassConfig, "marshal: %v", err)
	}
	var dst net.Addr = &net.IPAddr{IP: net.IP(ip.AsSlice())}
	if network == "udp4" {
		dst = &net.UDPAddr{IP: net.IP(ip.AsSlice())}
	}
	dl := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	_ = pc.SetDeadline(dl)
	if _, err := pc.WriteTo(wire, dst); err != nil {
		return classify(err, "ping failed")
	}
	buf := make([]byte, 1500)
	for {
		n, peer, err := pc.ReadFrom(buf)
		if err != nil {
			return failDebug(ClassUnreachable, err.Error(), "ping failed: not all pings succeeded, packet loss of 100.000000")
		}
		if pa := peerIP(peer); pa != ip {
			continue
		}
		rm, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || rm.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		if e, ok := rm.Body.(*icmp.Echo); ok && e.Seq == 0 && (network == "udp4" || e.ID == id) {
			p.step("echo")
			if p.strict() && len(e.Data) != len(payload) {
				p.strictIssue("echo reply payload length %d != %d", len(e.Data), len(payload))
			}
			return nil
		}
	}
}

func peerIP(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.IPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	}
	return netip.Addr{}
}
