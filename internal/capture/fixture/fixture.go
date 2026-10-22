// Package fixture builds packet captures for tests: Ethernet frames carrying
// IPv4/IPv6 TCP sessions (with controllable segmentation, reordering, loss and
// teardown), UDP datagrams and ICMP echoes, written as pcap. It is test
// support, not part of the agent.
package fixture

import (
	"bytes"
	"net"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Frame is one captured packet.
type Frame struct {
	TS   time.Time
	Data []byte
}

// Capture accumulates frames with a monotonically advancing clock.
type Capture struct {
	Frames []Frame
	Now    time.Time
	Step   time.Duration // clock advance per frame (default 1 ms)
	VLAN   uint16        // non-zero adds an 802.1Q tag
	Raw    bool          // emit raw IP (LINKTYPE_RAW) instead of Ethernet
	Snap   int           // when > 0, PCAP() truncates each record to this many bytes (original length kept)
	id     uint16
}

// New starts a capture at t.
func New(t time.Time) *Capture { return &Capture{Now: t, Step: time.Millisecond} }

// Sleep advances the clock.
func (c *Capture) Sleep(d time.Duration) { c.Now = c.Now.Add(d) }

var (
	macA = net.HardwareAddr{2, 0, 0, 0, 0, 1}
	macB = net.HardwareAddr{2, 0, 0, 0, 0, 2}
)

func (c *Capture) emit(src, dst netip.Addr, proto layers.IPProtocol, l4 gopacket.SerializableLayer, setNet func(gopacket.NetworkLayer), payload []byte, ttl uint8) {
	c.id++
	var nl gopacket.SerializableLayer
	if src.Is4() {
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: ttl, Protocol: proto, SrcIP: src.AsSlice(), DstIP: dst.AsSlice(), Id: c.id, Flags: layers.IPv4DontFragment}
		if setNet != nil {
			setNet(ip)
		}
		nl = ip
	} else {
		ip := &layers.IPv6{Version: 6, HopLimit: ttl, NextHeader: proto, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}
		if setNet != nil {
			setNet(ip)
		}
		nl = ip
	}
	var ls []gopacket.SerializableLayer
	if !c.Raw {
		et := layers.EthernetTypeIPv4
		if !src.Is4() {
			et = layers.EthernetTypeIPv6
		}
		eth := &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: et}
		ls = append(ls, eth)
		if c.VLAN != 0 {
			eth.EthernetType = layers.EthernetTypeDot1Q
			ls = append(ls, &layers.Dot1Q{VLANIdentifier: c.VLAN, Type: et})
		}
	}
	ls = append(ls, nl)
	if l4 != nil {
		ls = append(ls, l4)
	}
	if payload != nil {
		ls = append(ls, gopacket.Payload(payload))
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		panic(err)
	}
	c.Frames = append(c.Frames, Frame{TS: c.Now, Data: append([]byte(nil), buf.Bytes()...)})
	c.Now = c.Now.Add(c.Step)
}

// UDP appends a datagram.
func (c *Capture) UDP(src, dst netip.AddrPort, payload []byte) {
	u := &layers.UDP{SrcPort: layers.UDPPort(src.Port()), DstPort: layers.UDPPort(dst.Port())}
	c.emit(src.Addr(), dst.Addr(), layers.IPProtocolUDP, u, func(n gopacket.NetworkLayer) { u.SetNetworkLayerForChecksum(n) }, payload, 64)
}

// Echo appends an ICMP (or ICMPv6) echo request or reply.
func (c *Capture) Echo(src, dst netip.Addr, reply bool, id, seq uint16, payload []byte) {
	if src.Is4() {
		t := uint8(layers.ICMPv4TypeEchoRequest)
		if reply {
			t = uint8(layers.ICMPv4TypeEchoReply)
		}
		ic := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(t, 0), Id: id, Seq: seq}
		c.emit(src, dst, layers.IPProtocolICMPv4, ic, nil, payload, 64)
		return
	}
	t := uint8(layers.ICMPv6TypeEchoRequest)
	if reply {
		t = uint8(layers.ICMPv6TypeEchoReply)
	}
	ic := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(t, 0)}
	echo := &layers.ICMPv6Echo{Identifier: id, SeqNumber: seq}
	c.emit(src, dst, layers.IPProtocolICMPv6, &icmp6Wrap{ic, echo}, func(n gopacket.NetworkLayer) { ic.SetNetworkLayerForChecksum(n) }, payload, 64)
}

// icmp6Wrap serialises an ICMPv6 header followed by its echo body.
type icmp6Wrap struct {
	h *layers.ICMPv6
	e *layers.ICMPv6Echo
}

func (w *icmp6Wrap) SerializeTo(b gopacket.SerializeBuffer, o gopacket.SerializeOptions) error {
	if err := w.e.SerializeTo(b, o); err != nil {
		return err
	}
	return w.h.SerializeTo(b, o)
}

func (w *icmp6Wrap) LayerType() gopacket.LayerType { return layers.LayerTypeICMPv6 }

// Conn is a scripted TCP connection.
type Conn struct {
	c           *Capture
	cli, srv    netip.AddrPort
	cseq, sseq  uint32 // next sequence number each side will send
	cack, sack  uint32 // the ack number each side sends (= peer's next seq)
	ClientOpen  bool
	established bool
	MSS         int
}

// TCP starts a connection description; nothing is emitted until Handshake.
func (c *Capture) TCP(client, server netip.AddrPort) *Conn {
	return &Conn{c: c, cli: client, srv: server, cseq: 1000, sseq: 500000, MSS: 1460}
}

func (cn *Conn) pkt(fromClient bool, seq, ack uint32, flags func(*layers.TCP), payload []byte) {
	src, dst := cn.cli, cn.srv
	if !fromClient {
		src, dst = cn.srv, cn.cli
	}
	t := &layers.TCP{SrcPort: layers.TCPPort(src.Port()), DstPort: layers.TCPPort(dst.Port()), Seq: seq, Ack: ack, Window: 64240}
	flags(t)
	cn.c.emit(src.Addr(), dst.Addr(), layers.IPProtocolTCP, t, func(n gopacket.NetworkLayer) { t.SetNetworkLayerForChecksum(n) }, payload, 64)
}

// Handshake emits SYN, SYN-ACK, ACK.
func (cn *Conn) Handshake() *Conn {
	cn.pkt(true, cn.cseq, 0, func(t *layers.TCP) { t.SYN = true }, nil)
	cn.cseq++
	cn.pkt(false, cn.sseq, cn.cseq, func(t *layers.TCP) { t.SYN, t.ACK = true, true }, nil)
	cn.sseq++
	cn.pkt(true, cn.cseq, cn.sseq, func(t *layers.TCP) { t.ACK = true }, nil)
	cn.established = true
	return cn
}

// SYNOnly emits a lone SYN (a connection attempt).
func (cn *Conn) SYNOnly() { cn.pkt(true, cn.cseq, 0, func(t *layers.TCP) { t.SYN = true }, nil) }

// Refuse emits a SYN answered by RST-ACK.
func (cn *Conn) Refuse() {
	cn.SYNOnly()
	cn.pkt(false, 0, cn.cseq+1, func(t *layers.TCP) { t.RST, t.ACK = true, true }, nil)
}

// Send emits data from one side in MSS-sized segments, each ACKed in the same
// packet (PSH|ACK) for compactness.
func (cn *Conn) Send(fromClient bool, data []byte) *Conn {
	for len(data) > 0 {
		n := min(len(data), cn.MSS)
		cn.Segment(fromClient, 0, data[:n], true)
		data = data[n:]
	}
	return cn
}

// Chunks sends each element as its own segment, in order.
func (cn *Conn) Chunks(fromClient bool, parts ...[]byte) *Conn {
	for _, p := range parts {
		cn.Segment(fromClient, 0, p, true)
	}
	return cn
}

// Segment emits one data segment at offset off bytes beyond the sender's next
// sequence number. With advance it moves the send position past the segment;
// without, it leaves the position (to send later segments first, reorder, or
// retransmit).
func (cn *Conn) Segment(fromClient bool, off int, data []byte, advance bool) {
	if fromClient {
		cn.pkt(true, cn.cseq+uint32(off), cn.sseq, func(t *layers.TCP) { t.ACK, t.PSH = true, true }, data)
		if advance {
			cn.cseq += uint32(len(data))
		}
	} else {
		cn.pkt(false, cn.sseq+uint32(off), cn.cseq, func(t *layers.TCP) { t.ACK, t.PSH = true, true }, data)
		if advance {
			cn.sseq += uint32(len(data))
		}
	}
}

// Skip advances a sender's sequence number by n bytes never sent (loss).
func (cn *Conn) Skip(fromClient bool, n int) {
	if fromClient {
		cn.cseq += uint32(n)
	} else {
		cn.sseq += uint32(n)
	}
}

// Keepalive emits a zero-length ACK with seq-1, as TCP keepalives do.
func (cn *Conn) Keepalive(fromClient bool) {
	if fromClient {
		cn.pkt(true, cn.cseq-1, cn.sseq, func(t *layers.TCP) { t.ACK = true }, nil)
	} else {
		cn.pkt(false, cn.sseq-1, cn.cseq, func(t *layers.TCP) { t.ACK = true }, nil)
	}
}

// Close emits FIN/ACK each way and the final ACK.
func (cn *Conn) Close() {
	cn.pkt(true, cn.cseq, cn.sseq, func(t *layers.TCP) { t.FIN, t.ACK = true, true }, nil)
	cn.cseq++
	cn.pkt(false, cn.sseq, cn.cseq, func(t *layers.TCP) { t.FIN, t.ACK = true, true }, nil)
	cn.sseq++
	cn.pkt(true, cn.cseq, cn.sseq, func(t *layers.TCP) { t.ACK = true }, nil)
}

// Reset emits RST from one side.
func (cn *Conn) Reset(fromClient bool) {
	if fromClient {
		cn.pkt(true, cn.cseq, cn.sseq, func(t *layers.TCP) { t.RST, t.ACK = true, true }, nil)
	} else {
		cn.pkt(false, cn.sseq, cn.cseq, func(t *layers.TCP) { t.RST, t.ACK = true, true }, nil)
	}
}

// PCAP serialises the capture (Ethernet unless Raw).
func (c *Capture) PCAP() []byte {
	var b bytes.Buffer
	lt := layers.LinkTypeEthernet
	if c.Raw {
		lt = layers.LinkTypeRaw
	}
	w := pcapgo.NewWriter(&b)
	if err := w.WriteFileHeader(65535, lt); err != nil {
		panic(err)
	}
	for _, f := range c.Frames {
		d := f.Data
		if c.Snap > 0 && len(d) > c.Snap {
			d = d[:c.Snap]
		}
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: f.TS, CaptureLength: len(d), Length: len(f.Data)}, d); err != nil {
			panic(err)
		}
	}
	return b.Bytes()
}
