package capture

import (
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	netmod "github.com/PurdueBlueTeam/phylax/internal/collect/net"
)

// parsed is the result of decoding one frame down to the transport layer.
type parsed struct {
	ok           bool
	src, dst     netip.Addr
	proto        uint8
	sport, dport uint16
	ipLen        int // IP total length (header + payload) as on the wire
	payloadWire  int // transport payload bytes on the wire
	payload      []byte
	icmpMsg      []byte
	tcp          *layers.TCP
}

type decoder struct {
	link layers.LinkType
	eth  layers.Ethernet
	vlan layers.Dot1Q
	ip4  layers.IPv4
	ip6  layers.IPv6
	tcp  layers.TCP
	udp  layers.UDP
	ic4  layers.ICMPv4
	ic6  layers.ICMPv6
	pl   gopacket.Payload

	pEth, pIP4, pIP6 *gopacket.DecodingLayerParser
	dl               []gopacket.LayerType
}

func newDecoder() decoder { return decoder{link: layers.LinkTypeEthernet} }

// A decoder holds pointers to its own fields, so it must be built in place.
func (d *decoder) init() {
	mk := func(first gopacket.LayerType) *gopacket.DecodingLayerParser {
		p := gopacket.NewDecodingLayerParser(first, &d.eth, &d.vlan, &d.ip4, &d.ip6, &d.tcp, &d.udp, &d.ic4, &d.ic6, &d.pl)
		p.IgnoreUnsupported = true
		return p
	}
	d.pEth, d.pIP4, d.pIP6 = mk(layers.LayerTypeEthernet), mk(layers.LayerTypeIPv4), mk(layers.LayerTypeIPv6)
}

func (d *decoder) setLink(l layers.LinkType) { d.link = l }

func (d *decoder) decode(data []byte) (parsed, error) {
	if d.pEth == nil {
		d.init()
	}
	var p parsed
	var par *gopacket.DecodingLayerParser
	switch d.link {
	case layers.LinkTypeRaw, layers.LinkTypeIPv4, layers.LinkTypeIPv6:
		if len(data) == 0 {
			return p, nil
		}
		if data[0]>>4 == 6 {
			par = d.pIP6
		} else {
			par = d.pIP4
		}
	default:
		par = d.pEth
	}
	d.dl = d.dl[:0]
	err := par.DecodeLayers(data, &d.dl)
	extra := 0
	for _, lt := range d.dl {
		switch lt {
		case layers.LayerTypeIPv4:
			p.ok = true
			p.src, p.dst = addr(d.ip4.SrcIP), addr(d.ip4.DstIP)
			p.proto = uint8(d.ip4.Protocol)
			p.ipLen = int(d.ip4.Length)
			if p.ipLen == 0 {
				p.ipLen = len(data)
			}
			extra = int(d.ip4.IHL) * 4
		case layers.LayerTypeIPv6:
			p.ok = true
			p.src, p.dst = addr(d.ip6.SrcIP), addr(d.ip6.DstIP)
			p.proto = uint8(d.ip6.NextHeader)
			p.ipLen = 40 + int(d.ip6.Length)
			extra = 40
		case layers.LayerTypeTCP:
			p.proto = netmod.ProtoTCP
			p.sport, p.dport = uint16(d.tcp.SrcPort), uint16(d.tcp.DstPort)
			p.tcp = &d.tcp
			p.payload = d.tcp.Payload
			p.payloadWire = p.ipLen - extra - int(d.tcp.DataOffset)*4
		case layers.LayerTypeUDP:
			p.proto = netmod.ProtoUDP
			p.sport, p.dport = uint16(d.udp.SrcPort), uint16(d.udp.DstPort)
			p.payload = d.udp.Payload
			p.payloadWire = int(d.udp.Length) - 8
		case layers.LayerTypeICMPv4:
			p.proto = netmod.ProtoICMP
			p.icmpMsg = append(append([]byte(nil), d.ic4.Contents...), d.ic4.Payload...)
		case layers.LayerTypeICMPv6:
			p.proto = netmod.ProtoICMPv6
			p.icmpMsg = append(append([]byte(nil), d.ic6.Contents...), d.ic6.Payload...)
		}
	}
	if p.ok && p.tcp == nil && p.proto != netmod.ProtoUDP && p.proto != netmod.ProtoICMP && p.proto != netmod.ProtoICMPv6 &&
		len(d.ip6.Contents) == 40 && d.dl[len(d.dl)-1] == layers.LayerTypeIPv6 {
		d.v6ext(&p, extra)
	}
	if p.payloadWire < 0 {
		p.payloadWire = 0
	}
	if p.tcp != nil && p.payloadWire < len(p.payload) {
		p.payloadWire = len(p.payload)
	}
	return p, err
}

func addr(ip []byte) netip.Addr {
	a, _ := netip.AddrFromSlice(ip)
	return a.Unmap()
}

// v6ext walks IPv6 extension headers (not DecodingLayers in gopacket) to reach
// TCP, UDP or ICMPv6. Fragments other than the first are left undecoded.
func (d *decoder) v6ext(p *parsed, extra int) {
	nh := uint8(d.ip6.NextHeader)
	rest := d.ip6.Payload
	for i := 0; i < 8; i++ {
		switch nh {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(rest) < 8 {
				return
			}
			n := (int(rest[1]) + 1) * 8
			if n > len(rest) {
				return
			}
			nh, rest, extra = rest[0], rest[n:], extra+n
		case 44: // fragment: only an unfragmented-looking first fragment carries the header
			if len(rest) < 8 || (uint16(rest[2])<<8|uint16(rest[3]))>>3 != 0 {
				return
			}
			nh, rest, extra = rest[0], rest[8:], extra+8
		case netmod.ProtoTCP:
			if d.tcp.DecodeFromBytes(rest, gopacket.NilDecodeFeedback) != nil {
				return
			}
			p.proto = netmod.ProtoTCP
			p.sport, p.dport = uint16(d.tcp.SrcPort), uint16(d.tcp.DstPort)
			p.tcp, p.payload = &d.tcp, d.tcp.Payload
			p.payloadWire = p.ipLen - extra - int(d.tcp.DataOffset)*4
			return
		case netmod.ProtoUDP:
			if d.udp.DecodeFromBytes(rest, gopacket.NilDecodeFeedback) != nil {
				return
			}
			p.proto = netmod.ProtoUDP
			p.sport, p.dport = uint16(d.udp.SrcPort), uint16(d.udp.DstPort)
			p.payload, p.payloadWire = d.udp.Payload, int(d.udp.Length)-8
			return
		case netmod.ProtoICMPv6:
			if d.ic6.DecodeFromBytes(rest, gopacket.NilDecodeFeedback) != nil {
				return
			}
			p.proto = netmod.ProtoICMPv6
			p.icmpMsg = append(append([]byte(nil), d.ic6.Contents...), d.ic6.Payload...)
			return
		default:
			return
		}
	}
}
