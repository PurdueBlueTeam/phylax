package checks

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

var qtypeNames = map[string]uint16{
	"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12,
	"MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33,
}

func qtypeValue(v any) (uint16, error) {
	if f, ok := toFloat(v); ok {
		if f < 1 || f > 65535 {
			return 0, fmt.Errorf("bad qtype %v", v)
		}
		return uint16(f), nil
	}
	s := strings.ToUpper(strings.TrimSpace(asString(v)))
	t, ok := qtypeNames[s]
	if !ok {
		return 0, fmt.Errorf("unknown qtype %v", v)
	}
	return t, nil
}

// runDNS sends one query and reports the answer records as strings
// (A/AAAA as IPs, CNAME/NS/PTR as names, MX as "prio name", TXT as text).
func runDNS(ctx context.Context, ck Check) (map[string]any, error) {
	server, err := pstr(ck.Params, "server")
	if err != nil {
		return nil, err
	}
	name, err := pstr(ck.Params, "name")
	if err != nil {
		return nil, err
	}
	qt := uint16(1) // A
	if v, ok := ck.Params["qtype"]; ok {
		if qt, err = qtypeValue(v); err != nil {
			return nil, err
		}
	}
	addr, err := addrWithDefaultPort(server, ck)
	if err != nil {
		return nil, fmt.Errorf("dns: %v", err)
	}

	id := queryID(name, qt)
	buf := make([]byte, 0, 128)
	buf = binary.BigEndian.AppendUint16(buf, id)
	buf = binary.BigEndian.AppendUint16(buf, 0x0100) // RD
	buf = binary.BigEndian.AppendUint16(buf, 1)      // QDCOUNT
	buf = append(buf, 0, 0, 0, 0, 0, 0) // ANCOUNT, NSCOUNT, ARCOUNT
	buf = encodeDNSName(buf, name)
	buf = binary.BigEndian.AppendUint16(buf, qt)
	buf = binary.BigEndian.AppendUint16(buf, 1) // IN

	conn, err := net.DialTimeout("udp", addr, dialTimeout(ctx))
	if err != nil {
		return nil, fmt.Errorf("dns: %v", err)
	}
	defer conn.Close()
	if err := setConnDeadline(conn, ctx); err != nil {
		return nil, fmt.Errorf("dns: %v", err)
	}
	if _, err := conn.Write(buf); err != nil {
		return nil, fmt.Errorf("dns: %v", err)
	}
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("dns: no response: %v", err)
	}
	answers, err := parseDNSAnswers(resp[:n], id)
	if err != nil {
		return nil, fmt.Errorf("dns: %v (resp %x)", err, resp[:n])
	}
	return map[string]any{"answers": answers}, nil
}

// queryID derives a stable 16-bit pseudo-random query ID per check.
func queryID(name string, qt uint16) uint16 {
	return uint16(fnvHash32(name + ":" + strconv.Itoa(int(qt))) & 0xffff)
}

func fnvHash32(s string) uint32 {
	var h uint32 = 2166136261
	for i := range len(s) {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

func encodeDNSName(buf []byte, name string) []byte {
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	return append(buf, 0)
}

// parseDNSAnswers validates the header and extracts the answer records.
func parseDNSAnswers(b []byte, id uint16) ([]string, error) {
	if len(b) < 12 {
		return nil, fmt.Errorf("short response")
	}
	if binary.BigEndian.Uint16(b[0:2]) != id {
		return nil, fmt.Errorf("query id mismatch")
	}
	ancount := int(binary.BigEndian.Uint16(b[6:8]))
	// Skip the question section: the encoded name at offset 12 (up to the
	// trailing 0), then 4 bytes of qtype/qclass.
	off := 12
	for off < len(b) && b[off] != 0 {
		l := int(b[off] & 0x3f)
		if b[off]&0xc0 == 0xc0 {
			off += 2
			break
		}
		off += 1 + l
	}
	if off < len(b) {
		off++ // the 0
	}
	off += 4 // qtype + qclass
	if off > len(b) {
		return nil, fmt.Errorf("truncated question")
	}

	var answers []string
	for range ancount {
		// Answer name: a plain label run or a compression pointer.
		if off >= len(b) {
			return nil, fmt.Errorf("truncated answer name")
		}
		if b[off]&0xc0 != 0xc0 {
			for off < len(b) && b[off] != 0 {
				off += 1 + int(b[off]&0x3f)
			}
			off++
		} else {
			off += 2
		}
		if off+10 > len(b) {
			return nil, fmt.Errorf("truncated answer")
		}
		typ := binary.BigEndian.Uint16(b[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(b[off+8 : off+10]))
		off += 10
		if off+rdlen > len(b) {
			return nil, fmt.Errorf("truncated rdata")
		}
		if s, ok := decodeAnswer(typ, b[off:off+rdlen], b); ok {
			answers = append(answers, s)
		}
		off += rdlen
	}
	return answers, nil
}

func decodeAnswer(typ uint16, rdata, pkt []byte) (string, bool) {
	switch typ {
	case 1: // A
		if len(rdata) == 4 {
			return net.IP(rdata).String(), true
		}
	case 28: // AAAA
		if len(rdata) == 16 {
			return net.IP(rdata).String(), true
		}
	case 5, 2, 12: // CNAME, NS, PTR
		return decodeNameField(rdata, pkt)
	case 15: // MX
		if len(rdata) >= 3 {
			if s, ok := decodeNameField(rdata[2:], pkt); ok {
				return fmt.Sprintf("%d %s", binary.BigEndian.Uint16(rdata[0:2]), s), true
			}
		}
	case 16: // TXT
		var parts []string
		off := 0
		for off < len(rdata) {
			l := int(rdata[off])
			off++
			if off+l > len(rdata) {
				break
			}
			parts = append(parts, string(rdata[off:off+l]))
			off += l
		}
		return strings.Join(parts, " "), true
	}
	return "", false
}

// decodeNameField reads a domain name from rdata, which is either a plain
// encoded name or a single compression pointer into the packet.
func decodeNameField(rdata, pkt []byte) (string, bool) {
	if len(rdata) >= 2 && rdata[0]&0xc0 == 0xc0 {
		return readDNSName(pkt, int(binary.BigEndian.Uint16(rdata[0:2])))
	}
	var labels []string
	off := 0
	for off < len(rdata) {
		tag := rdata[off]
		if tag == 0 {
			off++
			break
		}
		if tag&0xc0 != 0 {
			return "", false
		}
		if off+1+int(tag) > len(rdata) {
			return "", false
		}
		labels = append(labels, string(rdata[off+1:off+1+int(tag)]))
		off += 1 + int(tag)
	}
	if len(labels) == 0 {
		return "", false
	}
	return strings.Join(labels, "."), true
}

// readDNSName decodes a domain name at off within pkt, following
// compression pointers.
func readDNSName(pkt []byte, off int) (string, bool) {
	var labels []string
	seen := 0
	for {
		if off >= len(pkt) || seen > 32 {
			return "", false
		}
		tag := pkt[off]
		switch {
		case tag == 0:
			if len(labels) == 0 {
				return "", false
			}
			return strings.Join(labels, "."), true
		case tag&0xc0 == 0xc0:
			if off+1 >= len(pkt) {
				return "", false
			}
			off = int(binary.BigEndian.Uint16(pkt[off : off+2]))
		case tag&0xc0 == 0x80:
			return "", false
		default:
			if off+1+int(tag) > len(pkt) {
				return "", false
			}
			labels = append(labels, string(pkt[off+1:off+1+int(tag)]))
			off += 1 + int(tag)
		}
		seen++
	}
}
