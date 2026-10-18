package capture

import (
	"testing"
)

// frame builds an Ethernet/IPv4 frame with a TCP or UDP payload.
func frameTCP(src, dst [16]byte, sport, dport uint16, payload []byte, flags byte) []byte {
	f := make([]byte, 0, 14+20+20+len(payload))
	// eth: dst mac, src mac, type 0x0800
	f = append(f, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0x08, 0x00)
	// ip
	total := 20 + 20 + len(payload)
	f = append(f, 0x45, 0, byte(total>>8), byte(total), 0, 0, 0x40, 0, 64, 6, 0, 0)
	f = append(f, src[12], src[13], src[14], src[15], dst[12], dst[13], dst[14], dst[15])
	// tcp
	f = append(f, byte(sport>>8), byte(sport), byte(dport>>8), byte(dport))
	f = append(f, 0, 0, 0, 0, 0, 0, 0, 0, byte(5<<4), flags, 0, 0, 0, 0, 0, 0)
	f = append(f, payload...)
	return f
}

func frameUDP(src, dst [16]byte, sport, dport uint16, payload []byte) []byte {
	f := make([]byte, 0, 14+20+8+len(payload))
	f = append(f, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0x08, 0x00)
	total := 20 + 8 + len(payload)
	f = append(f, 0x45, 0, byte(total>>8), byte(total), 0, 0, 0x40, 0, 64, 17, 0, 0)
	f = append(f, src[12], src[13], src[14], src[15], dst[12], dst[13], dst[14], dst[15])
	f = append(f, byte(sport>>8), byte(sport), byte(dport>>8), byte(dport))
	f = append(f, byte(len(payload)+8>>8), byte(len(payload)+8), 0, 0)
	f = append(f, payload...)
	return f
}

// TestModuleParsers: frames driven through the module's entry point
// (the same path AF_PACKET frames take) produce flow records and the
// right parser transactions for each declared service port.
func TestModuleParsers(t *testing.T) {
	caller := &testCaller{}
	ring := NewRing(1 << 20)
	m := New(nil, nil, map[int]string{8080: "http", 2525: "smtp", 11110: "pop3", 2121: "ftp", 5353: "dns"}, ring, caller)

	c := client()
	s := server()

	// SMTP session: the module must emit exchanges after Finish
	m.packet("lo", frameTCP(c, s, 44444, 2525, []byte("EHLO x\r\n"), 0x18))
	m.packet("lo", frameTCP(s, c, 2525, 44444, []byte("250 x\r\n"), 0x18))
	m.packet("lo", frameTCP(c, s, 44444, 2525, []byte("QUIT\r\n"), 0x18))
	m.packet("lo", frameTCP(s, c, 2525, 44444, []byte("221 bye\r\n"), 0x18))
	m.finishFlows()
	if got := caller.count("exchange"); got != 2 {
		t.Errorf("smtp exchanges: %d", got)
	}

	// POP3: USER/PASS
	m.packet("lo", frameTCP(c, s, 44445, 11110, []byte("USER bob\r\n"), 0x18))
	m.packet("lo", frameTCP(s, c, 11110, 44445, []byte("+OK\r\n"), 0x18))
	m.packet("lo", frameTCP(c, s, 44445, 11110, []byte("QUIT\r\n"), 0x18))
	m.packet("lo", frameTCP(s, c, 11110, 44445, []byte("+OK bye\r\n"), 0x18))
	m.finishFlows()
	if got := caller.count("exchange"); got != 4 {
		t.Errorf("exchanges after pop3: %d (want 4)", got)
	}

	// DNS over UDP
	q := dnsWireQuery(0x00aa, "svc.example", "A")
	m.packet("lo", frameUDP(c, s, 44446, 5353, q))
	if got := caller.count("dns"); got != 1 {
		t.Errorf("dns: %d", got)
	}
	// DNS over TCP, split across two packets
	a := dnsWireAnswer(0x00aa, "svc.example", "A", "10.9.9.9")
	framed := append(u16(len(a)), a...)
	m.packet("lo", frameTCP(c, s, 44447, 5353, framed[:4], 0x18))
	m.packet("lo", frameTCP(c, s, 44447, 5353, framed[4:], 0x18))
	if got := caller.count("dns"); got != 2 {
		t.Errorf("dns tcp: %d (want 2)", got)
	}

	// FTP with passive data: control on 2121, data on an ephemeral port
	m.packet("lo", frameTCP(c, s, 44448, 2121, []byte("USER ann\r\n"), 0x18))
	m.packet("lo", frameTCP(s, c, 2121, 44448, []byte("331 y\r\n"), 0x18))
	m.packet("lo", frameTCP(c, s, 44448, 2121, []byte("PASS p\r\n"), 0x18))
	m.packet("lo", frameTCP(s, c, 2121, 44448, []byte("230 ok\r\n"), 0x18))
	m.packet("lo", frameTCP(c, s, 44448, 2121, []byte("PASV\r\n"), 0x18))
	m.packet("lo", frameTCP(s, c, 2121, 44448, []byte("227 Entering Passive Mode (10,1,2,3,200,10)\r\n"), 0x18)) // 200*256+10 = 51210
	m.packet("lo", frameTCP(c, s, 44448, 2121, []byte("RETR f.txt\r\n"), 0x18))
	// data connection: server -> client:51210
	var ds [16]byte
	copy(ds[12:], []byte{10, 1, 2, 4})
	m.packet("lo", frameTCP(ds, c, 55555, 51210, []byte("FILE"), 0x18))
	m.packet("lo", frameTCP(c, s, 51210, 55555, nil, 0x10)) // ACK
	m.packet("lo", frameTCP(s, c, 2121, 44448, []byte("150 Opening data connection\r\n"), 0x18))
	m.packet("lo", frameTCP(ds, c, 55555, 51210, []byte("DATA"), 0x18))
	m.packet("lo", frameTCP(c, s, 51210, 55555, nil, 0x11)) // FIN/ACK closes data
	m.packet("lo", frameTCP(s, c, 2121, 44448, []byte("226 Transfer complete\r\n"), 0x18))
	m.finishFlows()
	// USER, PASS, PASV, RETR (with data) + the earlier 4
	if got := caller.count("exchange"); got != 8 {
		t.Errorf("exchanges after ftp: %d (want 8)", got)
	}
}

// TestModuleOwnTrafficExcluded: the agent's own traffic (loopback)
// must not produce transactions (no feedback loop, docs: Capture
// mechanics).
func TestModuleOwnTrafficExcluded(t *testing.T) {
	caller := &testCaller{}
	m := New(nil, nil, map[int]string{8080: "http"}, nil, caller)
	loop := client()
	loop[12] = 127
	loop[13] = 0
	loop[14] = 0
	loop[15] = 1
	m.packet("lo", frameTCP(loop, loop, 44449, 8080, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), 0x18))
	m.finishFlows()
	if got := caller.count("http"); got != 0 {
		t.Errorf("own traffic produced %d http transactions", got)
	}
}
