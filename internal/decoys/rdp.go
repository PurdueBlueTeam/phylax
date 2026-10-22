package decoys

import (
	"bytes"
	"io"
	"net"
	"time"
)

// serveRDP reads the X.224 connection request, records the mstshash cookie
// (the user name the client is trying), answers a standard-RDP connection
// confirm and then discards what follows. It negotiates only.
func (m *Module) serveRDP(s *sess, c net.Conn) {
	s.idle()
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 3 {
		return
	}
	n := int(h[2])<<8 | int(h[3])
	if n < 11 || n > 512 {
		return
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(c, body); err != nil {
		return
	}
	const ck = "Cookie: mstshash="
	if i := bytes.Index(body, []byte(ck)); i >= 0 {
		rest := body[i+len(ck):]
		if j := bytes.IndexAny(rest, "\r\n"); j >= 0 {
			rest = rest[:j]
		}
		s.credential(string(rest), "", "rdp_cookie")
	} else {
		s.hit(StageRequest, SevInfo, map[string]any{"detail": "x224_connection_request"})
	}
	s.pause()
	// TPKT + X.224 CC + RDP_NEG_RSP(selectedProtocol=0)
	_, _ = c.Write([]byte{3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, 2, 0, 8, 0, 0, 0, 0, 0})
	_ = c.SetReadDeadline(time.Now().Add(m.cfg.IdleTimeout))
	_, _ = io.Copy(io.Discard, io.LimitReader(c, 8192))
}

// serveSMB is a banner-only lookalike for NetBIOS/SMB-ish ports other than
// 445: it records the first bytes and answers a NetBIOS negative session
// response. Port 445 is refused at configuration time.
func (m *Module) serveSMB(s *sess, c net.Conn) {
	s.idle()
	buf := make([]byte, 512)
	n, _ := c.Read(buf)
	if n > 0 {
		s.hit(StageRequest, SevInfo, map[string]any{"detail": "smb_first_bytes", "first_bytes_len": n})
	}
	s.pause()
	_, _ = c.Write([]byte{0x83, 0, 0, 1, 0x82})
}
