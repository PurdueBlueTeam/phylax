package capture

import (
	"testing"
	"time"

	"github.com/google/gopacket"

	"github.com/PurdueBlueTeam/phylax/internal/capture/fixture"
)

// FuzzProcess feeds arbitrary bytes as link-layer frames, in sequences, to a
// full Engine: decoding, flow tracking, reassembly and every parser behind it.
func FuzzProcess(f *testing.F) {
	c := newCap()
	cn := c.TCP(ap("10.0.0.5:40000"), ap("10.0.0.9:80")).Handshake()
	cn.Send(true, []byte(quotientReq))
	cn.Send(false, []byte(okResp))
	cn.Close()
	c.UDP(ap("10.0.0.5:51000"), ap("10.0.0.100:53"), fixture.DNSQuery(9, "a.b", 1, true))
	c.Echo(ip4("10.0.0.5"), ip4("10.0.0.9"), false, 1, 1, make([]byte, 24))
	v6 := newCap()
	v6.TCP(ap("[fd00::5]:40000"), ap("[fd00::9]:22")).Handshake().Send(true, []byte("SSH-2.0-x\r\n"))
	for _, fr := range append(c.Frames, v6.Frames...) {
		f.Add(fr.Data, uint8(0))
	}
	f.Fuzz(func(t *testing.T, data []byte, mut uint8) {
		e := NewEngine(Config{MaxFlows: 64, Ring: RingConfig{MaxPackets: 64}})
		ts := time.Unix(1700000000, 0)
		// the frame itself, a copy with a flipped byte, and a truncated copy
		frames := [][]byte{data}
		if len(data) > 0 {
			m := append([]byte(nil), data...)
			m[int(mut)%len(m)] ^= 0xff
			frames = append(frames, m, data[:len(data)/2])
		}
		for i, d := range frames {
			e.Process(gopacket.CaptureInfo{Timestamp: ts.Add(time.Duration(i) * time.Millisecond), CaptureLength: len(d), Length: len(d)}, d)
		}
		e.Flush(ts)
		if e.Stats().FlowsActive != 0 {
			t.Fatal("flush left flows")
		}
	})
}
