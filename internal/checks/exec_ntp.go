package checks

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"time"
)

const (
	ntpPacketSize = 48
	ntpEpochDelta = 2208988800 // seconds between 1900 and 1970
)

// runNTP sends one minimal mode-3 query and reports reachability plus the
// clock offset in milliseconds ((T2-T1)+(T3-T4))/2.
func runNTP(ctx context.Context, ck Check) (map[string]any, error) {
	server, err := pstr(ck.Params, "server")
	if err != nil {
		return nil, err
	}
	addr, err := addrWithDefaultPort(server, ck)
	if err != nil {
		return nil, fmt.Errorf("ntp: %v", err)
	}
	conn, err := net.DialTimeout("udp", addr, dialTimeout(ctx))
	if err != nil {
		return nil, fmt.Errorf("ntp: %v", err)
	}
	defer conn.Close()
	if err := setConnDeadline(conn, ctx); err != nil {
		return nil, fmt.Errorf("ntp: %v", err)
	}

	pkt := make([]byte, ntpPacketSize)
	pkt[0] = 0x23 // LI=0, VN=4, mode 3 (client)
	t1 := time.Now()
	if _, err := conn.Write(pkt); err != nil {
		return nil, fmt.Errorf("ntp: %v", err)
	}
	if _, err := conn.Read(pkt); err != nil {
		return nil, fmt.Errorf("ntp: no response from %s: %v", addr, err)
	}
	t4 := time.Now()
	if pkt[0]&0x07 < 4 { // expect mode 4 (server) or 5 (broadcast)
		return nil, fmt.Errorf("ntp: bad mode %d in response", pkt[0]&0x07)
	}
	t2, t3 := ntpTime(pkt[32:40]), ntpTime(pkt[40:48]) // recv, xmit
	if t2 == 0 || t3 == 0 {
		return nil, fmt.Errorf("ntp: zero timestamps in response")
	}
	t1f := float64(t1.Unix()) + float64(t1.Nanosecond())/1e9
	t4f := float64(t4.Unix()) + float64(t4.Nanosecond())/1e9
	offsetMS := math.Round((t2-t1f + t3-t4f) * 1000 * 100) / 100
	return map[string]any{"reachable": true, "offset_ms": offsetMS}, nil
}

func ntpTime(b []byte) float64 {
	secs := binary.BigEndian.Uint32(b[0:4])
	frac := binary.BigEndian.Uint32(b[4:8])
	if secs == 0 {
		return 0
	}
	return float64(secs-ntpEpochDelta) + float64(frac)/4294967296
}
