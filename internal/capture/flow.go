package capture

import (
	"net/netip"
	"time"
)

// Flow is the record shipped for one connection (or UDP/ICMP exchange). It is
// emitted when the flow ends, never while it is open.
type Flow struct {
	CommunityID string         `json:"community_id"`
	Proto       uint8          `json:"proto"` // IP protocol number
	Client      netip.AddrPort `json:"client"`
	Server      netip.AddrPort `json:"server"`
	Start       time.Time      `json:"start"`
	End         time.Time      `json:"end"`

	PktsC2S    int64 `json:"pkts_c2s"`
	PktsS2C    int64 `json:"pkts_s2c"`
	BytesC2S   int64 `json:"bytes_c2s"` // IP bytes on the wire
	BytesS2C   int64 `json:"bytes_s2c"`
	PayloadC2S int64 `json:"payload_c2s"` // transport payload bytes
	PayloadS2C int64 `json:"payload_s2c"`

	Handshake string `json:"handshake,omitempty"` // tcp: established, refused, timeout, midstream
	Resets    int    `json:"resets,omitempty"`
	ResetBy   string `json:"reset_by,omitempty"` // client or server
	EndReason string `json:"end_reason"`         // fin, rst, idle, evicted, shutdown

	// FirstC2S and FirstS2C are SHA-256 (hex) of the first up to 64 payload
	// bytes each way: a cheap fingerprint of the opening exchange for protocols
	// no parser handles.
	FirstC2S string `json:"first_c2s,omitempty"`
	FirstS2C string `json:"first_s2c,omitempty"`

	Service   string `json:"service,omitempty"`    // parser that handled it, or "ftp-data(...)"
	RelatedTo string `json:"related_to,omitempty"` // Community ID of the control flow that announced this one
	Scan      bool   `json:"scan,omitempty"`       // part of an aggregated scan; see Scan events
	Txns      int    `json:"txns,omitempty"`
	Truncated bool   `json:"truncated,omitempty"` // payload was cut short by snap length or a reassembly gap

	Stored int64 `json:"stored_bytes,omitempty"` // bytes of this flow kept in full in the ring
}

// Scan aggregates a source touching many closed or silent ports/hosts.
type Scan struct {
	Src     netip.Addr `json:"src"`
	Start   time.Time  `json:"start"`
	End     time.Time  `json:"end"`
	Targets int        `json:"targets"` // distinct address:port pairs touched
	Hosts   int        `json:"hosts"`
	Final   bool       `json:"final"` // false when first reported, true when the window closed
}

type scanState struct {
	first, last time.Time
	targets     map[netip.AddrPort]struct{}
	reported    bool
}

const (
	maxScanSources = 1024
	maxScanTargets = 4096
)

// scanTracker watches failed or empty connections per source.
type scanTracker struct {
	threshold int
	window    time.Duration
	m         map[netip.Addr]*scanState
}

func newScanTracker(threshold int, window time.Duration) *scanTracker {
	return &scanTracker{threshold: threshold, window: window, m: map[netip.Addr]*scanState{}}
}

// note records one probe and returns a Scan to report when the threshold is
// first crossed. scanning reports whether src is currently a reported scanner.
func (t *scanTracker) note(src netip.Addr, dst netip.AddrPort, ts time.Time) (s *Scan, scanning bool) {
	st := t.m[src]
	if st != nil && ts.Sub(st.last) > t.window {
		// stale window; expire() will report it, start fresh here
		st = nil
	}
	if st == nil {
		if len(t.m) >= maxScanSources {
			return nil, false
		}
		st = &scanState{first: ts, targets: map[netip.AddrPort]struct{}{}}
		t.m[src] = st
	}
	st.last = ts
	if len(st.targets) < maxScanTargets {
		st.targets[dst] = struct{}{}
	}
	if !st.reported && len(st.targets) >= t.threshold {
		st.reported = true
		return st.scan(src, false), true
	}
	return nil, st.reported
}

func (st *scanState) scan(src netip.Addr, final bool) *Scan {
	hosts := map[netip.Addr]struct{}{}
	for ap := range st.targets {
		hosts[ap.Addr()] = struct{}{}
	}
	return &Scan{Src: src, Start: st.first, End: st.last, Targets: len(st.targets), Hosts: len(hosts), Final: final}
}

// expire reports and forgets windows that have gone quiet.
func (t *scanTracker) expire(now time.Time, emit func(Scan)) {
	for src, st := range t.m {
		if now.Sub(st.last) > t.window {
			if st.reported {
				emit(*st.scan(src, true))
			}
			delete(t.m, src)
		}
	}
}

func (t *scanTracker) flush(emit func(Scan)) {
	for src, st := range t.m {
		if st.reported {
			emit(*st.scan(src, true))
		}
		delete(t.m, src)
	}
}
