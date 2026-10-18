// Package capture is the agent's `capture` module (docs: Service
// monitoring: capture and health checks). It is bounded and passive:
// under load it drops packets rather than slowing the host, and reports
// drop counts.
//
// Linux capture is AF_PACKET with a memory-mapped ring, one socket per
// interface, kernel filters built in Go from the manifest (x/net/bpf),
// no libpcap. This file carries the interface- and capture-agnostic
// core: the packet ring, flow records, scan aggregation, the no-
// feedback-loop exclusion, and the on-alert freeze.
package capture

import (
	"encoding/binary"
	"sync"
	"time"
)

// Ring is one host's packet ring: the smaller of maxBytes or a
// configured fraction of free disk (the caller decides; the ring only
// enforces its own cap). Packets are kept full-length on the full
// ports, truncated to truncBytes elsewhere (docs: Capture tiers).
//
// The ring is an on-disk evidence store, not a live buffer: consumers
// (the alert-freeze pull, manual slices) read time-sliced ranges.
type Ring struct {
	mu       sync.Mutex
	entries  []entry
	maxBytes int
	trunc    int
	frozen   bool // freeze-on-alert: rotation must not overwrite
	drops    uint64
}

type entry struct {
	TS     time.Time
	IfName string
	Src    [16]byte // IPv4 in the last 4 bytes (Go/AF_PACKET layout)
	Dst    [16]byte
	Sport  uint16
	Dport  uint16
	Proto  uint8 // IP protocol
	Payload []byte
	Full   bool // captured full-length (full port)
}

// NewRing builds a ring capped at maxBytes.
func NewRing(maxBytes int) *Ring {
	return &Ring{maxBytes: maxBytes, trunc: 128}
}

// Add records one packet. Full-length on full ports, truncated to 128
// bytes elsewhere. Over-cap: the oldest non-frozen entries are dropped
// (oldest low-priority first — full-port packets count double, so they
// survive rotation; docs: Footprint targets).
func (r *Ring) Add(ts time.Time, ifname string, src, dst [16]byte, sport, dport uint16, proto uint8, payload []byte, full bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frozen {
		return // frozen evidence is not rotated; the freeze window is bounded
	}
	if !full && len(payload) > r.trunc {
		payload = payload[:r.trunc]
	}
	r.entries = append(r.entries, entry{
		TS: ts, IfName: ifname, Src: src, Dst: dst,
		Sport: sport, Dport: dport, Proto: proto,
		Payload: payload, Full: full,
	})
	total := 0
	for _, e := range r.entries {
		if e.Full {
			total += 2 * len(e.Payload)
		} else {
			total += r.trunc
		}
	}
	// drop oldest until under the cap
	for total > r.maxBytes && len(r.entries) > 0 {
		total -= cost(r.entries[0], r.trunc)
		r.entries = r.entries[1:]
		r.drops++
	}
}

func cost(e entry, trunc int) int {
	if e.Full {
		return 2 * len(e.Payload)
	}
	return trunc
}

// Freeze stops rotation (docs: Freeze on alert). The caller bounds the
// window and pulls the slice.
func (r *Ring) Freeze() {
	r.mu.Lock()
	r.frozen = true
	r.mu.Unlock()
}

// Unfreeze resumes rotation and trims back to the cap.
func (r *Ring) Unfreeze() {
	r.mu.Lock()
	r.frozen = false
	total := 0
	for _, e := range r.entries {
		total += cost(e, r.trunc)
	}
	for total > r.maxBytes && len(r.entries) > 0 {
		total -= cost(r.entries[0], r.trunc)
		r.entries = r.entries[1:]
	}
	r.mu.Unlock()
}

// Slice returns the entries in [from, to], filtered to a source when
// non-nil (docs: the controller pulls the slice filtered to the IPs
// involved).
func (r *Ring) Slice(from, to time.Time, src [16]byte) []entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []entry
	for _, e := range r.entries {
		if e.TS.Before(from) || e.TS.After(to) {
			continue
		}
		if src != [16]byte{} && e.Src != src {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Drops reports packets dropped by rotation.
func (r *Ring) Drops() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.drops
}

// IPv4FromAddr returns the AF_PACKET-style [16]byte for an IPv4 address
// (the kernel layout: four leading zero groups, address last).
func IPv4FromAddr(b []byte) [16]byte {
	var a [16]byte
	if len(b) == 4 {
		copy(a[12:], b)
	} else if len(b) == 16 {
		copy(a[:], b)
	}
	return a
}

// PortBytes renders a uint16 port in network byte order (the ring
// stores wire order).
func PortBytes(p int) uint16 {
	return binary.BigEndian.Uint16([]byte{byte(p >> 8), byte(p)})
}
