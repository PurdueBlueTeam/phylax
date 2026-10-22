package capture

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Defaults for a host ring. Production sizing (the smaller of 2 GB or 10% of
// free disk) is the caller's decision; the ring itself only enforces bounds.
const (
	DefaultRingBytes   = 256 << 20
	DefaultRingPackets = 2_000_000
	DefaultHoldBytes   = 256 << 20
)

// Packet is one stored packet.
type Packet struct {
	TS      time.Time
	OrigLen int // length on the wire
	Data    []byte
	Src     netip.Addr // zero for non-IP
	Dst     netip.Addr
}

// RingStats reports ring occupancy and loss.
type RingStats struct {
	Packets   int
	Bytes     int64
	Evicted   uint64 // packets pushed out by newer ones
	HoldDrops uint64 // packets not added to a hold because its budget was full
	Holds     int
	Oldest    time.Time
	Newest    time.Time
}

// Ring is a bounded in-memory packet ring shared by the capture goroutine and
// the freeze/pull callers. It stores each packet in its own slice, so the
// source may reuse its buffer. Memory is bounded by MaxBytes plus the holds'
// budget; the oldest packets are evicted first.
type Ring struct {
	mu       sync.Mutex
	maxBytes int64
	maxPkts  int
	holdMax  int64
	link     layers.LinkType

	buf   []Packet // circular
	head  int
	count int
	bytes int64

	evicted   uint64
	holdDrops uint64
	holds     map[string]*hold
}

type hold struct {
	from, to time.Time
	ips      map[netip.Addr]bool
	pkts     []Packet
	bytes    int64
	closed   bool
	full     bool
}

// RingConfig bounds a Ring.
type RingConfig struct {
	MaxBytes   int64
	MaxPackets int
	HoldBytes  int64 // total budget across all freezes
	LinkType   layers.LinkType
}

// NewRing makes an empty ring. Zero fields take the defaults.
func NewRing(c RingConfig) *Ring {
	if c.MaxBytes <= 0 {
		c.MaxBytes = DefaultRingBytes
	}
	if c.MaxPackets <= 0 {
		c.MaxPackets = DefaultRingPackets
	}
	if c.HoldBytes <= 0 {
		c.HoldBytes = DefaultHoldBytes
	}
	if c.LinkType == 0 {
		c.LinkType = layers.LinkTypeEthernet
	}
	return &Ring{maxBytes: c.MaxBytes, maxPkts: c.MaxPackets, holdMax: c.HoldBytes, link: c.LinkType, holds: map[string]*hold{}}
}

func (p Packet) cost() int64 { return int64(len(p.Data)) + 64 }

// Add stores a packet. data is copied. It reports false if the packet alone
// exceeds the ring.
func (r *Ring) Add(ts time.Time, origLen int, data []byte, src, dst netip.Addr) bool {
	pk := Packet{TS: ts, OrigLen: origLen, Data: append([]byte(nil), data...), Src: src, Dst: dst}
	if pk.cost() > r.maxBytes {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, h := range r.holds {
		if h.closed {
			continue
		}
		if ts.After(h.to) {
			h.closed = true
			continue
		}
		if ts.Before(h.from) || !h.match(pk) {
			continue
		}
		if r.holdBytesLocked()+pk.cost() > r.holdMax {
			h.full = true
			r.holdDrops++
			continue
		}
		h.pkts = append(h.pkts, pk)
		h.bytes += pk.cost()
	}
	if r.buf == nil {
		r.buf = make([]Packet, 1024)
	}
	for (r.bytes+pk.cost() > r.maxBytes || r.count >= r.maxPkts) && r.count > 0 {
		r.popLocked()
	}
	if r.count == len(r.buf) {
		r.growLocked()
	}
	r.buf[(r.head+r.count)%len(r.buf)] = pk
	r.count++
	r.bytes += pk.cost()
	return true
}

func (r *Ring) popLocked() {
	old := r.buf[r.head]
	r.bytes -= old.cost()
	r.buf[r.head] = Packet{}
	r.head = (r.head + 1) % len(r.buf)
	r.count--
	r.evicted++
}

func (r *Ring) growLocked() {
	n := len(r.buf) * 2
	if n > r.maxPkts {
		n = r.maxPkts
	}
	nb := make([]Packet, n)
	for i := 0; i < r.count; i++ {
		nb[i] = r.buf[(r.head+i)%len(r.buf)]
	}
	r.buf, r.head = nb, 0
}

func (h *hold) match(p Packet) bool {
	if len(h.ips) == 0 {
		return true
	}
	return h.ips[p.Src] || h.ips[p.Dst]
}

func (r *Ring) holdBytesLocked() int64 {
	var n int64
	for _, h := range r.holds {
		n += h.bytes
	}
	return n
}

// Stats returns occupancy.
func (r *Ring) Stats() RingStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := RingStats{Packets: r.count, Bytes: r.bytes, Evicted: r.evicted, HoldDrops: r.holdDrops, Holds: len(r.holds)}
	if r.count > 0 {
		s.Oldest = r.buf[r.head].TS
		s.Newest = r.buf[(r.head+r.count-1)%len(r.buf)].TS
	}
	return s
}

// ErrNoHold is returned for an unknown freeze id.
var ErrNoHold = errors.New("capture: no such freeze")

// Freeze pins the window [from, to] under id so eviction cannot lose it. The
// packets already in the ring are copied in (by reference; they are immutable)
// and packets arriving until `to` keep being appended: freezing never drops
// post-alert packets. Callers use from = alert-5min and to = alert+10min. ips,
// when non-empty, restricts the freeze to packets to or from those addresses.
// Freezing an existing id extends its window and IP set.
func (r *Ring) Freeze(id string, from, to time.Time, ips []netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.holds[id]
	if !ok {
		h = &hold{from: from, to: to, ips: map[netip.Addr]bool{}}
		r.holds[id] = h
	} else {
		if from.Before(h.from) {
			h.from = from
		}
		if to.After(h.to) {
			h.to = to
		}
		h.closed = false
	}
	for _, ip := range ips {
		h.ips[ip.Unmap()] = true
	}
	// Re-scan the ring: replace the hold's content with the union of what it
	// has and what the ring still carries, in time order.
	have := map[*byte]bool{}
	for _, p := range h.pkts {
		if len(p.Data) > 0 {
			have[&p.Data[0]] = true
		}
	}
	var merged []Packet
	var add int64
	for i := 0; i < r.count; i++ {
		p := r.buf[(r.head+i)%len(r.buf)]
		if p.TS.Before(h.from) || p.TS.After(h.to) || !h.match(p) {
			continue
		}
		if len(p.Data) > 0 && have[&p.Data[0]] {
			continue
		}
		if r.holdBytesLocked()+add+p.cost() > r.holdMax {
			h.full = true
			r.holdDrops++
			break
		}
		merged = append(merged, p)
		add += p.cost()
	}
	if len(merged) > 0 {
		all := make([]Packet, 0, len(h.pkts)+len(merged))
		all = append(all, h.pkts...)
		all = append(all, merged...)
		sortByTime(all)
		h.pkts = all
		h.bytes += add
	}
}

func sortByTime(p []Packet) {
	sort.SliceStable(p, func(i, j int) bool { return p[i].TS.Before(p[j].TS) })
}

// Release drops a freeze and its memory.
func (r *Ring) Release(id string) {
	r.mu.Lock()
	delete(r.holds, id)
	r.mu.Unlock()
}

// FreezeInfo describes a freeze.
type FreezeInfo struct {
	Packets int
	Bytes   int64
	From    time.Time
	To      time.Time
	Closed  bool // window ended: no more packets will be added
	Full    bool // budget hit: some packets were not kept
}

// Frozen reports on a freeze.
func (r *Ring) Frozen(id string) (FreezeInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.holds[id]
	if !ok {
		return FreezeInfo{}, ErrNoHold
	}
	return FreezeInfo{Packets: len(h.pkts), Bytes: h.bytes, From: h.from, To: h.to, Closed: h.closed, Full: h.full}, nil
}

// WriteFrozen writes the freeze as a pcap (the packets collected so far; call
// again after the window closes for the rest). It returns the packet count.
func (r *Ring) WriteFrozen(w io.Writer, id string) (int, error) {
	r.mu.Lock()
	h, ok := r.holds[id]
	if !ok {
		r.mu.Unlock()
		return 0, ErrNoHold
	}
	pkts := append([]Packet(nil), h.pkts...)
	r.mu.Unlock()
	return r.writePCAP(w, pkts)
}

// WriteSlice writes the live ring's packets in [from, to], restricted to ips
// when given, as a pcap.
func (r *Ring) WriteSlice(w io.Writer, from, to time.Time, ips []netip.Addr) (int, error) {
	set := map[netip.Addr]bool{}
	for _, ip := range ips {
		set[ip.Unmap()] = true
	}
	r.mu.Lock()
	var pkts []Packet
	for i := 0; i < r.count; i++ {
		p := r.buf[(r.head+i)%len(r.buf)]
		if p.TS.Before(from) || p.TS.After(to) {
			continue
		}
		if len(set) > 0 && !set[p.Src] && !set[p.Dst] {
			continue
		}
		pkts = append(pkts, p)
	}
	r.mu.Unlock()
	return r.writePCAP(w, pkts)
}

func (r *Ring) writePCAP(w io.Writer, pkts []Packet) (int, error) {
	pw := pcapgo.NewWriter(w)
	if err := pw.WriteFileHeader(65535, r.link); err != nil {
		return 0, err
	}
	for i, p := range pkts {
		ci := gopacket.CaptureInfo{Timestamp: p.TS, CaptureLength: len(p.Data), Length: p.OrigLen}
		if ci.Length < ci.CaptureLength {
			ci.Length = ci.CaptureLength
		}
		if err := pw.WritePacket(ci, p.Data); err != nil {
			return i, fmt.Errorf("capture: write pcap: %w", err)
		}
	}
	return len(pkts), nil
}
