package capture

// Per-direction TCP reassembly with hard bounds. It delivers in-order bytes
// to a callback, trims retransmitted and overlapping data, and parks
// out-of-order segments up to a fixed number of segments and bytes. When the
// bound is hit the stream is declared broken (gap): the caller ends the
// protocol parser rather than guessing across a hole.

// ReasmLimits bound one direction of one stream.
type ReasmLimits struct {
	MaxSegments int   // out-of-order segments parked
	MaxPending  int   // out-of-order bytes parked
	MaxBytes    int64 // in-order bytes delivered before the stream is cut off
}

// DefaultReasmLimits are applied when a Config leaves them zero.
var DefaultReasmLimits = ReasmLimits{MaxSegments: 64, MaxPending: 128 << 10, MaxBytes: 4 << 20}

type oooSeg struct {
	seq  uint32
	data []byte
}

// Reassembler is one direction of a TCP stream.
type Reassembler struct {
	lim       ReasmLimits
	init      bool
	next      uint32
	pend      []oooSeg // sorted by sequence distance from next
	pendBytes int
	delivered int64
	state     ReasmState
	// Gaps counts holes that ended the stream; Retrans counts bytes ignored as duplicates.
	Retrans int64
}

// ReasmState is the stream's health.
type ReasmState uint8

// States.
const (
	ReasmOK ReasmState = iota
	ReasmGap
	ReasmCapped
)

// NewReassembler returns an empty reassembler.
func NewReassembler(l ReasmLimits) *Reassembler {
	d := DefaultReasmLimits
	if l.MaxSegments <= 0 {
		l.MaxSegments = d.MaxSegments
	}
	if l.MaxPending <= 0 {
		l.MaxPending = d.MaxPending
	}
	if l.MaxBytes <= 0 {
		l.MaxBytes = d.MaxBytes
	}
	return &Reassembler{lim: l}
}

// State reports whether the stream is still usable.
func (r *Reassembler) State() ReasmState { return r.state }

// Delivered is the number of in-order bytes passed on.
func (r *Reassembler) Delivered() int64 { return r.delivered }

// Pending reports parked out-of-order bytes (for tests and gauges).
func (r *Reassembler) Pending() int { return r.pendBytes }

func seqDiff(a, b uint32) int32 { return int32(a - b) }

// Add feeds a segment. syn marks a SYN (consumes one sequence number before
// the data). deliver is called with in-order bytes; the slice is valid only
// during the call. The return value is the stream state after the segment.
func (r *Reassembler) Add(seq uint32, syn bool, data []byte, deliver func([]byte)) ReasmState {
	if r.state != ReasmOK {
		return r.state
	}
	if syn {
		if !r.init {
			r.init = true
			r.next = seq + 1
		}
		seq++ // data in a SYN segment (rare) starts after the SYN
	}
	if len(data) == 0 {
		return r.state
	}
	if !r.init {
		r.init, r.next = true, seq // mid-stream pickup
	}
	d := seqDiff(seq, r.next)
	switch {
	case d < 0:
		skip := int(-int64(d))
		if skip >= len(data) {
			r.Retrans += int64(len(data))
			return r.state
		}
		r.Retrans += int64(skip)
		data = data[skip:]
		seq = r.next
		fallthrough
	case d == 0:
		r.deliver(data, deliver)
		r.drain(deliver)
	default:
		r.park(seq, data)
	}
	return r.state
}

func (r *Reassembler) deliver(data []byte, deliver func([]byte)) {
	if r.state != ReasmOK {
		return
	}
	room := r.lim.MaxBytes - r.delivered
	if int64(len(data)) > room {
		data = data[:room]
		r.state = ReasmCapped
	}
	if len(data) > 0 {
		deliver(data)
		r.delivered += int64(len(data))
		r.next += uint32(len(data))
	}
	if r.delivered >= r.lim.MaxBytes {
		r.state = ReasmCapped
	}
}

func (r *Reassembler) park(seq uint32, data []byte) {
	if len(r.pend) >= r.lim.MaxSegments || r.pendBytes+len(data) > r.lim.MaxPending {
		r.state = ReasmGap
		r.pend, r.pendBytes = nil, 0
		return
	}
	cp := append([]byte(nil), data...)
	// insert sorted by distance from next
	i := len(r.pend)
	for i > 0 && seqDiff(r.pend[i-1].seq, seq) > 0 {
		i--
	}
	r.pend = append(r.pend, oooSeg{})
	copy(r.pend[i+1:], r.pend[i:])
	r.pend[i] = oooSeg{seq, cp}
	r.pendBytes += len(cp)
}

func (r *Reassembler) drain(deliver func([]byte)) {
	for len(r.pend) > 0 && r.state == ReasmOK {
		s := r.pend[0]
		d := seqDiff(s.seq, r.next)
		if d > 0 {
			return
		}
		r.pend = r.pend[1:]
		r.pendBytes -= len(s.data)
		skip := int(-int64(d))
		if skip >= len(s.data) {
			r.Retrans += int64(len(s.data))
			continue
		}
		r.deliver(s.data[skip:], deliver)
	}
	if len(r.pend) == 0 {
		r.pend = nil
	}
}
