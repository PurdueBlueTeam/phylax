package capture

import (
	"sync"
	"time"

	"golang.org/x/net/bpf"
)

// Flow is one flow record: endpoints, ports, start and end, bytes and
// packets each way, handshake result, resets, timeouts, first-bytes
// hashes each way, owning process when known (docs: Capture tiers).
type Flow struct {
	Src     [16]byte `json:"src"`
	Sport   uint16   `json:"sport"`
	Dst     [16]byte `json:"dst"`
	Dport   uint16   `json:"dport"`
	Proto   uint8    `json:"proto"`
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	BytesAB uint64   `json:"bytes_ab"`
	BytesBA uint64   `json:"bytes_ba"`
	PktsAB  uint32   `json:"pkts_ab"`
	PktsBA  uint32   `json:"pkts_ba"`
	Result  string   `json:"result"` // established | reset | timeout | handshake-fail
	ResetAB bool     `json:"reset_ab,omitempty"`
	ResetBA bool     `json:"reset_ba,omitempty"`
	HashAB  string   `json:"hash_ab,omitempty"` // first bytes A->B
	HashBA  string   `json:"hash_ba,omitempty"`
	Pid     int      `json:"pid,omitempty"` // owning process when known
	Scan    bool     `json:"scan,omitempty"`
}

// key identifies a connection (symmetric for matching, directional for
// byte counting).
type key struct {
	s, d [16]byte
	sp   uint16
	dp   uint16
	pr   uint8
}

func k1(src, dst [16]byte, sp, dp uint16, pr uint8) key {
	return key{src, dst, sp, dp, pr}
}

// Tracker builds flow records from a packet stream and aggregates
// scans: one "source X touched N ports" record, not thousands of
// flows (docs: Capture mechanics).
type Tracker struct {
	mu       sync.Mutex
	flows    map[key]*Flow
	scans    map[[16]byte]*scan
	hasher   func([]byte) string
	now      func() time.Time
	maxFlows int
	drops    uint64
}

type scan struct {
	Src      [16]byte
	Ports    map[uint16]bool
	Last     time.Time
	Packets  uint64
}

// NewTracker builds a tracker; hasher gives first-bytes hashes (nil
// disables them).
func NewTracker(hasher func([]byte) string) *Tracker {
	return &Tracker{
		flows:    map[key]*Flow{},
		scans:    map[[16]byte]*scan{},
		hasher:   hasher,
		now:      time.Now,
		maxFlows: 65536,
	}
}

// ForTest sets the clock (tests).
func (t *Tracker) ForTest(now func() time.Time) { t.now = now }

// Observe feeds one packet to the tracker. A==src side is AB.
func (t *Tracker) Observe(ts time.Time, src, dst [16]byte, sport, dport uint16, proto uint8, payload []byte, finOrRst bool, isRst bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ka := k1(src, dst, sport, dport, proto)
	kb := k1(dst, src, dport, sport, proto)
	f, ok := t.flows[ka]
	if !ok {
		if f, ok = t.flows[kb]; !ok {
			if len(t.flows) >= t.maxFlows {
				t.drops++
				return
			}
			// A is the initiating side: the source of the first packet.
			f = &Flow{
				Src: src, Sport: sport, Dst: dst, Dport: dport, Proto: proto,
				Start: ts,
			}
			t.flows[ka] = f
			t.flows[kb] = f
			// scan aggregation: a source touching many ports on one
			// destination in a short window is a scan, not flows
			sc := t.scans[src]
			if sc == nil {
				sc = &scan{Src: src, Ports: map[uint16]bool{}}
				t.scans[src] = sc
			}
			sc.Ports[dport] = true
			sc.Last = ts
			sc.Packets++
		}
	}
	f.End = ts
	if t.hasher != nil && len(payload) > 0 {
		if f.Src == src {
			if f.HashAB == "" {
				f.HashAB = t.hasher(payload)
			}
		} else if f.HashBA == "" {
			f.HashBA = t.hasher(payload)
		}
	}
	if f.Src == src {
		f.BytesAB += uint64(len(payload))
		f.PktsAB++
		if isRst {
			f.ResetAB = true
		}
	} else {
		f.BytesBA += uint64(len(payload))
		f.PktsBA++
		if isRst {
			f.ResetBA = true
		}
	}
	if finOrRst {
		if f.Result == "" || f.Result == "established" {
			if f.ResetAB || f.ResetBA {
				f.Result = "reset"
			} else {
				f.Result = "established"
			}
		}
	} else if f.Result == "" {
		f.Result = "established"
	}
}

// MarkPID records the owning process of a flow (from the agent's
// socket records).
func (t *Tracker) MarkPID(src, dst [16]byte, sport, dport uint16, proto uint8, pid int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if f, ok := t.flows[k1(src, dst, sport, dport, proto)]; ok {
		f.Pid = pid
	}
}
// Finish marks open flows as timed out and returns completed flows
// (closed, or scan-aggregated). A source that touched more than
// scanPortThreshold ports in the window produces one scan record, and
// the individual flows are dropped.
const scanPortThreshold = 10

func (t *Tracker) Finish(ts time.Time) []Flow {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Flow
	// scan aggregation: fold scan sources' flows into one record each
	for src, sc := range t.scans {
		if len(sc.Ports) < scanPortThreshold {
			continue
		}
		delete(t.scans, src)
		out = append(out, Flow{Src: src, Result: "scan", Scan: true,
			Start: sc.Last.Add(-time.Minute), End: sc.Last,
			PktsAB: uint32(sc.Packets),
		})
		// drop the individual flows for this source
		for ka := range t.flows {
			if ka.s == src {
				kb := key{s: ka.d, d: ka.s, sp: ka.dp, dp: ka.sp, pr: ka.pr}
				delete(t.flows, ka)
				delete(t.flows, kb)
			}
		}
	}
	seen := map[*Flow]bool{}
	for ka := range t.flows {
		f := t.flows[ka]
		if seen[f] {
			continue
		}
		seen[f] = true
		if f.Result == "" || f.Result == "established" {
			if ts.Sub(f.End) > 5*time.Second {
				f.Result = "timeout"
			}
		}
		out = append(out, *f)
		delete(t.flows, ka)
		kb := key{s: f.Dst, d: f.Src, sp: f.Dport, dp: f.Sport, pr: f.Proto}
		delete(t.flows, kb)
	}
	return out
}

// Drops reports flows dropped at the cap.
func (t *Tracker) Drops() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.drops
}

// Compile-time check that the bpf import is used by the filter builder
// (filter.go).
var _ = bpf.ALUOpAdd
