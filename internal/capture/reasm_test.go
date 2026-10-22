package capture

import (
	"bytes"
	"math/rand"
	"testing"
)

func collect() (*[]byte, func([]byte)) {
	var got []byte
	return &got, func(b []byte) { got = append(got, b...) }
}

func TestReassemblyOrderings(t *testing.T) {
	stream := make([]byte, 5000)
	rand.New(rand.NewSource(1)).Read(stream)
	const isn = 1000
	type seg struct {
		off int
		n   int
	}
	var segs []seg
	for off := 0; off < len(stream); off += 700 {
		segs = append(segs, seg{off, min(700, len(stream)-off)})
	}
	perms := map[string][]int{
		"in order": {0, 1, 2, 3, 4, 5, 6, 7},
		"reversed": {7, 6, 5, 4, 3, 2, 1, 0},
		"swapped":  {1, 0, 3, 2, 5, 4, 7, 6},
		"dups":     {0, 0, 1, 2, 2, 3, 4, 5, 6, 6, 7, 7},
		"overlap":  {0, 2, 1, 4, 3, 6, 5, 7},
	}
	for name, perm := range perms {
		r := NewReassembler(ReasmLimits{})
		got, deliver := collect()
		r.Add(isn, true, nil, deliver)
		for _, i := range perm {
			s := segs[i]
			r.Add(isn+1+uint32(s.off), false, stream[s.off:s.off+s.n], deliver)
		}
		if !bytes.Equal(*got, stream) || r.State() != ReasmOK || r.Pending() != 0 {
			t.Errorf("%s: got %d bytes ok=%v pending=%d", name, len(*got), bytes.Equal(*got, stream), r.Pending())
		}
	}
}

func TestReassemblyOverlappingSegmentsTrimmed(t *testing.T) {
	r := NewReassembler(ReasmLimits{})
	got, deliver := collect()
	r.Add(0, true, nil, deliver)
	r.Add(1, false, []byte("abcdef"), deliver)
	r.Add(4, false, []byte("defghi"), deliver)   // overlaps 3 bytes already delivered
	r.Add(10, false, []byte("jkl"), deliver)     // gap of 0? next is 10: contiguous (1+6+3=10)
	r.Add(20, false, []byte("tuv"), deliver)     // parked
	r.Add(13, false, []byte("mnopqrs"), deliver) // fills the hole exactly up to 20
	if string(*got) != "abcdefghijklmnopqrstuv" {
		t.Fatalf("%q", *got)
	}
	if r.Retrans != 3 {
		t.Fatalf("retrans %d", r.Retrans)
	}
}

func TestReassemblySequenceWraparound(t *testing.T) {
	r := NewReassembler(ReasmLimits{})
	got, deliver := collect()
	isn := uint32(0xFFFFFFF0)
	r.Add(isn, true, nil, deliver)
	seq := isn + 1
	// second segment arrives first, and straddles the 2^32 boundary
	r.Add(seq+10, false, bytes.Repeat([]byte("B"), 20), deliver)
	r.Add(seq, false, bytes.Repeat([]byte("A"), 10), deliver)
	if string(*got) != "AAAAAAAAAA"+"BBBBBBBBBBBBBBBBBBBB" {
		t.Fatalf("%q", *got)
	}
}

func TestReassemblyMidstreamPickup(t *testing.T) {
	r := NewReassembler(ReasmLimits{})
	got, deliver := collect()
	r.Add(5000, false, []byte("hello "), deliver)
	r.Add(5006, false, []byte("world"), deliver)
	if string(*got) != "hello world" {
		t.Fatalf("%q", *got)
	}
}

func TestReassemblyBounds(t *testing.T) {
	// too many parked segments: the stream is declared broken
	r := NewReassembler(ReasmLimits{MaxSegments: 4, MaxPending: 1 << 20})
	_, deliver := collect()
	r.Add(0, true, nil, deliver)
	for i := 0; i < 10; i++ {
		r.Add(100+uint32(i)*10, false, []byte("x"), deliver)
	}
	if r.State() != ReasmGap || r.Pending() != 0 {
		t.Fatalf("segments bound: state=%v pending=%d", r.State(), r.Pending())
	}
	// too many parked bytes
	r = NewReassembler(ReasmLimits{MaxSegments: 100, MaxPending: 1000})
	r.Add(0, true, nil, deliver)
	r.Add(100, false, make([]byte, 600), deliver)
	r.Add(800, false, make([]byte, 600), deliver)
	if r.State() != ReasmGap {
		t.Fatalf("bytes bound: %v", r.State())
	}
	// delivered-byte cap: the stream is cut off, never over the limit
	r = NewReassembler(ReasmLimits{MaxBytes: 1000})
	got, d2 := collect()
	r.Add(0, true, nil, d2)
	for i := 0; i < 10; i++ {
		r.Add(1+uint32(i)*300, false, make([]byte, 300), d2)
	}
	if len(*got) != 1000 || r.State() != ReasmCapped {
		t.Fatalf("cap: delivered %d state %v", len(*got), r.State())
	}
	// once broken, further segments are ignored
	before := len(*got)
	r.Add(5000, false, []byte("late"), d2)
	if len(*got) != before {
		t.Fatal("delivered after cap")
	}
}

func FuzzReassembly(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	f.Fuzz(func(t *testing.T, b []byte) {
		r := NewReassembler(ReasmLimits{MaxSegments: 8, MaxPending: 256, MaxBytes: 1024})
		var total int
		for len(b) >= 3 {
			seq := uint32(b[0])<<8 | uint32(b[1])
			n := int(b[2] % 16)
			b = b[3:]
			if n > len(b) {
				n = len(b)
			}
			r.Add(seq, false, b[:n], func(p []byte) { total += len(p) })
			b = b[n:]
			if total > 1024 || r.Pending() > 256 {
				t.Fatalf("bounds exceeded: total=%d pending=%d", total, r.Pending())
			}
		}
	})
}
