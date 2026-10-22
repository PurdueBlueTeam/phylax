package spool

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func open(t *testing.T, dir string, o Options) *Spool {
	t.Helper()
	if o.Agent == "" {
		o.Agent = "a1"
	}
	s, err := Open(dir, o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func ev(prio event.Priority, i int, pad int) event.Event {
	return event.Event{Kind: "test", Priority: prio, Fields: map[string]any{"i": i, "pad": strings.Repeat("x", pad)}}
}

func mustAppend(t *testing.T, s *Spool, e event.Event) event.Event {
	t.Helper()
	out, err := s.Append(e)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	return out
}

func all(t *testing.T, s *Spool) []event.Event {
	t.Helper()
	evs, err := s.ResendFrom(1, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// checkChain applies the controller store's rules: each event follows its
// predecessor by seq and hash, a gap record starting right after the
// predecessor and taking seq to+1, and every hash recomputes. It returns the
// number of gap records and the total count they announce.
func checkChain(t *testing.T, evs []event.Event) (gaps int, dropped uint64) {
	t.Helper()
	for i, e := range evs {
		if h, err := e.ComputeHash(); err != nil || h != e.Hash {
			t.Fatalf("seq %d: bad hash", e.Seq)
		}
		if from, to, ok := gapRange(e); ok {
			gaps++
			dropped += to - from + 1
			if c := asUint(e.Fields["count"]); c != to-from+1 {
				t.Fatalf("gap count %d for range %d-%d", c, from, to)
			}
		}
		if i == 0 {
			continue
		}
		if !follows(e, evs[i-1].Seq, evs[i-1].Hash) {
			t.Fatalf("seq %d (%s) does not follow %d: %+v", e.Seq, e.Kind, evs[i-1].Seq, e)
		}
	}
	return
}

func TestAppendReadAckReopen(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Options{})
	for i := 0; i < 10; i++ {
		e := mustAppend(t, s, ev(event.Priority(i%4), i, 10))
		if e.Seq != uint64(i+1) || e.Agent != "a1" {
			t.Fatalf("bad seal %+v", e)
		}
	}
	b, err := s.ReadBatch(100, 1<<20)
	if err != nil || len(b) != 10 {
		t.Fatalf("batch %d %v", len(b), err)
	}
	checkChain(t, b)
	if b2, _ := s.ReadBatch(100, 1<<20); len(b2) != 0 {
		t.Fatalf("cursor did not advance: %d", len(b2))
	}
	s.Rewind()
	if b2, _ := s.ReadBatch(3, 1<<20); len(b2) != 3 || b2[0].Seq != 1 {
		t.Fatalf("after rewind got %d", len(b2))
	}
	if err := s.Ack(6); err != nil {
		t.Fatal(err)
	}
	s.Rewind()
	b, _ = s.ReadBatch(100, 1<<20)
	if len(b) != 4 || b[0].Seq != 7 {
		t.Fatalf("want 4 unacked from 7, got %d", len(b))
	}
	seq, hash := s.Head()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = open(t, dir, Options{})
	defer s.Close()
	if sq, h := s.Head(); sq != seq || h != hash {
		t.Fatalf("head after reopen %d %s", sq, h)
	}
	if st := s.Stats(); st.AckSeq != 6 {
		t.Fatalf("ack not persisted: %d", st.AckSeq)
	}
	if e := mustAppend(t, s, ev(event.PriorityNormal, 99, 0)); e.Seq != 11 {
		t.Fatalf("seq %d", e.Seq)
	}
	checkChain(t, all(t, s))
}

func TestSecondOpenLocked(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Options{})
	defer s.Close()
	if _, err := Open(dir, Options{}); err == nil {
		t.Fatal("second Open of the same dir succeeded")
	}
}

func segFiles(t *testing.T, dir string) []string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(dir, "*.seg"))
	sort.Strings(m)
	return m
}

func TestCrashTornTail(t *testing.T) {
	for _, cut := range []int64{1, 5, 9, 30} { // inside payload, inside header, ...
		dir := t.TempDir()
		s := open(t, dir, Options{SegmentBytes: 1 << 10})
		for i := 0; i < 40; i++ {
			mustAppend(t, s, ev(event.Priority(i%4), i, 20))
		}
		s.Close()
		os.Remove(filepath.Join(dir, metaName)) // kill -9 never reaches Close
		fs := segFiles(t, dir)
		if len(fs) < 3 {
			t.Fatalf("want several segments, got %d", len(fs))
		}
		f := fs[len(fs)-1]
		st, _ := os.Stat(f)
		if err := os.Truncate(f, st.Size()-cut); err != nil {
			t.Fatal(err)
		}
		s = open(t, dir, Options{SegmentBytes: 1 << 10})
		if s.Stats().RepairedBytes == 0 {
			t.Fatal("expected a repair")
		}
		if seq, _ := s.Head(); seq != 39 {
			t.Fatalf("cut %d: head %d, want 39", cut, seq)
		}
		for i := 0; i < 5; i++ {
			mustAppend(t, s, ev(event.PriorityHigh, i, 0))
		}
		evs := all(t, s)
		if len(evs) != 44 {
			t.Fatalf("got %d events", len(evs))
		}
		if g, _ := checkChain(t, evs); g != 0 {
			t.Fatalf("unexpected gap records: %d", g)
		}
		s.Close()
	}
}

func TestCrashGarbageTail(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Options{})
	for i := 0; i < 5; i++ {
		mustAppend(t, s, ev(event.PriorityHigh, i, 5))
	}
	s.Close()
	fh, _ := os.OpenFile(segFiles(t, dir)[0], os.O_WRONLY|os.O_APPEND, 0)
	fh.Write(make([]byte, 100)) // zero-filled tail as after a power cut
	fh.Close()
	s = open(t, dir, Options{})
	defer s.Close()
	if s.Stats().RepairedBytes != 100 {
		t.Fatalf("repaired %d", s.Stats().RepairedBytes)
	}
	mustAppend(t, s, ev(event.PriorityHigh, 6, 0))
	checkChain(t, all(t, s))
}

func TestDamageMidLogDropsLaterSegmentsAndBridges(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Options{SegmentBytes: 1 << 10})
	for i := 0; i < 40; i++ {
		mustAppend(t, s, ev(event.PriorityNormal, i, 20))
	}
	s.Close() // meta records head 40
	fs := segFiles(t, dir)
	st, _ := os.Stat(fs[1])
	os.Truncate(fs[1], st.Size()/2+1)
	s = open(t, dir, Options{SegmentBytes: 1 << 10})
	defer s.Close()
	evs := all(t, s)
	g, dropped := checkChain(t, evs)
	if g != 1 || evs[len(evs)-1].Kind != GapKind {
		t.Fatalf("want one trailing gap record, got %d", g)
	}
	last := evs[len(evs)-1]
	if last.Seq != 41 || asUint(last.Fields["to"]) != 40 || last.Fields["class"] != "unknown" {
		t.Fatalf("gap %+v", last)
	}
	if dropped != 41-evs[len(evs)-2].Seq-0 && dropped == 0 {
		t.Fatal("empty gap")
	}
	e := mustAppend(t, s, ev(event.PriorityNormal, 1, 0))
	if e.Seq != 42 {
		t.Fatalf("seq %d: sequence numbers the controller may hold were reused", e.Seq)
	}
}

func TestSheddingAnnouncesWithGapRecord(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Options{MaxBytes: 200 << 10, SegmentBytes: 8 << 10})
	defer s.Close()
	var crit, stored, shed int
	for i := 0; i < 1000; i++ {
		p := event.PriorityBulk
		if i%20 == 0 {
			p = event.PriorityCritical
		} else if i%3 == 0 {
			p = event.PriorityNormal
		}
		_, err := s.Append(ev(p, i, 60))
		switch err {
		case nil:
			stored++
			if p == event.PriorityCritical {
				crit++
			}
		case ErrShed:
			shed++
			if p == event.PriorityCritical {
				t.Fatal("critical shed")
			}
		default:
			t.Fatalf("append %d: %v", i, err)
		}
		if st := s.Stats(); st.UsedBytes > st.MaxBytes {
			t.Fatalf("cap exceeded: %d", st.UnackedBytes)
		}
	}
	if shed == 0 {
		t.Fatal("expected shedding")
	}
	if crit != 50 {
		t.Fatalf("critical stored %d of 50 (unacked bulk must not crowd them out)", crit)
	}
	st := s.Stats()
	if st.Shed != uint64(shed) || st.State != StateFull {
		t.Fatalf("stats %+v shed=%d", st, shed)
	}
	evs := all(t, s)
	gaps, dropped := checkChain(t, evs)
	if gaps == 0 || dropped != uint64(shed) {
		t.Fatalf("gaps=%d announce %d dropped, want %d", gaps, dropped, shed)
	}
	// Total sequence space = stored events + gap-covered ones.
	if want := uint64(stored+shed) + s.Stats().GapRecords; evs[len(evs)-1].Seq != want {
		t.Fatalf("last seq %d want %d", evs[len(evs)-1].Seq, want)
	}
	for _, e := range evs {
		if e.Kind == GapKind {
			if e.Priority != event.PriorityCritical {
				t.Fatal("gap must be critical")
			}
			if c := e.Fields["class"]; c != "bulk" && c != "normal" && c != "mixed" {
				t.Fatalf("class %v", c)
			}
		}
	}
	// Survives restart and still verifies.
	s.Close()
	s = open(t, dir, Options{MaxBytes: 200 << 10, SegmentBytes: 8 << 10})
	checkChain(t, all(t, s))
}

func TestPendingGapFlushedOnCloseAndMixedClass(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Options{MaxBytes: 8 << 10, SegmentBytes: 2 << 10})
	for i := 0; i < 30; i++ {
		mustAppend(t, s, ev(event.PriorityCritical, i, 100))
		if s.Stats().UnackedBytes*10 > s.Stats().MaxBytes*8 {
			break
		}
	}
	for _, p := range []event.Priority{event.PriorityBulk, event.PriorityBulk, event.PriorityNormal, event.PriorityBulk} {
		if _, err := s.Append(ev(p, 0, 10)); err != ErrShed {
			t.Fatalf("want ErrShed for %v, got %v", p, err)
		}
	}
	s.Close()
	s = open(t, dir, Options{MaxBytes: 8 << 10, SegmentBytes: 2 << 10})
	defer s.Close()
	evs := all(t, s)
	gaps, dropped := checkChain(t, evs)
	if gaps != 1 || dropped != 4 || evs[len(evs)-1].Fields["class"] != "mixed" {
		t.Fatalf("gaps=%d dropped=%d, want one mixed-class run covering 4", gaps, dropped)
	}
}

func dirBytes(t *testing.T, dir string) int64 {
	var n int64
	for _, f := range segFiles(t, dir) {
		st, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		n += st.Size()
	}
	return n
}

func TestSizeCapEnforcedOnDisk(t *testing.T) {
	dir := t.TempDir()
	const max = 100 << 10
	s := open(t, dir, Options{MaxBytes: max, SegmentBytes: 10 << 10})
	defer s.Close()
	for i := 0; i < 5000; i++ {
		if _, err := s.Append(ev(event.Priority(i%4), i, 100)); err != nil && err != ErrShed && err != ErrFull {
			t.Fatal(err)
		}
		if i%250 == 0 {
			s.ReadBatch(50, 1<<20)
			s.Ack(uint64(i / 2))
		}
		if d := dirBytes(t, dir); d > max {
			t.Fatalf("on-disk %d over cap %d at %d", d, max, i)
		}
	}
	if d := dirBytes(t, dir); d != s.Stats().UsedBytes {
		t.Fatalf("accounting off: disk %d, used %d", d, s.Stats().UsedBytes)
	}
	checkChain(t, all(t, s))
}

func TestCriticalFullIsAnnounced(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Options{MaxBytes: 20 << 10, SegmentBytes: 4 << 10})
	defer s.Close()
	var full int
	for i := 0; i < 400; i++ {
		_, err := s.Append(ev(event.PriorityCritical, i, 100))
		if err == ErrFull {
			full++
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if full == 0 {
		t.Fatal("never full")
	}
	if _, err := s.Append(ev(event.PriorityBulk, 1, 0)); err != ErrShed {
		t.Fatalf("bulk: %v", err)
	}
	seq, _ := s.Head()
	s.Ack(seq)
	mustAppend(t, s, ev(event.PriorityCritical, 1000, 0)) // ack frees space
	_, dropped := checkChain(t, all(t, s))
	if dropped != uint64(full)+1 {
		t.Fatalf("announced %d, want %d", dropped, full+1)
	}
}

func TestAckedKeptUntilSpaceNeeded(t *testing.T) {
	dir := t.TempDir()
	const max = 40 << 10
	s := open(t, dir, Options{MaxBytes: max, SegmentBytes: 4 << 10})
	defer s.Close()
	for i := 0; i < 60; i++ {
		mustAppend(t, s, ev(event.PriorityNormal, i, 100))
	}
	if s.Stats().UsedBytes >= max {
		t.Fatal("test setup: should not be full")
	}
	nseg := len(segFiles(t, dir))
	head, _ := s.Head()
	s.Ack(head)
	if got := len(segFiles(t, dir)); got != nseg {
		t.Fatalf("ack deleted segments eagerly: %d -> %d", nseg, got)
	}
	first := segFiles(t, dir)[0]
	for i := 60; i < 160; i++ {
		mustAppend(t, s, ev(event.PriorityNormal, i, 100))
		h, _ := s.Head()
		s.Ack(h)
	}
	if _, err := os.Stat(first); err == nil {
		t.Fatal("oldest acked segment survived pressure")
	}
	st := s.Stats()
	if st.Shed != 0 {
		t.Fatalf("acked data must be reclaimed before anything is shed: %+v", st)
	}
	if st.OldestSeq <= 1 || st.UsedBytes > max {
		t.Fatalf("stats %+v", st)
	}
	evs := all(t, s)
	if evs[0].Seq != st.OldestSeq {
		t.Fatalf("oldest %d vs %d", evs[0].Seq, st.OldestSeq)
	}
	checkChain(t, evs) // oldest removed first: what remains is one contiguous chain
}

func TestAllSegmentsDeletedKeepsChain(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Options{MaxBytes: 6 << 10, SegmentBytes: 1 << 10})
	for i := 0; i < 8; i++ {
		mustAppend(t, s, ev(event.PriorityNormal, i, 50))
	}
	head, _ := s.Head()
	s.Ack(head)
	var last event.Event
	for i := 0; i < 60; i++ {
		last = mustAppend(t, s, ev(event.PriorityNormal, i, 50))
		h, _ := s.Head()
		s.Ack(h)
	}
	s.Close()
	s = open(t, dir, Options{MaxBytes: 6 << 10, SegmentBytes: 1 << 10})
	defer s.Close()
	if h, hh := s.Head(); h != last.Seq || hh != last.Hash {
		t.Fatal("head lost")
	}
	e := mustAppend(t, s, ev(event.PriorityNormal, 1, 0))
	if !follows(e, last.Seq, last.Hash) {
		t.Fatal("chain not continued")
	}
}

func TestResendAfterControllerRestore(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Options{SegmentBytes: 2 << 10})
	for i := 0; i < 100; i++ {
		mustAppend(t, s, ev(event.Priority(i%4), i, 30))
	}
	s.Ack(100)
	s.Close()
	s = open(t, dir, Options{SegmentBytes: 2 << 10})
	defer s.Close()
	if b, _ := s.ReadBatch(10, 1<<20); len(b) != 0 {
		t.Fatal("everything is acked; nothing pending")
	}
	// Restored controller's snapshot only reaches seq 40.
	got, err := s.ResendFrom(41, 1000)
	if err != nil || len(got) != 60 {
		t.Fatalf("resend: %d %v", len(got), err)
	}
	for i, e := range got {
		if e.Seq != uint64(41+i) {
			t.Fatalf("resend order: %d at %d", e.Seq, i)
		}
	}
	at40, _ := s.ResendFrom(40, 1)
	if got[0].PrevHash != at40[0].Hash {
		t.Fatal("resend does not link to the snapshot hash")
	}
	checkChain(t, got)
	if lim, _ := s.ResendFrom(1, 7); len(lim) != 7 {
		t.Fatalf("limit ignored: %d", len(lim))
	}
	// ResendFrom leaves the send cursor alone.
	if b, _ := s.ReadBatch(10, 1<<20); len(b) != 0 {
		t.Fatal("resend disturbed the cursor")
	}
}

func TestResendAfterPartialReclaim(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Options{MaxBytes: 20 << 10, SegmentBytes: 2 << 10})
	defer s.Close()
	for i := 0; i < 300; i++ {
		mustAppend(t, s, ev(event.PriorityNormal, i, 40))
		h, _ := s.Head()
		s.Ack(h)
	}
	st := s.Stats()
	if st.OldestSeq <= 1 {
		t.Fatal("expected reclaim")
	}
	got, _ := s.ResendFrom(1, 1000)
	if got[0].Seq != st.OldestSeq || int(got[len(got)-1].Seq-got[0].Seq)+1 != len(got) {
		t.Fatalf("resend from oldest retained: first=%d oldest=%d", got[0].Seq, st.OldestSeq)
	}
}

func TestConcurrentAppendReadBatch(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Options{MaxBytes: 4 << 20, SegmentBytes: 16 << 10, SyncInterval: 5 * time.Millisecond})
	defer s.Close()
	const writers, per = 4, 500
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if _, err := s.Append(ev(event.Priority((w+i)%4), i, 50)); err != nil {
					t.Error(err)
					return
				}
			}
		}(w)
	}
	var got []event.Event
	stop := make(chan struct{})
	rd := make(chan struct{})
	go func() {
		defer close(rd)
		for {
			b, err := s.ReadBatch(64, 1<<16)
			if err != nil {
				t.Error(err)
				return
			}
			got = append(got, b...)
			if len(b) > 0 {
				s.Ack(b[len(b)-1].Seq)
			}
			s.Stats()
			select {
			case <-stop:
				if len(b) == 0 {
					return
				}
			default:
				if len(b) == 0 {
					time.Sleep(time.Millisecond)
				}
			}
		}
	}()
	wg.Wait()
	close(stop)
	<-rd
	if len(got) != writers*per {
		t.Fatalf("delivered %d of %d", len(got), writers*per)
	}
	checkChain(t, got)
}

func TestFrameRoundTripAndErrors(t *testing.T) {
	e := event.Event{Agent: "a", Kind: "k", Time: time.Unix(1, 2), Fields: map[string]any{"big": uint64(1) << 62}}
	e.Seal(0, event.GenesisHash)
	pl, _ := encodeEvent(e)
	fr := appendFrame(nil, pl)
	got, n, err := readFrame(strings.NewReader(string(fr)))
	if err != nil || n != len(fr) {
		t.Fatal(err)
	}
	d, err := decodeEvent(got)
	if err != nil || d.Hash != e.Hash {
		t.Fatalf("decode %v (large ints must keep their hash)", err)
	}
	if _, _, err := readFrame(strings.NewReader(string(fr[:len(fr)-1]))); err != errTorn {
		t.Fatalf("want torn, got %v", err)
	}
	bad := append([]byte(nil), fr...)
	bad[len(bad)-2] ^= 0xff
	if _, _, err := readFrame(strings.NewReader(string(bad))); err != errCorrupt {
		t.Fatalf("want corrupt, got %v", err)
	}
}

func FuzzDecodeFrame(f *testing.F) {
	e := event.Event{Agent: "a", Kind: "k", Time: time.Unix(1, 2), Fields: map[string]any{"x": 1}}
	e.Seal(0, event.GenesisHash)
	pl, _ := encodeEvent(e)
	f.Add(appendFrame(nil, pl))
	f.Add([]byte{})
	f.Add([]byte{1, 0, 0, 0, 0, 0, 0, 0, 'x'})
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, data []byte) {
		payload, n, err := readFrame(strings.NewReader(string(data)))
		if err != nil {
			return
		}
		if n > len(data) || n != frameHeader+len(payload) {
			t.Fatalf("bad length %d", n)
		}
		if string(appendFrame(nil, payload)) != string(data[:n]) {
			t.Fatal("frame did not round trip")
		}
		if ev, err := decodeEvent(payload); err == nil {
			if h, _ := ev.ComputeHash(); h != ev.Hash {
				t.Fatal("decoder accepted an event with a bad hash")
			}
		}
	})
}
