package spool

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

const sparseEvery = 32

type sparseEnt struct {
	seq uint64
	off int64
}

// segment is the in-memory index of one segment file: a few words plus a
// sparse offset table, never the events themselves.
type segment struct {
	path           string
	firstPrev      string
	firstFrom      uint64 // first sequence the first event accounts for (gap: its from)
	minSeq, maxSeq uint64
	count          int
	size           int64
	lastHash       string
	sparse         []sparseEnt
	w              *os.File // set only while this is the active segment
	dirty          bool     // written since the last fsync
}

func segName(firstSeq uint64) string { return fmt.Sprintf("seg-%020d.seg", firstSeq) }

func isSegName(name string) bool {
	var seq uint64
	var tail string
	n, _ := fmt.Sscanf(name, "seg-%020d%s", &seq, &tail)
	return n == 2 && tail == ".seg"
}

// gapRange extracts the shed range from a gap record.
func gapRange(ev event.Event) (from, to uint64, ok bool) {
	from, to = asUint(ev.Fields["from"]), asUint(ev.Fields["to"])
	return from, to, ev.Kind == GapKind && from != 0 && to >= from
}

// follows reports whether ev is a valid successor of (prevSeq, prevHash): the
// next sequence number, or a gap record whose range starts right after prevSeq
// and which therefore takes sequence to+1 (the hash bridge).
func follows(ev event.Event, prevSeq uint64, prevHash string) bool {
	if ev.PrevHash != prevHash {
		return false
	}
	if from, to, ok := gapRange(ev); ok {
		return from == prevSeq+1 && ev.Seq == to+1
	}
	return ev.Seq == prevSeq+1
}

// note records a frame of n bytes holding ev at the end of the segment.
func (g *segment) note(ev event.Event, n int) {
	if g.count%sparseEvery == 0 {
		g.sparse = append(g.sparse, sparseEnt{ev.Seq, g.size})
	}
	if g.count == 0 {
		g.minSeq, g.firstPrev, g.firstFrom = ev.Seq, ev.PrevHash, ev.Seq
		if from, _, ok := gapRange(ev); ok {
			g.firstFrom = from
		}
	}
	g.maxSeq = ev.Seq
	g.lastHash = ev.Hash
	g.count++
	g.size += int64(n)
}

// scanSegment validates a segment file frame by frame, truncating a torn or
// corrupt tail. It returns the rebuilt index and how many bytes were cut.
func scanSegment(path string) (*segment, int64, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	g := &segment{path: path}
	r := bufio.NewReaderSize(f, 64<<10)
	for {
		payload, n, err := readFrame(r)
		if err != nil {
			break
		}
		ev, err := decodeEvent(payload)
		if err != nil || (g.count > 0 && !follows(ev, g.maxSeq, g.lastHash)) {
			break
		}
		g.note(ev, n)
	}
	cut := st.Size() - g.size
	if cut > 0 {
		if err := f.Truncate(g.size); err != nil {
			return nil, 0, fmt.Errorf("spool: repair %s: %w", filepath.Base(path), err)
		}
		if err := f.Sync(); err != nil {
			return nil, 0, err
		}
	}
	return g, cut, nil
}

// setIter streams the events of one priority set with Seq > after, in order,
// holding at most one open file and one read buffer.
type setIter struct {
	segs  []*segment
	after uint64
	idx   int
	f     *os.File
	r     *bufio.Reader
	first bool
}

func newSetIter(segs []*segment, after uint64) *setIter {
	it := &setIter{after: after, first: true}
	for _, g := range segs {
		if g.maxSeq > after {
			it.segs = append(it.segs, g)
		}
	}
	return it
}

func (it *setIter) close() {
	if it.f != nil {
		it.f.Close()
		it.f, it.r = nil, nil
	}
}

func (it *setIter) open() error {
	g := it.segs[it.idx]
	f, err := os.Open(g.path)
	if err != nil {
		return err
	}
	var off int64
	// The sparse table lets us skip most of a segment on resume.
	i := sort.Search(len(g.sparse), func(i int) bool { return g.sparse[i].seq > it.after })
	if i > 0 {
		off = g.sparse[i-1].off
	}
	it.f = f
	it.r = bufio.NewReaderSize(io.NewSectionReader(f, off, g.size-off), 32<<10)
	return nil
}

// next returns the next event and its frame size; ok is false at the end.
func (it *setIter) next() (ev event.Event, n int, ok bool, err error) {
	for {
		if it.idx >= len(it.segs) {
			return ev, 0, false, nil
		}
		if it.f == nil {
			if err := it.open(); err != nil {
				return ev, 0, false, err
			}
		}
		payload, n, rerr := readFrame(it.r)
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				it.close()
				it.idx++
				continue
			}
			return ev, 0, false, fmt.Errorf("spool: read %s: %w", filepath.Base(it.segs[it.idx].path), rerr)
		}
		ev, derr := decodeEvent(payload)
		if derr != nil {
			return ev, 0, false, derr
		}
		if ev.Seq <= it.after {
			continue
		}
		return ev, n, true, nil
	}
}
