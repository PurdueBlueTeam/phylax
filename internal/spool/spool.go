package spool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// GapKind is the Kind of the record that announces dropped sequence numbers.
// Fields: from, to (inclusive range), count, class. Its Seq is to+1 and its
// PrevHash is the hash of the last event before the range (the hash bridge),
// which is the shape the controller store accepts.
const GapKind = "spool.gap"

const (
	gapReserve  = 512 // generous size of one gap record frame
	lockName    = "spool.lock"
	defaultSeg  = 4 << 20
	defaultMax  = 200 << 20
	defaultSync = time.Second
)

var (
	// ErrShed means the event was dropped by the shedding policy (it is
	// Normal or Bulk and the spool is over that class's admission limit). The
	// loss is announced to the controller by a gap record.
	ErrShed = errors.New("spool: event shed")
	// ErrFull means a High or Critical event was dropped because the spool is
	// physically full of unacknowledged data. Also announced by a gap record.
	ErrFull = errors.New("spool: full")
	// ErrClosed is returned after Close.
	ErrClosed = errors.New("spool: closed")
)

// Options configures a spool.
type Options struct {
	Agent        string        // default Agent for events that carry none
	MaxBytes     int64         // size cap on segment data (default 200 MB)
	SegmentBytes int64         // roll threshold per segment (default 4 MB)
	SyncInterval time.Duration // bound on unsynced data (default 1 s); Critical events sync at once
	Now          func() time.Time
}

// Congestion states reported in heartbeats.
const (
	StateOK        = "ok"
	StateWarning   = "warning"   // unacked data at or above 90% of the cap
	StateFull      = "full"      // events were dropped
	StateRecovered = "recovered" // back under 70%
)

// Stats is a snapshot of spool health.
type Stats struct {
	HeadSeq, AckSeq, OldestSeq uint64
	Segments                   int
	UsedBytes, MaxBytes        int64
	UnackedBytes               int64
	Appended                   uint64
	Shed                       uint64 // events dropped (all announced by gap records)
	GapRecords                 uint64
	RepairedBytes              int64 // cut from damaged tails at Open
	State                      string
}

type pending struct {
	from, count uint64
	class       event.Priority
	label       string // overrides the class name when set
}

// Spool is safe for concurrent use.
type Spool struct {
	dir  string
	opts Options
	lock *dirLock

	mu       sync.Mutex
	closed   bool
	segs     []*segment // seq order; only the last may be open for writing
	used     int64
	ack      uint64
	ackHash  string
	headSeq  uint64 // last event written (virtual sequence numbers of a pending gap excluded)
	headHash string
	cursor   uint64
	run      *pending // dropped events not yet announced
	metaAt   time.Time
	metaAck  uint64
	state    string
	st       Stats
	stop     chan struct{}
	done     chan struct{}
}

// Open opens (creating if needed) the spool in dir, repairing damaged tails.
func Open(dir string, opts Options) (*Spool, error) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = defaultMax
	}
	if opts.SegmentBytes <= 0 {
		opts.SegmentBytes = defaultSeg
	}
	if opts.SyncInterval <= 0 {
		opts.SyncInterval = defaultSync
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	lk, err := lockDir(filepath.Join(dir, lockName))
	if err != nil {
		return nil, err
	}
	s := &Spool{dir: dir, opts: opts, lock: lk, state: StateOK, stop: make(chan struct{}), done: make(chan struct{})}
	if err := s.load(); err != nil {
		lk.unlock()
		return nil, err
	}
	go s.syncLoop()
	return s, nil
}

func (s *Spool) load() error {
	m := readMeta(s.dir)
	os.Remove(filepath.Join(s.dir, metaName+".tmp"))
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	var names []string
	for _, de := range ents {
		if isSegName(de.Name()) {
			names = append(names, de.Name())
		}
	}
	sort.Strings(names) // zero-padded first sequence: lexical == numeric
	var cut int64
	broken := false
	for _, n := range names {
		path := filepath.Join(s.dir, n)
		if broken { // everything after a break is unreachable by the chain
			if st, err := os.Stat(path); err == nil {
				cut += st.Size()
			}
			os.Remove(path)
			continue
		}
		g, c, err := scanSegment(path)
		if err != nil {
			return err
		}
		cut += c
		if g.count == 0 {
			os.Remove(path)
			broken = true
			continue
		}
		if k := len(s.segs); k > 0 {
			p := s.segs[k-1]
			if g.firstPrev != p.lastHash || g.firstFrom != p.maxSeq+1 {
				// Gap between segments: cannot be bridged without rewriting.
				cut += g.size
				os.Remove(path)
				broken = true
				continue
			}
		}
		s.segs = append(s.segs, g)
		s.used += g.size
		if c > 0 {
			broken = true
		}
	}
	s.st.RepairedBytes = cut
	if n := len(s.segs); n > 0 {
		s.headSeq, s.headHash = s.segs[n-1].maxSeq, s.segs[n-1].lastHash
	} else {
		s.headSeq, s.headHash = m.HeadSeq, m.HeadHash
		// With nothing left, the whole range above the ack is lost; bridge it
		// from the last acknowledged hash.
		if m.HeadSeq > m.Ack {
			s.headSeq, s.headHash = m.Ack, m.AckHash
		}
	}
	s.ack, s.ackHash = min(m.Ack, max(m.HeadSeq, s.headSeq)), m.AckHash
	s.metaAck = s.ack
	s.cursor = s.ack
	// The meta head can be ahead of the segments only if data was lost behind
	// its back. Never reuse sequence numbers the controller may hold: announce
	// the missing range with a gap record.
	if m.HeadSeq > s.headSeq {
		s.run = &pending{from: s.headSeq + 1, count: m.HeadSeq - s.headSeq, label: "unknown"}
		return s.flushRun()
	}
	return nil
}

func asUint(v any) uint64 {
	switch n := v.(type) {
	case uint64:
		return n
	case int:
		if n > 0 {
			return uint64(n)
		}
	case interface{ Int64() (int64, error) }:
		if i, err := n.Int64(); err == nil && i > 0 {
			return uint64(i)
		}
	}
	return 0
}

// flushRun writes the gap record for the pending dropped run. It bypasses the
// admission limits (a gap record is a few hundred bytes).
func (r *pending) className() string {
	if r.label != "" {
		return r.label
	}
	return r.class.String()
}

func (s *Spool) flushRun() error {
	r := s.run
	if r == nil {
		return nil
	}
	to := r.from + r.count - 1
	if err := s.reclaim(gapReserve); err != nil {
		return err // no room even for the record: keep the run pending
	}
	g := event.Event{
		Agent: s.opts.Agent, Time: s.opts.Now(), Kind: GapKind, Schema: 1, Priority: event.PriorityCritical,
		Fields: map[string]any{"from": r.from, "to": to, "count": r.count, "class": r.className()},
	}
	if err := g.Seal(to, s.headHash); err != nil {
		return err
	}
	if err := s.store(g); err != nil {
		return err
	}
	s.run = nil
	s.st.GapRecords++
	return nil
}

// Append seals e onto the chain (assigning Seq, PrevHash, Hash; filling Agent
// and Time if empty), stores it durably per the sync policy and returns it.
// If the event is dropped by the shedding policy the error is ErrShed or
// ErrFull, no event is stored, and a gap record will announce the loss.
func (s *Spool) Append(e event.Event) (event.Event, error) {
	if e.Priority > event.PriorityBulk {
		return e, fmt.Errorf("spool: invalid priority %d", e.Priority)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return e, ErrClosed
	}
	if e.Agent == "" {
		e.Agent = s.opts.Agent
	}
	if e.Time.IsZero() {
		e.Time = s.opts.Now()
	}
	probe := e
	if err := probe.Seal(s.headSeq+1<<40, s.headHash); err != nil { // generous sequence width
		return e, err
	}
	pl, err := encodeEvent(probe)
	if err != nil {
		return e, err
	}
	need := int64(frameHeader+len(pl)) + 64 // room for a gap record too
	if err := s.admit(e.Priority, need); err != nil {
		s.drop(e.Priority)
		if e.Priority >= event.PriorityNormal {
			return e, ErrShed
		}
		return e, ErrFull
	}
	err = s.flushRun()
	if err == nil {
		err = s.reclaim(need) // the gap record may have taken the room
	}
	if err != nil {
		if errors.Is(err, ErrFull) {
			s.drop(e.Priority)
			return e, ErrFull
		}
		return e, err
	}
	if err := e.Seal(s.headSeq, s.headHash); err != nil {
		return e, err
	}
	if err := s.store(e); err != nil {
		return e, err
	}
	s.st.Appended++
	s.updateState()
	return e, nil
}

// admit decides whether an event of class c needing n bytes may be stored.
// Acknowledged segments are reclaimed oldest-first only when the physical cap
// requires it; the class limit applies to unacknowledged data.
func (s *Spool) admit(c event.Priority, n int64) error {
	if n > s.opts.MaxBytes {
		return ErrFull
	}
	if s.unacked()+n > s.opts.MaxBytes*c.AdmitPercent()/100 {
		return ErrFull
	}
	return s.reclaim(n)
}

// reclaim deletes acknowledged segments, oldest first, until n more bytes fit
// under the physical cap. It fails with ErrFull if only unacked data is left.
func (s *Spool) reclaim(n int64) error {
	for s.used+n > s.opts.MaxBytes {
		if len(s.segs) == 0 || s.segs[0].maxSeq > s.ack {
			return ErrFull
		}
		if err := s.removeOldest(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Spool) unacked() int64 {
	var n int64
	for _, g := range s.segs {
		if g.maxSeq > s.ack {
			n += g.size
		}
	}
	return n
}

// drop records a dropped arrival in the pending run. The event consumes the
// next sequence number virtually: the run's gap record will take the one after.
func (s *Spool) drop(c event.Priority) {
	if s.run == nil {
		s.run = &pending{from: s.headSeq + 1, class: c}
	} else if s.run.class != c {
		s.run.label = "mixed" // one run, one gap record: no record per class switch
	}
	s.run.count++
	s.st.Shed++
	s.state = StateFull
}

// store writes a sealed event (already linked to the head) to the active
// segment and advances the head.
func (s *Spool) store(e event.Event) error {
	pl, err := encodeEvent(e)
	if err != nil {
		return err
	}
	frame := appendFrame(make([]byte, 0, frameHeader+len(pl)), pl)
	var g *segment
	if n := len(s.segs); n > 0 && s.segs[n-1].w != nil {
		g = s.segs[n-1]
		if g.size > 0 && g.size+int64(len(frame)) > s.opts.SegmentBytes {
			if err := s.closeActive(g); err != nil {
				return err
			}
			g = nil
		}
	}
	if g == nil {
		if g, err = s.newSegment(e.Seq); err != nil {
			return err
		}
	}
	if _, err := g.w.Write(frame); err != nil {
		// Roll back a partial write so the file stays frame-aligned.
		g.w.Truncate(g.size)
		g.w.Seek(g.size, 0)
		return fmt.Errorf("spool: write: %w", err)
	}
	g.note(e, len(frame))
	g.dirty = true
	s.used += int64(len(frame))
	s.headSeq, s.headHash = e.Seq, e.Hash
	if e.Priority == event.PriorityCritical {
		if err := g.sync(); err != nil {
			return fmt.Errorf("spool: sync: %w", err)
		}
	}
	return nil
}

func (g *segment) sync() error {
	if g.w == nil || !g.dirty {
		return nil
	}
	if err := g.w.Sync(); err != nil {
		return err
	}
	g.dirty = false
	return nil
}

func (s *Spool) newSegment(seq uint64) (*segment, error) {
	path := filepath.Join(s.dir, segName(seq))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("spool: new segment: %w", err)
	}
	if err := syncDir(s.dir); err != nil {
		f.Close()
		return nil, err
	}
	g := &segment{path: path, w: f}
	s.segs = append(s.segs, g)
	return g, nil
}

func (s *Spool) closeActive(g *segment) error {
	if g.w == nil {
		return nil
	}
	err := g.sync()
	if cerr := g.w.Close(); err == nil {
		err = cerr
	}
	g.w = nil
	return err
}

// removeOldest deletes the oldest segment. The chain head is persisted first
// so deleting every segment cannot lose it.
func (s *Spool) removeOldest() error {
	g := s.segs[0]
	if err := s.persistMeta(); err != nil {
		return err
	}
	if err := s.closeActive(g); err != nil {
		return err
	}
	if err := os.Remove(g.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("spool: remove segment: %w", err)
	}
	s.segs = s.segs[1:]
	s.used -= g.size
	return nil
}

func (s *Spool) updateState() {
	u := s.unacked()
	switch {
	case u*10 >= s.opts.MaxBytes*9:
		if s.state != StateFull {
			s.state = StateWarning
		}
	case u*10 <= s.opts.MaxBytes*7 && (s.state == StateFull || s.state == StateWarning):
		s.state = StateRecovered
	}
}

func (s *Spool) persistMeta() error {
	// The head recorded must be durable: it is what stops sequence reuse.
	if err := s.syncDirty(); err != nil {
		return fmt.Errorf("spool: sync: %w", err)
	}
	m := meta{Ack: s.ack, AckHash: s.ackHash, HeadSeq: s.headSeq, HeadHash: s.headHash}
	if err := writeMeta(s.dir, m); err != nil {
		return fmt.Errorf("spool: meta: %w", err)
	}
	s.metaAt, s.metaAck = s.opts.Now(), s.ack
	return nil
}

func (s *Spool) syncDirty() error {
	if n := len(s.segs); n > 0 {
		return s.segs[n-1].sync()
	}
	return nil
}

func (s *Spool) syncLoop() {
	defer close(s.done)
	t := time.NewTicker(s.opts.SyncInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.mu.Lock()
			if !s.closed {
				s.syncDirty()
				if s.ack != s.metaAck {
					s.persistMeta()
				}
			}
			s.mu.Unlock()
		}
	}
}

// ReadBatch returns up to maxEvents unacknowledged events (about maxBytes of
// stored frames, always at least one if any is pending) in sequence order,
// and advances the send cursor so successive calls continue where the last
// stopped. Everything returned is already durable. Sequence order, not
// priority order, is what the controller's chain check accepts; priority acts
// at admission and shedding instead. After a reconnect call Rewind.
func (s *Spool) ReadBatch(maxEvents, maxBytes int) ([]event.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if err := s.flushRun(); err != nil && !errors.Is(err, ErrFull) {
		return nil, err
	}
	if err := s.syncDirty(); err != nil {
		return nil, fmt.Errorf("spool: sync: %w", err)
	}
	it := newSetIter(s.segs, max(s.cursor, s.ack))
	defer it.close()
	var out []event.Event
	budget := maxBytes
	for len(out) < maxEvents && (budget > 0 || len(out) == 0) {
		ev, n, ok, err := it.next()
		if err != nil {
			return out, err
		}
		if !ok {
			break
		}
		out = append(out, ev)
		budget -= n
		s.cursor = ev.Seq
	}
	return out, nil
}

// Rewind resets the send cursor to the last acknowledged sequence.
func (s *Spool) Rewind() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cursor = s.ack
}

// Ack records the controller's cumulative acknowledgment: every event with
// Seq <= upTo has been received. Acked data is retained until space is needed.
func (s *Spool) Ack(upTo uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	upTo = min(upTo, s.headSeq)
	if upTo <= s.ack {
		return nil
	}
	s.ack = upTo
	s.ackHash = ""
	it := newSetIter(s.segs, upTo-1)
	if ev, _, ok, err := it.next(); err == nil && ok && ev.Seq == upTo {
		s.ackHash = ev.Hash
	}
	it.close()
	s.cursor = max(s.cursor, s.ack)
	s.updateState()
	if s.opts.Now().Sub(s.metaAt) >= s.opts.SyncInterval {
		return s.persistMeta()
	}
	return nil
}

// ResendFrom returns up to maxEvents retained events with Seq >= seq in
// sequence order, acknowledged or not, without touching the send cursor. It
// serves a restored controller and chain verification. Sequences already
// deleted are simply absent: compare the first Seq returned with seq, or see
// Stats.OldestSeq.
func (s *Spool) ResendFrom(seq uint64, maxEvents int) ([]event.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if err := s.flushRun(); err != nil && !errors.Is(err, ErrFull) {
		return nil, err
	}
	if err := s.syncDirty(); err != nil {
		return nil, err
	}
	if seq == 0 {
		seq = 1
	}
	it := newSetIter(s.segs, seq-1)
	defer it.close()
	var out []event.Event
	for len(out) < maxEvents {
		ev, _, ok, err := it.next()
		if err != nil {
			return out, err
		}
		if !ok {
			break
		}
		out = append(out, ev)
	}
	return out, nil
}

// Head returns the sequence and hash of the newest stored event.
func (s *Spool) Head() (uint64, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.headSeq, s.headHash
}

// Stats returns a snapshot.
func (s *Spool) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.st
	st.HeadSeq, st.AckSeq = s.headSeq, s.ack
	st.UsedBytes, st.MaxBytes, st.State = s.used, s.opts.MaxBytes, s.state
	st.Segments, st.UnackedBytes = len(s.segs), s.unacked()
	if len(s.segs) > 0 {
		st.OldestSeq = s.segs[0].minSeq
	}
	return st
}

// Close announces any pending gap, flushes, persists the meta file and
// releases the directory lock.
func (s *Spool) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.stop)
	err := s.flushRun()
	if errors.Is(err, ErrFull) {
		err = nil // no room to announce; the drops stay unannounced
	}
	if serr := s.syncDirty(); err == nil {
		err = serr
	}
	for _, g := range s.segs {
		if cerr := s.closeActive(g); err == nil {
			err = cerr
		}
	}
	if merr := s.persistMeta(); err == nil {
		err = merr
	}
	s.mu.Unlock()
	<-s.done
	if uerr := s.lock.unlock(); err == nil {
		err = uerr
	}
	return err
}
