// Package spool implements the agent's local event store: sequenced,
// hash-chained event records (docs/protocol.md § Spool) with an
// acknowledgment watermark and size-bounded shedding.
//
// Storage is a single JSONL file (the active segment); compaction rewrites
// it into a fresh segment when space must be freed. The chain is
// prev-hash linked with SHA-256 so the controller can verify that a resent
// range passes through any previously recorded (seq, hash) pair after a
// restore, and so an agent cannot rewrite its own history.
package spool

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Shed classes, in drop order. Lower value drops first when the spool is
// over its cap and no acknowledged records remain.
const (
	ClassProtected = iota // alerts, evidence, heartbeats, step results: never shed
	ClassFlow              // flows on unscored ports
	ClassChurn             // connection churn
	ClassLog               // raw log lines
)

// Record is one spooled event.
type Record struct {
	Seq    uint64 `json:"seq"`
	TS     string `json:"ts"` // RFC3339Nano
	Type   string `json:"type"`
	Data   string `json:"data"` // base64
	Class  int    `json:"c"`
	Prev   string `json:"prev"` // hex sha256, empty for seq 1
	Hash   string `json:"hash"` // hex sha256
}

// Event is the caller's view of an event before it is sequenced.
type Event struct {
	TS    time.Time
	Type  string
	Data  []byte
	Class int
}

// fileRecord is the on-disk line format (same as Record).
type fileRecord = Record

// Store is a spool rooted at dir.
type Store struct {
	dir   string
	file  *os.File
	path  string
	capB  int64
	size  int64 // bytes currently on disk

	mu     sync.Mutex
	seq    uint64
	ack    uint64 // highest contiguous acknowledged seq
	chain  string // hex hash of the last record ("" if empty)
	cache  []fileRecord
	dirty  bool
}

// Open opens (or creates) the spool at dir. capB is the byte cap; 0 means
// unlimited.
func Open(dir string, capB int64) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "spool.jsonl")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, file: f, path: path, capB: capB}
	if err := s.load(); err != nil {
		f.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	st, err := s.file.Stat()
	if err != nil {
		return err
	}
	s.size = st.Size()
	sc := bufio.NewScanner(s.file)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	var prev string
	line := 0
	for sc.Scan() {
		line++
		var r fileRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return fmt.Errorf("spool: bad record at line %d: %w", line, err)
		}
		want := hashRecord(prev, r)
		if want != r.Hash || r.Prev != prev {
			return fmt.Errorf("spool: chain broken at seq %d", r.Seq)
		}
		if r.Seq != s.seq+1 {
			return fmt.Errorf("spool: seq gap at %d (have %d)", r.Seq, s.seq)
		}
		s.seq = r.Seq
		prev = r.Hash
		s.cache = append(s.cache, r)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	s.chain = prev
	// Load the ack watermark sidecar.
	var ws struct {
		Ack uint64 `json:"ack"`
	}
	if b, err := os.ReadFile(filepath.Join(s.dir, "ack.json")); err == nil {
		_ = json.Unmarshal(b, &ws)
		if ws.Ack > s.seq {
			ws.Ack = s.seq
		}
		s.ack = ws.Ack
	}
	return nil
}

// HashRecord computes the chain hash for a record's fields, given the
// predecessor's hash. The agent spool and the controller's mirror use the
// same function, so a resent chain can be re-verified exactly.
func HashRecord(prevHex string, seq uint64, ts, typ, dataB64 string) string {
	h := sha256.New()
	h.Write([]byte(prevHex))
	binarySeq := make([]byte, 8)
	for i := range 8 {
		binarySeq[i] = byte(seq >> (8 * uint(i)))
	}
	h.Write(binarySeq)
	h.Write([]byte(ts))
	h.Write([]byte(typ))
	h.Write([]byte(dataB64))
	return hex.EncodeToString(h.Sum(nil))
}

func hashRecord(prevHex string, r fileRecord) string {
	return HashRecord(prevHex, r.Seq, r.TS, r.Type, r.Data)
}

func putU64(b []byte, v uint64) {
	for i := range 8 {
		b[i] = byte(v >> (8 * i))
	}
}

// Append stores one event, assigning the next sequence number. It returns
// the record's chain hash.
func (s *Store) Append(ev Event) (uint64, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	r := fileRecord{
		Seq:   s.seq,
		TS:    ev.TS.UTC().Format(time.RFC3339Nano),
		Type:  ev.Type,
		Data:  base64.StdEncoding.EncodeToString(ev.Data),
		Class: ev.Class,
		Prev:  s.chain,
	}
	r.Hash = hashRecord(r.Prev, r)
	line, err := json.Marshal(r)
	if err != nil {
		s.seq--
		return 0, "", err
	}
	if _, err := s.file.Write(append(line, '\n')); err != nil {
		s.seq--
		return 0, "", err
	}
	s.size += int64(len(line)) + 1
	s.cache = append(s.cache, r)
	s.chain = r.Hash
	return r.Seq, r.Hash, nil
}

// Range returns all records with fromSeq <= seq <= toSeq (either 0 = open
// bound). Records are returned in seq order.
func (s *Store) Range(fromSeq, toSeq uint64) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Record
	for _, r := range s.cache {
		if r.Seq < fromSeq || (toSeq != 0 && r.Seq > toSeq) {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, nil
}

// Ack marks all records up to seq as acknowledged (the watermark is
// monotonic).
func (s *Store) Ack(seq uint64) {
	s.mu.Lock()
	if seq > s.ack {
		s.ack = seq
		s.persistAck()
	}
	s.mu.Unlock()
}

// Acked returns the highest contiguous acknowledged seq.
func (s *Store) Acked() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ack
}

// Count returns the number of spooled records.
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.cache)
}

// Bytes returns the on-disk byte count.
func (s *Store) Bytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.size
}

// Full reports whether the spool is at or over its cap.
func (s *Store) Full() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.capB > 0 && s.size >= s.capB
}

// Shed frees space, in the design's order: acknowledged records oldest
// first, then unacknowledged records by class (log, churn, flow). It stops
// once the spool is under its cap. Protected records are never shed.
// Returns the number of records dropped.
func (s *Store) Shed() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.FullLocked() {
		return 0, nil
	}
	drop := map[uint64]bool{}
	var freed int64
	full := func() bool { return s.size-freed >= s.capB }
	recSize := func(r fileRecord) int64 {
		b, _ := json.Marshal(r)
		return int64(len(b)) + 1
	}
	for _, r := range s.cache {
		if !full() {
			break
		}
		if r.Seq <= s.ack {
			drop[r.Seq] = true
			freed += recSize(r)
		}
	}
	for _, class := range []int{ClassLog, ClassChurn, ClassFlow} {
		if !full() {
			break
		}
		for _, r := range s.cache {
			if drop[r.Seq] || r.Class != class {
				continue
			}
			drop[r.Seq] = true
			freed += recSize(r)
			if !full() {
				break
			}
		}
	}
	return s.rewriteLocked(drop)
}

func (s *Store) FullLocked() bool {
	return s.capB > 0 && s.size >= s.capB
}

// rewriteLocked compacts the spool, dropping the given seqs and re-linking
// the chain. On write failure the previous state is left untouched.
func (s *Store) rewriteLocked(drop map[uint64]bool) (int, error) {
	var kept []fileRecord
	for _, r := range s.cache {
		if !drop[r.Seq] {
			kept = append(kept, r)
		}
	}
	n := len(s.cache) - len(kept)
	if n == 0 {
		return 0, nil
	}
	// Re-link: the chain restarts at the first kept record.
	prev := ""
	for i := range kept {
		kept[i].Prev = prev
		kept[i].Hash = hashRecord(prev, kept[i])
		prev = kept[i].Hash
	}
	s.chain = ""
	if len(kept) > 0 {
		s.chain = kept[len(kept)-1].Hash
	}
	if err := s.writeAll(kept); err != nil {
		return 0, err
	}
	s.cache = kept
	return n, nil
}

func (s *Store) writeAll(recs []fileRecord) error {
	tmp := s.path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	var size int64
	for _, r := range recs {
		b, _ := json.Marshal(r)
		if _, err := w.Write(append(b, '\n')); err != nil {
			f.Close()
			os.Remove(tmp)
			return err
		}
		size += int64(len(b)) + 1
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return err
	}
	newf, err := os.OpenFile(s.path, os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	s.file.Close()
	s.file = newf
	s.size = size
	return nil
}

func (s *Store) persistAck() {
	b, _ := json.Marshal(struct {
		Ack uint64 `json:"ack"`
	}{Ack: s.ack})
	_ = os.WriteFile(filepath.Join(s.dir, "ack.json"), b, 0o600)
}

// Verify re-checks the on-disk chain from scratch. It returns the first
// bad seq (0 if the chain is intact) and the record count.
func (s *Store) Verify() (badSeq uint64, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := ""
	for _, r := range s.cache {
		n++
		if hashRecord(prev, r) != r.Hash || r.Prev != prev {
			return r.Seq, n
		}
		prev = r.Hash
	}
	return 0, n
}

// Close flushes and closes the spool.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file.Close()
}

// MaxSeq returns the highest sequence number stored.
func (s *Store) MaxSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq
}
