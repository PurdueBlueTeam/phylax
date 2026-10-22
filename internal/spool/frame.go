package spool

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

const (
	frameHeader = 8       // u32 payload length, u32 crc32c(payload), little endian
	maxPayload  = 1 << 20 // bound on a single event frame
)

var (
	castagnoli = crc32.MakeTable(crc32.Castagnoli)

	// errTorn marks a frame cut short by a crash.
	errTorn = errors.New("spool: torn frame")
	// errCorrupt marks a frame that is complete but invalid.
	errCorrupt = errors.New("spool: corrupt frame")
)

// appendFrame appends the frame for payload to dst.
func appendFrame(dst, payload []byte) []byte {
	var h [frameHeader]byte
	binary.LittleEndian.PutUint32(h[0:], uint32(len(payload)))
	binary.LittleEndian.PutUint32(h[4:], crc32.Checksum(payload, castagnoli))
	dst = append(dst, h[:]...)
	return append(dst, payload...)
}

// readFrame reads one frame. It returns io.EOF at a clean end, errTorn for a
// truncated frame and errCorrupt for a bad length or checksum. n is the number
// of bytes the frame occupies.
func readFrame(r io.Reader) (payload []byte, n int, err error) {
	var h [frameHeader]byte
	got, err := io.ReadFull(r, h[:])
	if err != nil {
		if got == 0 && err == io.EOF {
			return nil, 0, io.EOF
		}
		return nil, 0, errTorn
	}
	ln := binary.LittleEndian.Uint32(h[0:])
	if ln == 0 || ln > maxPayload {
		return nil, 0, errCorrupt
	}
	buf := make([]byte, ln)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, 0, errTorn
	}
	if crc32.Checksum(buf, castagnoli) != binary.LittleEndian.Uint32(h[4:]) {
		return nil, 0, errCorrupt
	}
	return buf, frameHeader + int(ln), nil
}

// encodeEvent serialises a sealed event.
func encodeEvent(e event.Event) ([]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("spool: encode: %w", err)
	}
	if len(b) > maxPayload {
		return nil, fmt.Errorf("spool: event of %d bytes exceeds %d", len(b), maxPayload)
	}
	return b, nil
}

// decodeEvent parses an event frame payload and checks it is a self-consistent
// sealed event. Numbers are kept as json.Number so the hash recomputes exactly.
func decodeEvent(p []byte) (event.Event, error) {
	var e event.Event
	dec := json.NewDecoder(bytes.NewReader(p))
	dec.UseNumber()
	if err := dec.Decode(&e); err != nil {
		return e, fmt.Errorf("%w: %v", errCorrupt, err)
	}
	if dec.More() || e.Seq == 0 || e.Priority > event.PriorityBulk {
		return e, errCorrupt
	}
	h, err := e.ComputeHash()
	if err != nil || h != e.Hash {
		return e, fmt.Errorf("%w: hash mismatch", errCorrupt)
	}
	return e, nil
}
