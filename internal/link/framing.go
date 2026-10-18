// Package link implements the Phylax wire protocol: TLS with pinned keys,
// length-prefixed framing, zstd compression, priority-ordered sending and
// the message type registry. See docs/protocol.md.
package link

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxMessage is the maximum framed message size (type byte + body).
const MaxMessage = 4 << 20

// compThreshold is the body size above which zstd compression is attempted.
const compThreshold = 512

// Message types (docs/protocol.md § Message types).
const (
	TypHello        byte = 0x01
	TypHeartbeat    byte = 0x02
	TypEvents       byte = 0x03
	TypStepResult   byte = 0x04
	TypChunk        byte = 0x05
	TypAck          byte = 0x10
	TypStep         byte = 0x11
	TypConfig       byte = 0x12
	TypFetch        byte = 0x13
	TypChunkC2A     byte = 0x14 // controller -> agent chunk
	TypControl      byte = 0x15
	TypRelayRequest byte = 0x16
)

// Compression flag bit: set in the type byte for zstd-compressed bodies.
const FlagCompressed byte = 0x80

// Message is one framed protocol message.
type Message struct {
	Type    byte // without FlagCompressed
	Payload []byte
}

// Reader reads framed messages from r.
type Reader struct {
	r io.Reader
}

func NewReader(r io.Reader) *Reader { return &Reader{r: r} }

// Read reads one message, decompressing when the flag is set.
func (rd *Reader) Read() (*Message, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(rd.r, hdr[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(hdr[:4])
	typ := hdr[4]
	if length < 1 || length > MaxMessage {
		return nil, fmt.Errorf("link: bad message length %d", length)
	}
	body := make([]byte, length-1)
	if _, err := io.ReadFull(rd.r, body); err != nil {
		return nil, err
	}
	compressed := typ&FlagCompressed != 0
	t := typ &^ FlagCompressed
	if compressed {
		var err error
		body, err = zstdDecompress(body)
		if err != nil {
			return nil, fmt.Errorf("link: decompress: %w", err)
		}
		if len(body) > MaxMessage {
			return nil, errors.New("link: decompressed body exceeds limit")
		}
	}
	return &Message{Type: t, Payload: body}, nil
}

// Writer writes framed messages to w.
type Writer struct {
	w io.Writer
}

func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// Write frames and writes one message, compressing bodies that shrink.
func (wr *Writer) Write(m *Message) error {
	body := m.Payload
	typ := m.Type
	if len(body) > compThreshold {
		if c := zstdCompress(body); len(c) < len(body) {
			body, typ = c, m.Type|FlagCompressed
		}
	}
	if 1+len(body) > MaxMessage {
		return fmt.Errorf("link: message too large: %d", 1+len(body))
	}
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[:4], uint32(1+len(body)))
	hdr[4] = typ
	if _, err := wr.w.Write(hdr[:]); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := wr.w.Write(body); err != nil {
			return err
		}
	}
	return nil
}

// EncodeJSON marshals v as a message payload.
func EncodeJSON(v any) ([]byte, error) { return json.Marshal(v) }

// DecodeJSON unmarshals a message payload into v.
func DecodeJSON(p []byte, v any) error { return json.Unmarshal(p, v) }
