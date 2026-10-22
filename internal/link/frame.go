package link

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

const (
	// MaxFrame bounds the length field (type byte + body) on the wire.
	MaxFrame = 4 << 20
	// MaxDecompressed bounds a compressed body after decompression.
	MaxDecompressed = 4 << 20
	// ChunkSize is the size of bulk chunks.
	ChunkSize = 256 << 10
	// compressedFlag is OR-ed into the type byte of zstd-compressed bodies.
	compressedFlag = 0x40
	// compressMin is the smallest body worth compressing.
	compressMin = 512
)

var (
	ErrFrameTooLarge   = errors.New("link: frame exceeds maximum size")
	ErrFrameEmpty      = errors.New("link: empty frame")
	ErrDecompressLimit = errors.New("link: decompressed body exceeds limit")
	ErrBadCompression  = errors.New("link: bad compressed body")
)

var encoder = mustEncoder()

func mustEncoder() *zstd.Encoder {
	e, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithWindowSize(1<<20))
	if err != nil {
		panic(err)
	}
	return e
}

// FrameWriter writes frames. It is not safe for concurrent use.
type FrameWriter struct {
	w   io.Writer
	buf []byte
}

func NewFrameWriter(w io.Writer) *FrameWriter { return &FrameWriter{w: w} }

// WriteFrame writes one frame. If compress is true and the body is large
// enough and compresses smaller, it is sent zstd-compressed.
func (fw *FrameWriter) WriteFrame(t Type, body []byte, compress bool) error {
	if t&compressedFlag != 0 {
		return fmt.Errorf("link: type 0x%02x collides with compression flag", byte(t))
	}
	wire := byte(t)
	if compress && len(body) >= compressMin {
		if len(body) > MaxDecompressed {
			return ErrFrameTooLarge
		}
		c := encoder.EncodeAll(body, nil)
		if len(c) < len(body) {
			body = c
			wire |= compressedFlag
		}
	}
	n := len(body) + 1
	if n > MaxFrame {
		return ErrFrameTooLarge
	}
	fw.buf = append(fw.buf[:0], 0, 0, 0, 0, wire)
	binary.BigEndian.PutUint32(fw.buf, uint32(n))
	fw.buf = append(fw.buf, body...)
	_, err := fw.w.Write(fw.buf) // one Write keeps frames atomic on the stream
	if cap(fw.buf) > 1<<20 {
		fw.buf = nil
	}
	return err
}

// FrameReader reads frames. It is not safe for concurrent use.
type FrameReader struct {
	r   io.Reader
	dec *zstd.Decoder
	hdr [4]byte
}

func NewFrameReader(r io.Reader) *FrameReader { return &FrameReader{r: r} }

// ReadFrame returns the next frame's type and (decompressed) body. The length
// is checked before any body byte is buffered, and the buffer grows only as
// data actually arrives, so a peer cannot make us allocate by merely claiming
// a large frame.
func (fr *FrameReader) ReadFrame() (Type, []byte, error) {
	if _, err := io.ReadFull(fr.r, fr.hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(fr.hdr[:])
	if n == 0 {
		return 0, nil, ErrFrameEmpty
	}
	if n > MaxFrame {
		return 0, nil, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, n, MaxFrame)
	}
	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, fr.r, int64(n)); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	raw := buf.Bytes()
	wire, body := raw[0], raw[1:]
	if wire&compressedFlag == 0 {
		return Type(wire), body, nil
	}
	out, err := fr.decompress(body)
	if err != nil {
		return 0, nil, err
	}
	return Type(wire &^ compressedFlag), out, nil
}

func (fr *FrameReader) decompress(body []byte) ([]byte, error) {
	// Reject an oversized declared content size before touching the decoder.
	var h zstd.Header
	if err := h.Decode(body); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadCompression, err)
	}
	if h.HasFCS && h.FrameContentSize > MaxDecompressed {
		return nil, fmt.Errorf("%w: declared %d", ErrDecompressLimit, h.FrameContentSize)
	}
	if fr.dec == nil {
		d, err := zstd.NewReader(nil,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxMemory(MaxDecompressed),
			zstd.WithDecoderMaxWindow(8<<20))
		if err != nil {
			return nil, err
		}
		fr.dec = d
	}
	if err := fr.dec.Reset(bytes.NewReader(body)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadCompression, err)
	}
	// The limit reader enforces the cap even when a frame lies about its size.
	out, err := io.ReadAll(io.LimitReader(fr.dec, MaxDecompressed+1))
	if errors.Is(err, zstd.ErrDecoderSizeExceeded) || errors.Is(err, zstd.ErrWindowSizeExceeded) {
		return nil, fmt.Errorf("%w: %v", ErrDecompressLimit, err)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadCompression, err)
	}
	if len(out) > MaxDecompressed {
		return nil, ErrDecompressLimit
	}
	return out, nil
}

// Close releases decoder resources.
func (fr *FrameReader) Close() {
	if fr.dec != nil {
		fr.dec.Close()
	}
}
