package link

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func rawFrame(wire byte, body []byte) []byte {
	b := make([]byte, 5, 5+len(body))
	binary.BigEndian.PutUint32(b, uint32(len(body)+1))
	b[4] = wire
	return append(b, body...)
}

func TestFrameRoundTripCompressedAndPlain(t *testing.T) {
	var buf bytes.Buffer
	fw := NewFrameWriter(&buf)
	big := []byte(strings.Repeat(`{"k":"value"}`, 2000))
	small := []byte(`{"a":1}`)
	if err := fw.WriteFrame(TypeEvents, big, true); err != nil {
		t.Fatal(err)
	}
	if buf.Len() > len(big)/4 {
		t.Fatalf("compressible body not compressed: %d bytes on wire for %d", buf.Len(), len(big))
	}
	if buf.Bytes()[4]&compressedFlag == 0 {
		t.Fatal("compression flag not set")
	}
	fw.WriteFrame(TypeAck, small, true)
	fr := NewFrameReader(&buf)
	defer fr.Close()
	typ, body, err := fr.ReadFrame()
	if err != nil || typ != TypeEvents || !bytes.Equal(body, big) {
		t.Fatalf("compressed frame: %v %v", typ, err)
	}
	typ, body, err = fr.ReadFrame()
	if err != nil || typ != TypeAck || !bytes.Equal(body, small) {
		t.Fatalf("plain frame: %v %v", typ, err)
	}
	if _, _, err := fr.ReadFrame(); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestOversizedFrameRejectedWithoutReadingBody(t *testing.T) {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, MaxFrame+1)
	// Only the header exists: a reader that tried to buffer the body would hit EOF instead.
	_, _, err := NewFrameReader(bytes.NewReader(hdr)).ReadFrame()
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge, got %v", err)
	}
	binary.BigEndian.PutUint32(hdr, 0)
	if _, _, err := NewFrameReader(bytes.NewReader(hdr)).ReadFrame(); !errors.Is(err, ErrFrameEmpty) {
		t.Fatalf("want ErrFrameEmpty, got %v", err)
	}
	if err := NewFrameWriter(io.Discard).WriteFrame(TypeChunk, make([]byte, MaxFrame), false); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("writer accepted oversized frame: %v", err)
	}
}

func TestTruncatedFrame(t *testing.T) {
	f := rawFrame(byte(TypeAck), []byte(`{"seq":1}`))
	_, _, err := NewFrameReader(bytes.NewReader(f[:len(f)-3])).ReadFrame()
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want ErrUnexpectedEOF, got %v", err)
	}
}

// bomb: 64 MiB of zeros compresses to a few KiB, far under the frame cap.
func TestDecompressionBombRejected(t *testing.T) {
	const size = 64 << 20
	for _, tc := range []struct {
		name   string
		stream bool // streaming encoders omit the content size from the header
	}{{"declared-size", false}, {"undeclared-size", true}} {
		t.Run(tc.name, func(t *testing.T) {
			zeros := make([]byte, size)
			var c []byte
			if tc.stream {
				var b bytes.Buffer
				w, _ := zstd.NewWriter(&b)
				w.Write(zeros)
				w.Close()
				c = b.Bytes()
			} else {
				e, _ := zstd.NewWriter(nil)
				c = e.EncodeAll(zeros, nil)
			}
			if len(c) > MaxFrame {
				t.Fatalf("test bomb too big: %d", len(c))
			}
			frame := rawFrame(byte(TypeEvents)|compressedFlag, c)
			_, _, err := NewFrameReader(bytes.NewReader(frame)).ReadFrame()
			if !errors.Is(err, ErrDecompressLimit) {
				t.Fatalf("want ErrDecompressLimit, got %v", err)
			}
		})
	}
}

func TestDecompressionAtLimitAccepted(t *testing.T) {
	body := make([]byte, MaxDecompressed)
	var buf bytes.Buffer
	if err := NewFrameWriter(&buf).WriteFrame(TypeEvents, body, true); err != nil {
		t.Fatal(err)
	}
	_, got, err := NewFrameReader(&buf).ReadFrame()
	if err != nil || len(got) != MaxDecompressed {
		t.Fatalf("limit-sized body: %d %v", len(got), err)
	}
}

func TestGarbageCompressedBody(t *testing.T) {
	_, _, err := NewFrameReader(bytes.NewReader(rawFrame(byte(TypeEvents)|compressedFlag, []byte("not zstd at all")))).ReadFrame()
	if !errors.Is(err, ErrBadCompression) {
		t.Fatalf("want ErrBadCompression, got %v", err)
	}
}
