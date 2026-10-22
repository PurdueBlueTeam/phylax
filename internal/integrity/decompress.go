package integrity

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"io"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// ReadLimits bound everything the package readers do with untrusted archives.
type ReadLimits struct {
	MaxDecompressed int64 // total decompressed bytes per stream (default 8 GiB)
	MaxFileSize     int64 // per-file bytes (default 4 GiB)
	MaxFiles        int   // entries per package (default 200000)
}

func (l ReadLimits) withDefaults() ReadLimits {
	if l.MaxDecompressed <= 0 {
		l.MaxDecompressed = 8 << 30
	}
	if l.MaxFileSize <= 0 {
		l.MaxFileSize = 4 << 30
	}
	if l.MaxFiles <= 0 {
		l.MaxFiles = 200000
	}
	return l
}

var errTooBig = errors.New("integrity: archive exceeds size limit")

// limitReader errors (rather than silently truncating) past n bytes.
type limitReader struct {
	r io.Reader
	n int64
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errTooBig
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

// decompress sniffs the compression of r (gzip, xz, zstd, bzip2 or none) and
// returns a bounded decompressing reader plus a close func.
func decompress(r io.Reader, max int64) (io.Reader, func(), error) {
	br := bufio.NewReaderSize(r, 64<<10)
	head, _ := br.Peek(6)
	var out io.Reader
	closer := func() {}
	switch {
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, nil, err
		}
		out, closer = gz, func() { gz.Close() }
	case bytes.HasPrefix(head, []byte{0xfd, '7', 'z', 'X', 'Z', 0}):
		xr, err := xz.NewReader(br)
		if err != nil {
			return nil, nil, err
		}
		out = xr
	case bytes.HasPrefix(head, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		zr, err := zstd.NewReader(br, zstd.WithDecoderMaxMemory(1<<30))
		if err != nil {
			return nil, nil, err
		}
		out, closer = zr, zr.Close
	case bytes.HasPrefix(head, []byte("BZh")):
		out = bzip2.NewReader(br)
	default:
		out = br
	}
	return &limitReader{r: out, n: max}, closer, nil
}
