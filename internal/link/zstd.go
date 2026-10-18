package link

import (
	"github.com/klauspost/compress/zstd"
)

var (
	zstdEnc *zstd.Encoder
	zstdDec *zstd.Decoder
)

func init() {
	var err error
	zstdEnc, err = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		panic(err)
	}
	zstdDec, err = zstd.NewReader(nil)
	if err != nil {
		panic(err)
	}
}

func zstdCompress(b []byte) []byte { return zstdEnc.EncodeAll(b, nil) }

func zstdDecompress(b []byte) ([]byte, error) {
	out, err := zstdDec.DecodeAll(b, nil)
	return out, err
}
