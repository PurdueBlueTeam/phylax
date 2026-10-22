package integrity

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

// On-disk format (all integers uvarint unless noted):
//
//	"PXLG1\n"                          magic
//	metaLen, meta JSON
//	sigLen, signature                  over sha256(magic || metaLen || meta || payload)
//	payload                            zstd stream of the body below
//
// body: string table (count, then len+bytes each), entry count, entries sorted
// by (path, hash) with front-coded paths (shared-prefix length, suffix),
// 32-byte sha256, size, mode, source byte and string-table indexes for
// package, version, signer and os; then the known-bad list (count, hash, label
// index). Sorted + front-coded + zstd keeps a full distro ledger compact.
const magic = "PXLG1\n"

// Signer signs ledger files. The release key lives behind this interface.
type Signer interface {
	Sign(msg []byte) ([]byte, error)
}

// Verifier verifies ledger signatures.
type Verifier interface{ Verify(msg, sig []byte) error }

// Ed25519Signer signs with an ed25519 private key.
type Ed25519Signer struct{ Key ed25519.PrivateKey }

func (s Ed25519Signer) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.Key, msg), nil }

// Ed25519Verifier verifies with an ed25519 public key.
type Ed25519Verifier struct{ Key ed25519.PublicKey }

// ErrBadSignature is returned when a ledger signature does not verify.
var ErrBadSignature = errors.New("integrity: ledger signature invalid")

func (v Ed25519Verifier) Verify(msg, sig []byte) error {
	if len(v.Key) != ed25519.PublicKeySize || !ed25519.Verify(v.Key, msg, sig) {
		return ErrBadSignature
	}
	return nil
}

// MaxLedgerBytes bounds the decompressed size of a ledger body.
const MaxLedgerBytes = 1 << 30

type strtab struct {
	idx map[string]uint64
	l   []string
}

func (t *strtab) id(s string) uint64 {
	if i, ok := t.idx[s]; ok {
		return i
	}
	i := uint64(len(t.l))
	t.idx[s] = i
	t.l = append(t.l, s)
	return i
}

// Marshal encodes the ledger. sg may be nil for an unsigned ledger (tests,
// local caches); production ledgers are signed.
func (l *Ledger) Marshal(sg Signer) ([]byte, error) {
	tab := &strtab{idx: map[string]uint64{}}
	ents := l.Entries()
	var body bytes.Buffer
	put := func(v uint64) { var b [binary.MaxVarintLen64]byte; body.Write(b[:binary.PutUvarint(b[:], v)]) }
	var rows bytes.Buffer
	rput := func(v uint64) { var b [binary.MaxVarintLen64]byte; rows.Write(b[:binary.PutUvarint(b[:], v)]) }
	prev := ""
	for _, e := range ents {
		n := 0
		for n < len(prev) && n < len(e.Path) && prev[n] == e.Path[n] {
			n++
		}
		rput(uint64(n))
		rput(uint64(len(e.Path) - n))
		rows.WriteString(e.Path[n:])
		rows.Write(e.SHA256[:])
		rput(uint64(e.Size))
		rput(uint64(e.Mode))
		rows.WriteByte(byte(e.Source))
		rput(tab.id(e.Package))
		rput(tab.id(e.Version))
		rput(tab.id(e.Signer))
		rput(tab.id(e.OS))
		prev = e.Path
	}
	var bad bytes.Buffer
	bput := func(v uint64) { var b [binary.MaxVarintLen64]byte; bad.Write(b[:binary.PutUvarint(b[:], v)]) }
	badKeys := make([]Sum, 0, len(l.bad))
	for s := range l.bad {
		badKeys = append(badKeys, s)
	}
	sortSums(badKeys)
	bput(uint64(len(badKeys)))
	for _, s := range badKeys {
		bad.Write(s[:])
		bput(tab.id(l.bad[s]))
	}
	put(uint64(len(tab.l)))
	for _, s := range tab.l {
		put(uint64(len(s)))
		body.WriteString(s)
	}
	put(uint64(len(ents)))
	body.Write(rows.Bytes())
	body.Write(bad.Bytes())

	var comp bytes.Buffer
	zw, err := zstd.NewWriter(&comp, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(body.Bytes()); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	meta, err := json.Marshal(l.Meta)
	if err != nil {
		return nil, err
	}
	var head bytes.Buffer
	head.WriteString(magic)
	var vb [binary.MaxVarintLen64]byte
	head.Write(vb[:binary.PutUvarint(vb[:], uint64(len(meta)))])
	head.Write(meta)
	var sig []byte
	if sg != nil {
		sig, err = sg.Sign(signedMessage(head.Bytes(), comp.Bytes()))
		if err != nil {
			return nil, err
		}
	}
	var out bytes.Buffer
	out.Write(head.Bytes())
	out.Write(vb[:binary.PutUvarint(vb[:], uint64(len(sig)))])
	out.Write(sig)
	out.Write(comp.Bytes())
	return out.Bytes(), nil
}

func signedMessage(head, payload []byte) []byte {
	h := sha256.New()
	h.Write(head)
	h.Write(payload)
	return h.Sum(nil)
}

func sortSums(s []Sum) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && bytes.Compare(s[j][:], s[j-1][:]) < 0; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// Unmarshal decodes a ledger. If v is nil the ledger must be unsigned-tolerant:
// callers that require a signature must pass a Verifier; with v == nil the
// signature is not checked (only for local, already-trusted caches).
func Unmarshal(data []byte, v Verifier) (*Ledger, error) {
	if !bytes.HasPrefix(data, []byte(magic)) {
		return nil, errors.New("integrity: not a ledger file")
	}
	r := bytes.NewReader(data[len(magic):])
	metaLen, err := binary.ReadUvarint(r)
	if err != nil || metaLen > uint64(r.Len()) {
		return nil, errors.New("integrity: corrupt ledger header")
	}
	meta := make([]byte, metaLen)
	io.ReadFull(r, meta)
	headLen := len(data) - r.Len()
	head := data[:headLen]
	sigLen, err := binary.ReadUvarint(r)
	if err != nil || sigLen > uint64(r.Len()) {
		return nil, errors.New("integrity: corrupt ledger header")
	}
	sig := make([]byte, sigLen)
	io.ReadFull(r, sig)
	payload := data[len(data)-r.Len():]
	if v != nil {
		if err := v.Verify(signedMessage(head, payload), sig); err != nil {
			return nil, err
		}
	}
	var m Meta
	if err := json.Unmarshal(meta, &m); err != nil {
		return nil, fmt.Errorf("integrity: ledger meta: %w", err)
	}
	zr, err := zstd.NewReader(bytes.NewReader(payload), zstd.WithDecoderMaxMemory(MaxLedgerBytes))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	br := bufio.NewReader(io.LimitReader(zr, MaxLedgerBytes))
	rd := func() uint64 {
		if err != nil {
			return 0
		}
		var x uint64
		x, err = binary.ReadUvarint(br)
		return x
	}
	readN := func(n uint64) []byte {
		if err != nil {
			return nil
		}
		if n > MaxLedgerBytes {
			err = errors.New("integrity: oversized field")
			return nil
		}
		b := make([]byte, n)
		_, err = io.ReadFull(br, b)
		return b
	}
	ns := rd()
	if err == nil && ns > MaxLedgerBytes {
		err = errors.New("integrity: corrupt string table")
	}
	var tab []string
	for i := uint64(0); i < ns && err == nil; i++ {
		tab = append(tab, string(readN(rd())))
	}
	str := func(i uint64) string {
		if i >= uint64(len(tab)) {
			if err == nil {
				err = errors.New("integrity: bad string index")
			}
			return ""
		}
		return tab[i]
	}
	l := NewLedger(m)
	ne := rd()
	prev := ""
	for i := uint64(0); i < ne && err == nil; i++ {
		share := rd()
		suf := rd()
		if err == nil && share > uint64(len(prev)) {
			err = errors.New("integrity: corrupt path prefix")
			break
		}
		path := prev[:share] + string(readN(suf))
		var e Entry
		e.Path = path
		copy(e.SHA256[:], readN(32))
		e.Size = int64(rd())
		e.Mode = uint32(rd())
		if sb := readN(1); len(sb) == 1 {
			e.Source = Source(sb[0])
		}
		e.Package = str(rd())
		e.Version = str(rd())
		e.Signer = str(rd())
		e.OS = str(rd())
		if err != nil {
			break
		}
		l.Add(e)
		prev = path
	}
	nb := rd()
	for i := uint64(0); i < nb && err == nil; i++ {
		var s Sum
		copy(s[:], readN(32))
		lbl := str(rd())
		if err == nil {
			l.bad[s] = lbl
		}
	}
	if err != nil {
		return nil, fmt.Errorf("integrity: decode ledger: %w", err)
	}
	return l, nil
}
