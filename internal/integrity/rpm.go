package integrity

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// RPM header tags used here.
const (
	tagName            = 1000
	tagVersion         = 1001
	tagRelease         = 1002
	tagEpoch           = 1003
	tagSize            = 1009
	tagFileSizes       = 1028
	tagFileModes       = 1030
	tagFileDigests     = 1035
	tagFileLinkTos     = 1036
	tagFileFlags       = 1037
	tagArch            = 1022
	tagBaseNames       = 1117
	tagDirIndexes      = 1116
	tagDirNames        = 1118
	tagPayloadComp     = 1125
	tagLongFileSizes   = 5008
	tagFileDigestAlgo  = 5011
	rpmTypeInt32       = 4
	rpmTypeInt64       = 5
	rpmTypeString      = 6
	rpmTypeStringArray = 8
	rpmTypeI18N        = 9
	rpmTypeInt16       = 3
	rpmGhost           = 1 << 6
)

type rpmHeader struct {
	tags map[uint32]rpmTag
}
type rpmTag struct {
	typ   uint32
	count uint32
	data  []byte // slice of the data store starting at the tag offset
	store []byte
}

// parseRPMHeaderBlob parses "il dl" index + store (no 8-byte magic). Returns
// the header and the number of bytes consumed.
func parseRPMHeaderBlob(b []byte) (*rpmHeader, int, error) {
	if len(b) < 8 {
		return nil, 0, errors.New("integrity: short rpm header")
	}
	il := binary.BigEndian.Uint32(b[0:4])
	dl := binary.BigEndian.Uint32(b[4:8])
	if il > 1<<20 || dl > 1<<28 {
		return nil, 0, errors.New("integrity: rpm header too large")
	}
	need := 8 + int(il)*16 + int(dl)
	if len(b) < need {
		return nil, 0, errors.New("integrity: truncated rpm header")
	}
	store := b[8+int(il)*16 : need]
	h := &rpmHeader{tags: map[uint32]rpmTag{}}
	for i := 0; i < int(il); i++ {
		e := b[8+i*16 : 8+i*16+16]
		tag := binary.BigEndian.Uint32(e[0:4])
		typ := binary.BigEndian.Uint32(e[4:8])
		off := binary.BigEndian.Uint32(e[8:12])
		cnt := binary.BigEndian.Uint32(e[12:16])
		if int(off) > len(store) {
			continue // region-trailer / out of range tags are ignored
		}
		h.tags[tag] = rpmTag{typ: typ, count: cnt, data: store[off:], store: store}
	}
	return h, need, nil
}

func (h *rpmHeader) str(tag uint32) string {
	t, ok := h.tags[tag]
	if !ok || (t.typ != rpmTypeString && t.typ != rpmTypeI18N && t.typ != rpmTypeStringArray) {
		return ""
	}
	if i := bytes.IndexByte(t.data, 0); i >= 0 {
		return string(t.data[:i])
	}
	return ""
}

func (h *rpmHeader) strs(tag uint32) []string {
	t, ok := h.tags[tag]
	if !ok || t.typ != rpmTypeStringArray {
		return nil
	}
	out := make([]string, 0, t.count)
	d := t.data
	for i := uint32(0); i < t.count; i++ {
		j := bytes.IndexByte(d, 0)
		if j < 0 {
			return out
		}
		out = append(out, string(d[:j]))
		d = d[j+1:]
	}
	return out
}

func (h *rpmHeader) ints(tag uint32) []uint64 {
	t, ok := h.tags[tag]
	if !ok {
		return nil
	}
	w := map[uint32]int{rpmTypeInt16: 2, rpmTypeInt32: 4, rpmTypeInt64: 8}[t.typ]
	if w == 0 || int(t.count)*w > len(t.data) {
		return nil
	}
	out := make([]uint64, t.count)
	for i := range out {
		d := t.data[i*w:]
		switch w {
		case 2:
			out[i] = uint64(binary.BigEndian.Uint16(d))
		case 4:
			out[i] = uint64(binary.BigEndian.Uint32(d))
		case 8:
			out[i] = binary.BigEndian.Uint64(d)
		}
	}
	return out
}

// rpmFile is a file as described by an rpm header.
type rpmFile struct {
	Path   string
	Mode   uint32
	Size   int64
	Digest string // hex digest from the header ("" for dirs/ghosts)
	Link   string
	Flags  uint64
}

func (h *rpmHeader) files() []rpmFile {
	base := h.strs(tagBaseNames)
	dirs := h.strs(tagDirNames)
	di := h.ints(tagDirIndexes)
	if len(base) == 0 || len(di) != len(base) {
		return nil
	}
	modes := h.ints(tagFileModes)
	sizes := h.ints(tagLongFileSizes)
	if sizes == nil {
		sizes = h.ints(tagFileSizes)
	}
	digs := h.strs(tagFileDigests)
	links := h.strs(tagFileLinkTos)
	flags := h.ints(tagFileFlags)
	out := make([]rpmFile, len(base))
	for i := range base {
		if int(di[i]) >= len(dirs) {
			continue
		}
		f := rpmFile{Path: dirs[di[i]] + base[i]}
		if i < len(modes) {
			f.Mode = uint32(modes[i])
		}
		if i < len(sizes) {
			f.Size = int64(sizes[i])
		}
		if i < len(digs) {
			f.Digest = digs[i]
		}
		if i < len(links) {
			f.Link = links[i]
		}
		if i < len(flags) {
			f.Flags = flags[i]
		}
		out[i] = f
	}
	return out
}

func (h *rpmHeader) nevra() (name, version, arch string) {
	v, rel := h.str(tagVersion), h.str(tagRelease)
	if rel != "" {
		v += "-" + rel
	}
	if e := h.ints(tagEpoch); len(e) == 1 {
		v = strconv.FormatUint(e[0], 10) + ":" + v
	}
	return h.str(tagName), v, h.str(tagArch)
}

// ReadRPMFile parses an .rpm from disk.
func ReadRPMFile(path string, lim ReadLimits) (*Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadRPM(f, lim)
}

// ReadRPM parses an RPM package: lead, signature header, main header (name,
// version, modes) and the cpio "newc" payload (gzip, xz, zstd or plain), hashing
// every regular file's content as it streams. Header digests are not trusted;
// the hash is computed from the payload.
func ReadRPM(r io.Reader, lim ReadLimits) (*Package, error) {
	lim = lim.withDefaults()
	var lead [96]byte
	if _, err := io.ReadFull(r, lead[:]); err != nil || !bytes.Equal(lead[:4], []byte{0xed, 0xab, 0xee, 0xdb}) {
		return nil, errors.New("integrity: not an rpm (bad lead)")
	}
	readHdr := func(pad bool) (*rpmHeader, error) {
		var pre [16]byte
		if _, err := io.ReadFull(r, pre[:]); err != nil {
			return nil, fmt.Errorf("integrity: rpm header: %w", err)
		}
		if !bytes.Equal(pre[:3], []byte{0x8e, 0xad, 0xe8}) {
			return nil, errors.New("integrity: bad rpm header magic")
		}
		il := binary.BigEndian.Uint32(pre[8:12])
		dl := binary.BigEndian.Uint32(pre[12:16])
		if il > 1<<20 || dl > 1<<28 {
			return nil, errors.New("integrity: rpm header too large")
		}
		body := make([]byte, 8+int(il)*16+int(dl))
		copy(body, pre[8:16])
		if _, err := io.ReadFull(r, body[8:]); err != nil {
			return nil, fmt.Errorf("integrity: rpm header body: %w", err)
		}
		h, _, err := parseRPMHeaderBlob(body)
		if err != nil {
			return nil, err
		}
		if pad {
			if p := (8 - len(body[8:])%8) % 8; p > 0 {
				if _, err := io.CopyN(io.Discard, r, int64(p)); err != nil {
					return nil, err
				}
			}
		}
		return h, nil
	}
	if _, err := readHdr(true); err != nil { // signature header, unused
		return nil, err
	}
	h, err := readHdr(false)
	if err != nil {
		return nil, err
	}
	pkg := &Package{Format: "rpm"}
	pkg.Name, pkg.Version, pkg.Arch = h.nevra()
	dr, closeFn, err := decompress(r, lim.MaxDecompressed)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	if err := readCpio(dr, pkg, lim); err != nil {
		return nil, err
	}
	for i := range pkg.Entries {
		pkg.Entries[i].Package, pkg.Entries[i].Version = pkg.Name, pkg.Version
	}
	return pkg, nil
}

func hex8(b []byte) (uint32, error) {
	v, err := strconv.ParseUint(string(b), 16, 32)
	return uint32(v), err
}

func readCpio(r io.Reader, pkg *Package, lim ReadLimits) error {
	type pend struct {
		path string
		mode uint32
	}
	pending := map[[2]uint32][]pend{} // (dev,ino) -> hardlinks awaiting data
	for {
		var h [110]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return fmt.Errorf("integrity: cpio header: %w", err)
		}
		if s := string(h[:6]); s != "070701" && s != "070702" {
			return fmt.Errorf("integrity: unsupported cpio magic %q", h[:6])
		}
		f := make([]uint32, 13)
		for i := range f {
			v, err := hex8(h[6+i*8 : 14+i*8])
			if err != nil {
				return errors.New("integrity: corrupt cpio header")
			}
			f[i] = v
		}
		mode, ino, nlink, fsize, devmaj, devmin, namesize := f[1], f[0], f[4], int64(f[6]), f[7], f[8], int64(f[11])
		if namesize <= 0 || namesize > 8192 {
			return errors.New("integrity: bad cpio name size")
		}
		nb := make([]byte, namesize)
		if _, err := io.ReadFull(r, nb); err != nil {
			return err
		}
		if _, err := io.CopyN(io.Discard, r, int64((4-(110+namesize)%4)%4)); err != nil {
			return err
		}
		name := strings.TrimRight(string(nb), "\x00")
		if name == "TRAILER!!!" {
			for _, ps := range pending { // hardlinks that never got data are empty files
				for _, pd := range ps {
					pkg.Entries = append(pkg.Entries, Entry{Path: pd.path, SHA256: sha256.Sum256(nil), Mode: pd.mode})
				}
			}
			return nil
		}
		if len(pkg.Entries) >= lim.MaxFiles {
			return errTooBig
		}
		p := NormalizePath(name)
		isReg := mode&0o170000 == 0o100000
		perm := mode & 0o7777
		dev := [2]uint32{devmaj<<16 | devmin, ino}
		var sum Sum
		var n int64
		if isReg && fsize > 0 {
			if fsize > lim.MaxFileSize {
				return errTooBig
			}
			hs := sha256.New()
			if _, err := io.CopyN(hs, r, fsize); err != nil {
				return fmt.Errorf("integrity: cpio data %s: %w", name, err)
			}
			copy(sum[:], hs.Sum(nil))
			n = fsize
			pkg.Entries = append(pkg.Entries, Entry{Path: p, SHA256: sum, Size: n, Mode: perm})
			for _, pd := range pending[dev] {
				pkg.Entries = append(pkg.Entries, Entry{Path: pd.path, SHA256: sum, Size: n, Mode: pd.mode})
			}
			delete(pending, dev)
		} else if isReg && nlink > 1 {
			pending[dev] = append(pending[dev], pend{p, perm})
		} else if isReg { // genuinely empty file
			sum = sha256.Sum256(nil)
			pkg.Entries = append(pkg.Entries, Entry{Path: p, SHA256: sum, Mode: perm})
		}
		if _, err := io.CopyN(io.Discard, r, fsize-n+int64((4-fsize%4)%4)); err != nil {
			return err
		}
	}
}
