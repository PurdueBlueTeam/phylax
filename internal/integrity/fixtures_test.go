package integrity

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

type fxFile struct {
	Path string
	Data string
	Mode int64
	Link string // hardlink target (deb) / ignored for rpm
}

func compressAs(t testing.TB, kind string, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	switch kind {
	case "gz":
		w := gzip.NewWriter(&out)
		w.Write(b)
		w.Close()
	case "xz":
		w, err := xz.NewWriter(&out)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(b)
		w.Close()
	case "zst":
		w, _ := zstd.NewWriter(&out)
		w.Write(b)
		w.Close()
	case "":
		return b
	default:
		t.Fatal("kind", kind)
	}
	return out.Bytes()
}

func tarOf(t testing.TB, files []fxFile) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	tw.WriteHeader(&tar.Header{Name: "./usr/", Typeflag: tar.TypeDir, Mode: 0o755})
	for _, f := range files {
		if f.Link != "" {
			tw.WriteHeader(&tar.Header{Name: "." + f.Path, Typeflag: tar.TypeLink, Linkname: "." + f.Link, Mode: f.Mode})
			continue
		}
		tw.WriteHeader(&tar.Header{Name: "." + f.Path, Typeflag: tar.TypeReg, Size: int64(len(f.Data)), Mode: f.Mode})
		tw.Write([]byte(f.Data))
	}
	tw.WriteHeader(&tar.Header{Name: "./usr/bin/sym", Typeflag: tar.TypeSymlink, Linkname: "x"})
	tw.Close()
	return b.Bytes()
}

// makeDeb builds a synthetic .deb. dataComp is gz, xz, zst or "".
func makeDeb(t testing.TB, name, version, dataComp string, files []fxFile) []byte {
	ctl := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: amd64\nDescription: x\n continued\n", name, version)
	var cb bytes.Buffer
	tw := tar.NewWriter(&cb)
	tw.WriteHeader(&tar.Header{Name: "./control", Size: int64(len(ctl)), Mode: 0o644})
	tw.Write([]byte(ctl))
	tw.Close()
	var out bytes.Buffer
	out.WriteString("!<arch>\n")
	member := func(n string, data []byte) {
		fmt.Fprintf(&out, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", n+"/", 0, 0, 0, "100644", len(data))
		out.Write(data)
		if len(data)%2 == 1 {
			out.WriteByte('\n')
		}
	}
	member("debian-binary", []byte("2.0\n"))
	member("control.tar.gz", compressAs(t, "gz", cb.Bytes()))
	ext := ".tar"
	if dataComp != "" {
		ext += "." + dataComp
	}
	member("data"+ext, compressAs(t, dataComp, tarOf(t, files)))
	return out.Bytes()
}

type rpmTagVal struct {
	tag uint32
	typ uint32
	val any // string, []string, []uint32
}

func rpmHeaderBytes(tags []rpmTagVal, magic bool) []byte {
	sort.Slice(tags, func(i, j int) bool { return tags[i].tag < tags[j].tag })
	var store bytes.Buffer
	var idx bytes.Buffer
	for _, tg := range tags {
		if tg.typ == rpmTypeInt32 {
			for store.Len()%4 != 0 {
				store.WriteByte(0)
			}
		}
		off := store.Len()
		count := 1
		switch v := tg.val.(type) {
		case string:
			store.WriteString(v)
			store.WriteByte(0)
		case []string:
			count = len(v)
			for _, s := range v {
				store.WriteString(s)
				store.WriteByte(0)
			}
		case []uint32:
			count = len(v)
			for _, x := range v {
				binary.Write(&store, binary.BigEndian, x)
			}
		}
		binary.Write(&idx, binary.BigEndian, []uint32{tg.tag, tg.typ, uint32(off), uint32(count)})
	}
	var out bytes.Buffer
	if magic {
		out.Write([]byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0})
	}
	binary.Write(&out, binary.BigEndian, []uint32{uint32(len(tags)), uint32(store.Len())})
	out.Write(idx.Bytes())
	out.Write(store.Bytes())
	return out.Bytes()
}

func cpioNewc(files []fxFile) []byte {
	var b bytes.Buffer
	ino := uint32(1)
	ent := func(name string, mode, nlink uint32, data string, ino uint32) {
		fmt.Fprintf(&b, "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x", ino, mode, 0, 0, nlink, 0, len(data), 0, 0, 0, 0, len(name)+1, 0)
		b.WriteString(name)
		b.WriteByte(0)
		for (110+len(name)+1)%4 != 0 && b.Len()%4 != 0 {
			b.WriteByte(0)
		}
		b.WriteString(data)
		for b.Len()%4 != 0 {
			b.WriteByte(0)
		}
	}
	inoOf := map[string]uint32{}
	for _, f := range files {
		if f.Link != "" {
			continue
		}
		inoOf[f.Path] = ino
		ino++
	}
	for _, f := range files {
		name := "." + f.Path
		switch {
		case f.Link != "": // hardlink: first has no data, last carries it (here: link entry first, target later)
			ent(name, 0o100000|uint32(f.Mode), 2, "", inoOf[f.Link])
		default:
			nl := uint32(1)
			for _, g := range files {
				if g.Link == f.Path {
					nl = 2
				}
			}
			ent(name, 0o100000|uint32(f.Mode), nl, f.Data, inoOf[f.Path])
		}
	}
	ent("TRAILER!!!", 0, 1, "", 0)
	return b.Bytes()
}

// makeRPM builds a synthetic .rpm with a cpio newc payload.
func makeRPM(t testing.TB, name, version, release, payloadComp string, files []fxFile) []byte {
	var dirs []string
	dirIdx := map[string]uint32{}
	var bases []string
	var di, modes []uint32
	for _, f := range files {
		d, b := f.Path[:lastSlash(f.Path)+1], f.Path[lastSlash(f.Path)+1:]
		if _, ok := dirIdx[d]; !ok {
			dirIdx[d] = uint32(len(dirs))
			dirs = append(dirs, d)
		}
		bases = append(bases, b)
		di = append(di, dirIdx[d])
		modes = append(modes, 0o100000|uint32(f.Mode))
	}
	var digs []string
	var sizes []uint32
	for _, f := range files {
		d := f.Data
		if f.Link != "" {
			for _, g := range files {
				if g.Path == f.Link {
					d = g.Data
				}
			}
		}
		s := sha256.Sum256([]byte(d))
		digs = append(digs, fmt.Sprintf("%x", s))
		sizes = append(sizes, uint32(len(d)))
	}
	hdr := rpmHeaderBytes([]rpmTagVal{
		{tagName, rpmTypeString, name}, {tagVersion, rpmTypeString, version}, {tagRelease, rpmTypeString, release},
		{tagArch, rpmTypeString, "x86_64"}, {tagBaseNames, rpmTypeStringArray, bases}, {tagDirNames, rpmTypeStringArray, dirs},
		{tagDirIndexes, rpmTypeInt32, di}, {tagFileModes, rpmTypeInt16 + 1, modes}, {tagFileSizes, rpmTypeInt32, sizes},
		{tagFileDigests, rpmTypeStringArray, digs}, {tagFileDigestAlgo, rpmTypeInt32, []uint32{8}},
	}, true)
	var out bytes.Buffer
	lead := make([]byte, 96)
	copy(lead, []byte{0xed, 0xab, 0xee, 0xdb, 3, 0})
	out.Write(lead)
	sig := rpmHeaderBytes([]rpmTagVal{{62, rpmTypeString, "x"}}, true) // 1 string tag, data 2 bytes -> exercises 8-byte padding
	out.Write(sig)
	for (len(sig)-16)%8 != 0 { // pad data store to 8
		out.WriteByte(0)
		sig = append(sig, 0)
	}
	out.Write(hdr)
	out.Write(compressAs(t, payloadComp, cpioNewc(files)))
	return out.Bytes()
}

func lastSlash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}

func sumOf(s string) Sum { return sha256.Sum256([]byte(s)) }
