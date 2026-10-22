package integrity

import (
	"archive/tar"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Package is the parsed content of a vendor package.
type Package struct {
	Name, Version, Arch string
	Format              string // "deb" or "rpm"
	Entries             []Entry
}

// ReadDebFile parses a .deb from disk.
func ReadDebFile(path string, lim ReadLimits) (*Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadDeb(f, lim)
}

// ReadDeb parses a Debian package: an ar archive holding control.tar.* and
// data.tar.* (gzip, xz, zstd or plain). Every regular file in the data tarball
// is hashed (sha256) as it streams; hard links reuse the target's hash;
// symlinks, directories and devices are skipped. The result carries no OS or
// Source: the Builder stamps those.
func ReadDeb(r io.Reader, lim ReadLimits) (*Package, error) {
	lim = lim.withDefaults()
	var magicBuf [8]byte
	if _, err := io.ReadFull(r, magicBuf[:]); err != nil || string(magicBuf[:]) != "!<arch>\n" {
		return nil, errors.New("integrity: not a deb (bad ar magic)")
	}
	pkg := &Package{Format: "deb"}
	var haveData bool
	for {
		var hdr [60]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("integrity: deb ar header: %w", err)
		}
		if hdr[58] != '`' || hdr[59] != '\n' {
			return nil, errors.New("integrity: corrupt ar header")
		}
		name := strings.TrimRight(strings.TrimSpace(string(hdr[:16])), "/")
		size, err := strconv.ParseInt(strings.TrimSpace(string(hdr[48:58])), 10, 64)
		if err != nil || size < 0 {
			return nil, errors.New("integrity: corrupt ar size")
		}
		member := io.LimitReader(r, size)
		switch {
		case strings.HasPrefix(name, "control.tar"):
			if err := readDebControl(member, pkg, lim); err != nil {
				return nil, err
			}
		case strings.HasPrefix(name, "data.tar"):
			if err := readTarEntries(member, pkg, lim); err != nil {
				return nil, err
			}
			haveData = true
		}
		if _, err := io.Copy(io.Discard, member); err != nil {
			return nil, err
		}
		if size%2 == 1 { // ar pads members to even length
			if _, err := io.CopyN(io.Discard, r, 1); err != nil && err != io.EOF {
				return nil, err
			}
		}
	}
	if !haveData {
		return nil, errors.New("integrity: deb has no data.tar member")
	}
	for i := range pkg.Entries {
		pkg.Entries[i].Package, pkg.Entries[i].Version = pkg.Name, pkg.Version
	}
	return pkg, nil
}

func readDebControl(r io.Reader, pkg *Package, lim ReadLimits) error {
	dr, closeFn, err := decompress(r, 64<<20)
	if err != nil {
		return err
	}
	defer closeFn()
	tr := tar.NewReader(dr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("integrity: deb control tar: %w", err)
		}
		if strings.TrimPrefix(h.Name, "./") != "control" {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, 1<<20))
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(line, ":")
			if !ok || strings.HasPrefix(line, " ") {
				continue
			}
			switch strings.ToLower(k) {
			case "package":
				pkg.Name = strings.TrimSpace(v)
			case "version":
				pkg.Version = strings.TrimSpace(v)
			case "architecture":
				pkg.Arch = strings.TrimSpace(v)
			}
		}
	}
}

func tarMode(h *tar.Header) uint32 {
	m := uint32(h.Mode) & 0o777
	if h.Mode&0o4000 != 0 {
		m |= 0o4000
	}
	if h.Mode&0o2000 != 0 {
		m |= 0o2000
	}
	if h.Mode&0o1000 != 0 {
		m |= 0o1000
	}
	return m
}

func readTarEntries(r io.Reader, pkg *Package, lim ReadLimits) error {
	dr, closeFn, err := decompress(r, lim.MaxDecompressed)
	if err != nil {
		return err
	}
	defer closeFn()
	tr := tar.NewReader(dr)
	byPath := map[string]Entry{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("integrity: deb data tar: %w", err)
		}
		if len(pkg.Entries) >= lim.MaxFiles {
			return errTooBig
		}
		p := NormalizePath(h.Name)
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			if h.Size > lim.MaxFileSize {
				return errTooBig
			}
			hs := sha256.New()
			n, err := io.Copy(hs, tr)
			if err != nil {
				return fmt.Errorf("integrity: hashing %s: %w", h.Name, err)
			}
			e := Entry{Path: p, Size: n, Mode: tarMode(h)}
			copy(e.SHA256[:], hs.Sum(nil))
			byPath[p] = e
			pkg.Entries = append(pkg.Entries, e)
		case tar.TypeLink:
			if t, ok := byPath[NormalizePath(h.Linkname)]; ok {
				t.Path, t.Mode = p, tarMode(h)
				byPath[p] = t
				pkg.Entries = append(pkg.Entries, t)
			}
		}
	}
	return nil
}
