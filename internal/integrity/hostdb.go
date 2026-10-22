package integrity

import (
	"bufio"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // pure-Go driver
)

// HostFile is what the host's package database claims about one file. It is a
// hint only: an attacker with root can edit these databases.
type HostFile struct {
	Package string
	Version string
	MD5     string // dpkg md5sums (lower hex), "" for rpm
	SHA256  string // rpm digest when the algorithm is sha256
}

// HostHints is the read-only view of dpkg / rpm metadata used to guess which
// package version to fetch and which version a host claims to run.
type HostHints struct {
	Packages map[string]string   // package -> installed version
	Files    map[string]HostFile // normalised path -> claim
}

func newHints() *HostHints {
	return &HostHints{Packages: map[string]string{}, Files: map[string]HostFile{}}
}

// ClaimedVersion returns the package version the host claims for a path.
func (h *HostHints) ClaimedVersion(path string) string {
	if h == nil {
		return ""
	}
	return h.Files[NormalizePath(path)].Version
}

// Owner returns the package the host claims owns path.
func (h *HostHints) Owner(path string) string {
	if h == nil {
		return ""
	}
	return h.Files[NormalizePath(path)].Package
}

// Entries returns hint ledger entries for files whose host digest is sha256
// (rpm). They carry SourceHostHint and never prove anything.
func (h *HostHints) Entries(osName string) []Entry {
	var out []Entry
	for p, f := range h.Files {
		if len(f.SHA256) != 64 {
			continue
		}
		s, err := ParseSum(f.SHA256)
		if err != nil {
			continue
		}
		out = append(out, Entry{Path: p, SHA256: s, Package: f.Package, Version: f.Version, OS: osName, Source: SourceHostHint})
	}
	return out
}

// ReadDpkgHints reads <root>/var/lib/dpkg/status and info/*.md5sums. root is
// "/" on a live host or a mounted image. Nothing is written.
func ReadDpkgHints(root string) (*HostHints, error) {
	h := newHints()
	dpkg := filepath.Join(root, "var/lib/dpkg")
	f, err := os.Open(filepath.Join(dpkg, "status"))
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var name, ver, status string
	flush := func() {
		if name != "" && ver != "" && strings.Contains(status, "installed") && !strings.Contains(status, "not-installed") {
			h.Packages[name] = ver
		}
		name, ver, status = "", "", ""
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if k, v, ok := strings.Cut(line, ": "); ok && !strings.HasPrefix(line, " ") {
			switch k {
			case "Package":
				name = v
			case "Version":
				ver = v
			case "Status":
				status = v
			}
		}
	}
	flush()
	f.Close()
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sums, _ := filepath.Glob(filepath.Join(dpkg, "info", "*.md5sums"))
	for _, m := range sums {
		pkg := strings.TrimSuffix(filepath.Base(m), ".md5sums")
		short, _, _ := strings.Cut(pkg, ":")
		mf, err := os.Open(m)
		if err != nil {
			continue
		}
		s := bufio.NewScanner(mf)
		for s.Scan() {
			sum, path, ok := strings.Cut(s.Text(), "  ")
			if !ok || len(sum) != 32 {
				continue
			}
			h.Files[NormalizePath(path)] = HostFile{Package: short, Version: h.Packages[short], MD5: strings.ToLower(sum)}
		}
		mf.Close()
	}
	return h, nil
}

// ReadRPMDBHints reads an rpm sqlite database (rpmdb.sqlite, Fedora and Rocky
// 9) strictly read-only and immutable. Each row's blob is an rpm header.
func ReadRPMDBHints(dbPath string) (*HostHints, error) {
	u := url.URL{Scheme: "file", Path: dbPath, RawQuery: "mode=ro&immutable=1&_pragma=query_only(1)"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query("SELECT blob FROM Packages")
	if err != nil {
		return nil, fmt.Errorf("integrity: rpmdb: %w", err)
	}
	defer rows.Close()
	h := newHints()
	for rows.Next() {
		var blob []byte
		if err := rows.Scan(&blob); err != nil {
			return nil, err
		}
		hd, _, err := parseRPMHeaderBlob(blob)
		if err != nil {
			continue
		}
		name, ver, _ := hd.nevra()
		if name == "" {
			continue
		}
		h.Packages[name] = ver
		algo := uint64(1) // md5 default
		if a := hd.ints(tagFileDigestAlgo); len(a) == 1 {
			algo = a[0]
		}
		for _, f := range hd.files() {
			if f.Digest == "" || f.Mode&0o170000 != 0o100000 || f.Flags&rpmGhost != 0 {
				continue
			}
			hf := HostFile{Package: name, Version: ver}
			if algo == 8 {
				if _, err := hex.DecodeString(f.Digest); err == nil {
					hf.SHA256 = f.Digest
				}
			}
			h.Files[NormalizePath(f.Path)] = hf
		}
	}
	return h, rows.Err()
}
