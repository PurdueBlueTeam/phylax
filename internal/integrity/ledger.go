// Package integrity implements the binary integrity ledger (design: "Binary
// integrity ledger"): reference hashes with provenance, pure-Go readers for the
// truth sources (.deb, .rpm, Winbindex, host package DBs as hints), the
// agent-side checker (exec-time hashing, loaded-library checks, service
// binary pinning, sweeps) and a scheduled YARA interface.
//
// Everything here is ALERT ONLY (D-1): nothing in this package modifies,
// quarantines or restores a file. Hashing uses native Go calls only, never host
// tools.
package integrity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Source says where a ledger entry came from, in order of trust.
type Source uint8

const (
	// SourceReference is a lab-built reference ledger (rank 1).
	SourceReference Source = 1
	// SourceVendorPackage is a hash extracted from a vendor .deb/.rpm or a
	// Winbindex list (rank 2/3).
	SourceVendorPackage Source = 2
	// SourceHostHint comes from the host's own package DB. It is a hint and
	// never proof: an attacker with root can edit it.
	SourceHostHint Source = 3
)

func (s Source) String() string {
	switch s {
	case SourceReference:
		return "reference"
	case SourceVendorPackage:
		return "vendor_package"
	case SourceHostHint:
		return "host_hint"
	}
	return fmt.Sprintf("source(%d)", uint8(s))
}

// Trusted reports whether the source may be used as proof of a good binary.
func (s Source) Trusted() bool { return s == SourceReference || s == SourceVendorPackage }

// Sum is a sha256 digest.
type Sum [sha256.Size]byte

func (s Sum) String() string { return hex.EncodeToString(s[:]) }

// ParseSum parses a 64-character hex sha256.
func ParseSum(h string) (Sum, error) {
	var s Sum
	b, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil || len(b) != len(s) {
		return s, fmt.Errorf("integrity: bad sha256 %q", h)
	}
	copy(s[:], b)
	return s, nil
}

// Entry is one expected file.
type Entry struct {
	Path    string // normalised, see NormalizePath
	SHA256  Sum
	Size    int64
	Mode    uint32 // unix permission bits plus setuid/setgid/sticky; 0 if unknown
	Package string // owning package, "" for Windows system files
	Version string // package or file version
	Signer  string // signer (Windows, or vendor key id), "" if none
	OS      string // e.g. "debian12", "rocky9", "win2022"
	Source  Source
}

// NormalizePath canonicalises a path for lookup. Unix paths are cleaned,
// made absolute and folded through the usr-merge symlinks (/bin -> /usr/bin,
// /sbin, /lib, /lib64), so that "/bin/ls" and "/usr/bin/ls" are one key.
// Windows paths (drive letter or backslashes) are lower-cased, the drive letter
// is dropped and separators become "/", so `C:\Windows\System32\DNS.exe`
// becomes "/windows/system32/dns.exe".
func NormalizePath(p string) string {
	if len(p) >= 2 && p[1] == ':' || strings.ContainsRune(p, '\\') {
		if len(p) >= 2 && p[1] == ':' {
			p = p[2:]
		}
		p = strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
		return cleanAbs(p)
	}
	p = strings.TrimSuffix(p, " (deleted)")
	p = cleanAbs(p)
	for _, d := range []string{"/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32"} {
		if p == d || strings.HasPrefix(p, d+"/") {
			return "/usr" + p
		}
	}
	return p
}

func cleanAbs(p string) string {
	p = strings.TrimPrefix(p, "./")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	// path.Clean without importing path for a tiny job would be silly; use it.
	return pathClean(p)
}

// Meta describes a ledger as a whole.
type Meta struct {
	Name    string `json:"name"`         // e.g. "debian12-reference"
	OS      string `json:"os,omitempty"` // e.g. "debian12"
	Release string `json:"release,omitempty"`
	Built   int64  `json:"built,omitempty"` // unix seconds
}

// Ledger is an in-memory index with lookup by path and by hash.
type Ledger struct {
	Meta   Meta
	byPath map[string][]int
	byHash map[Sum][]int
	ents   []Entry
	bad    map[Sum]string // known-bad hash -> label
}

// NewLedger returns an empty ledger.
func NewLedger(m Meta) *Ledger {
	return &Ledger{Meta: m, byPath: map[string][]int{}, byHash: map[Sum][]int{}, bad: map[Sum]string{}}
}

// Add inserts an entry (path normalised). An identical entry (same path, hash,
// package, version, source) is ignored. It returns true if the entry was new.
func (l *Ledger) Add(e Entry) bool {
	e.Path = NormalizePath(e.Path)
	for _, i := range l.byPath[e.Path] {
		o := l.ents[i]
		if o.SHA256 == e.SHA256 && o.Package == e.Package && o.Version == e.Version && o.Source == e.Source && o.OS == e.OS {
			return false
		}
	}
	l.ents = append(l.ents, e)
	i := len(l.ents) - 1
	l.byPath[e.Path] = append(l.byPath[e.Path], i)
	l.byHash[e.SHA256] = append(l.byHash[e.SHA256], i)
	return true
}

// AddAll adds every entry and returns how many were new.
func (l *Ledger) AddAll(es []Entry) int {
	n := 0
	for _, e := range es {
		if l.Add(e) {
			n++
		}
	}
	return n
}

// AddBad records a hash known to be malicious (for example a C2 implant or
// the red team's trojaned build seen at a previous event).
func (l *Ledger) AddBad(s Sum, label string) { l.bad[s] = label }

// Bad returns the label of a known-bad hash.
func (l *Ledger) Bad(s Sum) (string, bool) { v, ok := l.bad[s]; return v, ok }

// Len is the number of entries.
func (l *Ledger) Len() int { return len(l.ents) }

// ByPath returns the entries recorded for a path.
func (l *Ledger) ByPath(path string) []Entry {
	return l.pick(l.byPath[NormalizePath(path)])
}

// ByHash returns the entries whose hash equals s.
func (l *Ledger) ByHash(s Sum) []Entry { return l.pick(l.byHash[s]) }

func (l *Ledger) pick(ix []int) []Entry {
	if len(ix) == 0 {
		return nil
	}
	out := make([]Entry, len(ix))
	for i, j := range ix {
		out[i] = l.ents[j]
	}
	return out
}

// Entries returns all entries sorted by path, then hash.
func (l *Ledger) Entries() []Entry {
	out := append([]Entry(nil), l.ents...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		if c := bytes.Compare(out[i].SHA256[:], out[j].SHA256[:]); c != 0 {
			return c < 0
		}
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].Source < out[j].Source
	})
	return out
}

// Merge adds everything from o (entries and bad hashes) into l.
func (l *Ledger) Merge(o *Ledger) {
	for _, e := range o.ents {
		l.Add(e)
	}
	for s, v := range o.bad {
		l.bad[s] = v
	}
}

// Builder accumulates entries from several truth sources into a ledger.
type Builder struct{ l *Ledger }

// NewBuilder starts a ledger.
func NewBuilder(m Meta) *Builder { return &Builder{l: NewLedger(m)} }

// AddEntries adds entries as given.
func (b *Builder) AddEntries(es []Entry) *Builder { b.l.AddAll(es); return b }

// AddPackage adds the entries of a parsed package, stamping the OS and source.
func (b *Builder) AddPackage(p *Package, os string, src Source) *Builder {
	for _, e := range p.Entries {
		e.OS = os
		e.Source = src
		b.l.Add(e)
	}
	return b
}

// Ledger returns the built ledger.
func (b *Builder) Ledger() *Ledger { return b.l }
