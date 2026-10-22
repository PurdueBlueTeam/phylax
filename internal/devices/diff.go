package devices

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// DiffKind is how an entry changed.
type DiffKind string

const (
	Added   DiffKind = "added"
	Removed DiffKind = "removed"
	Changed DiffKind = "changed"
)

// DiffEntry is one changed path.
type DiffEntry struct {
	Path          string
	Kind          DiffKind
	Before, After string
}

// Diff is a structural difference between two snapshots.
type Diff struct{ Entries []DiffEntry }

// Empty reports no difference.
func (d Diff) Empty() bool { return len(d.Entries) == 0 }

// DiffMaps compares two flattened configurations (path -> value), sorted by path.
func DiffMaps(a, b map[string]string) Diff {
	var d Diff
	for p, av := range a {
		bv, ok := b[p]
		switch {
		case !ok:
			d.Entries = append(d.Entries, DiffEntry{Path: p, Kind: Removed, Before: av})
		case bv != av:
			d.Entries = append(d.Entries, DiffEntry{Path: p, Kind: Changed, Before: av, After: bv})
		}
	}
	for p, bv := range b {
		if _, ok := a[p]; !ok {
			d.Entries = append(d.Entries, DiffEntry{Path: p, Kind: Added, After: bv})
		}
	}
	sort.Slice(d.Entries, func(i, j int) bool { return d.Entries[i].Path < d.Entries[j].Path })
	return d
}

// HashBytes is the hex sha256 used for snapshots.
func HashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
