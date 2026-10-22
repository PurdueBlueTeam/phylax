// Package wazuh is a read-only client for the Wazuh manager API and indexer:
// health, version-pin enforcement and alert import. It never mutates Wazuh and
// nothing on Phylax's critical path depends on it.
package wazuh

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// MinVersion is the oldest permitted manager (CVE-2025-24016 and 2026 authd/API
// bugs are fixed in 4.14.9).
const MinVersion = "4.14.9"

// Version is a dotted numeric version.
type Version [3]int

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]) }

// Cmp returns -1, 0, 1.
func (v Version) Cmp(o Version) int {
	for i := range v {
		if v[i] != o[i] {
			if v[i] < o[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// ParseVersion accepts "4.14.9", "v4.14.9", "Wazuh v4.14.9" and "4.14.9-rc1" style strings.
func ParseVersion(s string) (Version, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "Wazuh")
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+ "); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return Version{}, fmt.Errorf("wazuh: bad version %q", s)
	}
	var v Version
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 100000 {
			return Version{}, fmt.Errorf("wazuh: bad version %q", s)
		}
		v[i] = n
	}
	return v, nil
}

// ErrVersionPin is returned when the pin policy is violated.
var ErrVersionPin = errors.New("wazuh: version pin violated")

// CheckManager refuses a manager older than min (default MinVersion).
func CheckManager(manager, min string) (Version, error) {
	if min == "" {
		min = MinVersion
	}
	mv, err := ParseVersion(manager)
	if err != nil {
		return mv, err
	}
	lo, err := ParseVersion(min)
	if err != nil {
		return mv, err
	}
	if mv.Cmp(lo) < 0 {
		return mv, fmt.Errorf("%w: manager %s < required %s", ErrVersionPin, mv, lo)
	}
	return mv, nil
}

// CheckAgents refuses any agent newer than the manager (Wazuh does not support
// it) and returns the offending agent names.
func CheckAgents(manager Version, agents []Agent) error {
	var bad []string
	for _, a := range agents {
		if a.Version == "" {
			continue
		}
		av, err := ParseVersion(a.Version)
		if err != nil {
			bad = append(bad, a.Name+"(unparseable "+a.Version+")")
			continue
		}
		if av.Cmp(manager) > 0 {
			bad = append(bad, fmt.Sprintf("%s(%s)", a.Name, av))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%w: agents newer than manager %s: %s", ErrVersionPin, manager, strings.Join(bad, ", "))
	}
	return nil
}
