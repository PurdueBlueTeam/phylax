package vault

import (
	"errors"
	"strings"
)

// Reader is a scoped view of the vault.
type Reader interface {
	Get(name string) (Secret, error)
}

// Source is a vault that also reports the version of a secret.
type Source interface {
	Get(name string) (Secret, string, error)
}

var ErrNotAllowed = errors.New("vault: secret not in scope")

// Scoped returns a reader limited to the granted names; an entry ending in
// "/*" grants every name with that prefix.
func Scoped(src Source, names []string) Reader {
	return scoped{src: src, granted: append([]string(nil), names...)}
}

type scoped struct {
	src     Source
	granted []string
}

// Get reads a granted secret; anything else is ErrNotAllowed before the vault
// is touched (so a locked vault cannot leak which names exist).
func (s scoped) Get(name string) (Secret, error) {
	if !Covers(s.granted, name) {
		return Secret{}, ErrNotAllowed
	}
	sec, _, err := s.src.Get(name)
	return sec, err
}

// Covers reports whether a grant list covers name. An entry ending in "/*"
// covers every name with that prefix (so "cred/*" covers "cred/h1/admin" but
// neither "cred" nor "credx/a"); every other entry is an exact name.
func Covers(grants []string, name string) bool {
	for _, g := range grants {
		if prefix, ok := strings.CutSuffix(g, "*"); ok && strings.HasSuffix(prefix, "/") {
			// A grant "cred/*" has prefix "cred/", so the separator is
			// required and the bare prefix is not covered.
			if strings.HasPrefix(name, prefix) {
				return true
			}
			continue
		}
		if g == name {
			return true
		}
	}
	return false
}
