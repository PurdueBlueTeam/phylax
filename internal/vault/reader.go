package vault

import "errors"

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
func Scoped(src Source, names []string) Reader { panic("unimplemented: W1 Task 9") }

// Covers reports whether a grant list covers name.
func Covers(grants []string, name string) bool { panic("unimplemented: W1 Task 9a") }
