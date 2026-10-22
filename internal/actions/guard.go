package actions

import (
	"context"
	"fmt"
	"path"
	"strings"
)

// TouchKind says what kind of scorer-visible thing an action affects.
type TouchKind string

const (
	TouchAccount TouchKind = "account"
	TouchService TouchKind = "service"
	TouchPath    TouchKind = "path"
)

// Operations a Touch can carry.
const (
	OpModify          = "modify"
	OpLock            = "lock"
	OpDelete          = "delete"
	OpRename          = "rename"
	OpSetPassword     = "set_password"
	OpStop            = "stop"
	OpDisable         = "disable"
	OpMask            = "mask"
	OpRemoveFromGroup = "remove_from_group"
	OpQuarantine      = "quarantine"
)

// Touch is one scorer-visible property an action affects.
type Touch struct {
	Kind  TouchKind
	Name  string // account, service or path
	Op    string
	Group string // for OpRemoveFromGroup
	PCR   bool   // the change is part of a PCR transaction
}

// ScoringGuard decides whether a change may touch a scored property. The
// manifest scoring-safety lint will implement it; StaticGuard is the default.
type ScoringGuard interface {
	Allow(ctx context.Context, t Touch) error
}

// ErrScoringUnsafe is wrapped by every guard refusal.
var ErrScoringUnsafe = fmt.Errorf("actions: refused by scoring guard")

// StaticGuard is driven by lists of protected accounts, services, paths and
// access groups. Matching of accounts/services is case-insensitive (and
// ".service" is ignored); paths match by prefix on path boundaries.
type StaticGuard struct {
	Accounts []string // scored accounts: never locked, deleted, renamed; password only via PCR
	Services []string // scored services: never stopped, disabled or masked
	Paths    []string // scored content: never modified, moved or quarantined
	Groups   []string // access groups (e.g. "Remote Desktop Users"): protected accounts are never removed
}

func norm(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".service")) }

func in(list []string, s string) bool {
	for _, e := range list {
		if strings.EqualFold(norm(e), norm(s)) {
			return true
		}
	}
	return false
}

func (g StaticGuard) Allow(_ context.Context, t Touch) error {
	refuse := func(why string) error { return fmt.Errorf("%w: %s %q: %s", ErrScoringUnsafe, t.Op, t.Name, why) }
	switch t.Kind {
	case TouchAccount:
		if !in(g.Accounts, t.Name) {
			return nil
		}
		switch t.Op {
		case OpLock, OpDelete, OpRename:
			return refuse("scored account")
		case OpSetPassword:
			if !t.PCR {
				return refuse("scored passwords change only by PCR transaction")
			}
		case OpRemoveFromGroup:
			if in(g.Groups, t.Group) {
				return refuse("scored account would lose access group " + t.Group)
			}
		}
	case TouchService:
		if !in(g.Services, t.Name) {
			return nil
		}
		switch t.Op {
		case OpStop, OpDisable, OpMask:
			return refuse("scored service")
		}
	case TouchPath:
		p := path.Clean(strings.ReplaceAll(t.Name, "\\", "/"))
		for _, pp := range g.Paths {
			pp = path.Clean(strings.ReplaceAll(pp, "\\", "/"))
			if p == pp || strings.HasPrefix(p, strings.TrimSuffix(pp, "/")+"/") {
				return refuse("scored content")
			}
		}
	}
	return nil
}

// AllowAll is a guard that permits everything (tests, unmanaged hosts).
type AllowAll struct{}

func (AllowAll) Allow(context.Context, Touch) error { return nil }
