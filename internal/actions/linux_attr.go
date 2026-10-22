package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

// file.attr sets and clears chattr-style inode flags (ext4/xfs/btrfs) through
// the FS_IOC_GETFLAGS/FS_IOC_SETFLAGS ioctls, never the chattr binary.

// Inode flag bits (linux/fs.h).
const (
	flagImmutable = 0x00000010 // i
	flagAppend    = 0x00000020 // a
	flagNoDump    = 0x00000040 // d
	flagNoAtime   = 0x00000080 // A
)

var attrLetters = map[byte]uint32{'i': flagImmutable, 'a': flagAppend, 'd': flagNoDump, 'A': flagNoAtime}

// AttrBackend reads and writes inode flags of a real path.
type AttrBackend interface {
	Get(path string) (uint32, error)
	Set(path string, flags uint32) error
}

const kindAttrUndo = "file.attr.undo"

type attrSnap struct {
	Path  string `json:"path"`
	Flags uint32 `json:"flags"`
}

func parseAttrFlags(s string) (uint32, error) {
	var f uint32
	for i := 0; i < len(s); i++ {
		b, ok := attrLetters[s[i]]
		if !ok {
			return 0, fmt.Errorf("unsupported attribute %q (allowed: i a d A)", s[i])
		}
		f |= b
	}
	return f, nil
}

type fileAttr struct{}

func (fileAttr) Spec() Spec {
	chk := func(v any) error { _, err := parseAttrFlags(v.(string)); return err }
	return Spec{Name: "file.attr", Risk: RiskService,
		Doc: "Set (add) and clear (remove) chattr flags i, a, d, A on a file or directory via ioctl. Refuses +i/+a on cache, log, upload and database paths and on scored content.",
		Params: []ParamSpec{pathParam,
			{Name: "add", Type: String, Max: 8, Check: chk},
			{Name: "remove", Type: String, Max: 8, Check: chk}}}
}

func (fileAttr) Locks(Params) []string    { return nil }
func (fileAttr) Touches(p Params) []Touch { return []Touch{pathTouch(p.Str("path"), OpModify)} }

// attrSensitive paths must stay writable for the application or the log
// pipeline; an immutable flag there causes outages.
var attrSensitive = []string{"/cache", "/storage", "/logs", "/log", "/var/lib/mysql", "/var/lib/mariadb",
	"/var/spool", "/var/lib/php", "/tmp", "/upload", "/uploads"}

func lintAttr(path string, add uint32) error {
	if add&(flagImmutable|flagAppend) == 0 {
		return nil
	}
	lp := strings.ToLower(path) + "/"
	for _, s := range attrSensitive {
		if strings.Contains(lp, s+"/") {
			return fmt.Errorf("%w: +i/+a on %s would block writes the application or logging needs", ErrScoringUnsafe, path)
		}
	}
	return nil
}

func (e *Env) attr() AttrBackend {
	if e.lx().Attr != nil {
		return e.lx().Attr
	}
	return realAttr{}
}

func (fileAttr) want(p Params) (add, rem uint32, err error) {
	if add, err = parseAttrFlags(p.Str("add")); err != nil {
		return
	}
	if rem, err = parseAttrFlags(p.Str("remove")); err != nil {
		return
	}
	if add&rem != 0 {
		err = errors.New("the same flag is in add and remove")
	}
	if add == 0 && rem == 0 {
		err = errors.New("one of add, remove is required")
	}
	return
}

func attrString(f uint32) string {
	var b strings.Builder
	for _, l := range "iadA" {
		if f&attrLetters[byte(l)] != 0 {
			b.WriteRune(l)
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

func (a fileAttr) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	add, rem, err := a.want(p)
	if err != nil {
		return Plan{}, err
	}
	if err := lintAttr(p.Str("path"), add); err != nil {
		return Plan{}, err
	}
	cur, err := env.attr().Get(env.Resolve(p.Str("path")))
	if err != nil {
		return Plan{}, err
	}
	next := (cur | add) &^ rem
	if next == cur {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: fmt.Sprintf("attributes %s -> %s", attrString(cur), attrString(next))}, nil
}

func (fileAttr) Capture(_ context.Context, env *Env, p Params) (Rollback, error) {
	path := env.Resolve(p.Str("path"))
	cur, err := env.attr().Get(path)
	if err != nil {
		return Rollback{}, err
	}
	return Rollback{Kind: kindAttrUndo, Data: attrSnap{Path: path, Flags: cur}}, nil
}

func undoAttr(_ context.Context, env *Env, e deadman.Entry) error {
	var s attrSnap
	if err := json.Unmarshal(e.Data, &s); err != nil {
		return err
	}
	return env.attr().Set(s.Path, s.Flags)
}

func (a fileAttr) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	add, rem, err := a.want(p)
	if err != nil {
		return nil, err
	}
	path := env.Resolve(p.Str("path"))
	cur, err := env.attr().Get(path)
	if err != nil {
		return nil, err
	}
	return nil, env.attr().Set(path, (cur|add)&^rem)
}

func (a fileAttr) Verify(_ context.Context, env *Env, p Params) error {
	add, rem, _ := a.want(p)
	cur, err := env.attr().Get(env.Resolve(p.Str("path")))
	if err != nil {
		return err
	}
	if cur&add != add || cur&rem != 0 {
		return fmt.Errorf("attributes are %s after set", attrString(cur))
	}
	return nil
}
