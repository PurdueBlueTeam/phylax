package actions

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
)

// FileAccounts implements AccountBackend by editing passwd, shadow, group and
// gshadow under Root. Every other field and line is preserved byte for byte
// (aging fields, comments, NIS markers); writes are atomic and keep owner,
// mode and SELinux label (internal/atomicfile); edits run under the
// shadow-utils lock plus an in-process mutex.
type FileAccounts struct {
	Root string
	Now  func() time.Time
}

var rootMu sync.Map // root -> *sync.Mutex

func (a *FileAccounts) p(name string) string {
	root := a.Root
	if root == "" {
		root = "/"
	}
	return filepath.Join(root, "etc", name)
}

func (a *FileAccounts) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *FileAccounts) lock(ctx context.Context) (func(), error) {
	m, _ := rootMu.LoadOrStore(a.p(""), &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	rel, err := lockFileCross(ctx, a.p(".pwd.lock"))
	if err != nil {
		mu.Unlock()
		return nil, fmt.Errorf("account database lock: %w", err)
	}
	return func() { rel(); mu.Unlock() }, nil
}

// ---- colon-database model ----

type dbLine struct {
	raw   string
	f     []string // nil for blank/comment lines
	dirty bool
}

type db struct {
	lines   []*dbLine
	finalNL bool
}

func parseDB(b []byte) *db {
	d := &db{finalNL: len(b) == 0 || b[len(b)-1] == '\n'}
	s := strings.TrimSuffix(string(b), "\n")
	if len(b) == 0 {
		return d
	}
	for _, l := range strings.Split(s, "\n") {
		dl := &dbLine{raw: l}
		if strings.TrimSpace(l) != "" && !strings.HasPrefix(l, "#") {
			dl.f = strings.Split(l, ":")
		}
		d.lines = append(d.lines, dl)
	}
	return d
}

func (d *db) bytes() []byte {
	var sb strings.Builder
	for i, l := range d.lines {
		if i > 0 {
			sb.WriteByte('\n')
		}
		if l.dirty {
			sb.WriteString(strings.Join(l.f, ":"))
		} else {
			sb.WriteString(l.raw)
		}
	}
	if len(d.lines) > 0 && d.finalNL {
		sb.WriteByte('\n')
	}
	return []byte(sb.String())
}

func (d *db) find(name string) *dbLine {
	for _, l := range d.lines {
		if l.f != nil && l.f[0] == name {
			return l
		}
	}
	return nil
}

func (d *db) add(fields ...string) {
	if len(d.lines) > 0 && !d.finalNL {
		d.finalNL = true
	}
	d.lines = append(d.lines, &dbLine{f: fields, dirty: true})
	d.finalNL = true
}

func (d *db) remove(name string) bool {
	for i, l := range d.lines {
		if l.f != nil && l.f[0] == name {
			d.lines = append(d.lines[:i], d.lines[i+1:]...)
			return true
		}
	}
	return false
}

func (l *dbLine) set(i int, v string) {
	for len(l.f) <= i {
		l.f = append(l.f, "")
	}
	if l.f[i] != v {
		l.f[i] = v
		l.dirty = true
	}
}

func (l *dbLine) get(i int) string {
	if i < len(l.f) {
		return l.f[i]
	}
	return ""
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func removeFrom(list []string, name string) ([]string, bool) {
	var out []string
	hit := false
	for _, m := range list {
		if m == name {
			hit = true
			continue
		}
		out = append(out, m)
	}
	return out, hit
}

func (a *FileAccounts) load(name string, required bool) (*db, bool, error) {
	b, err := os.ReadFile(a.p(name))
	if errors.Is(err, fs.ErrNotExist) && !required {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return parseDB(b), true, nil
}

// edit loads the named files (shadow-utils lock must be held), lets fn mutate
// the parsed models, then writes the changed files atomically. If a later
// write fails the earlier ones are put back.
func (a *FileAccounts) edit(names []string, optional map[string]bool, fn func(m map[string]*db) error) error {
	m := map[string]*db{}
	orig := map[string][]byte{}
	for _, n := range names {
		b, err := os.ReadFile(a.p(n))
		if errors.Is(err, fs.ErrNotExist) && optional[n] {
			continue
		}
		if err != nil {
			return err
		}
		orig[n] = b
		m[n] = parseDB(b)
	}
	if err := fn(m); err != nil {
		return err
	}
	var written []string
	for _, n := range names {
		d := m[n]
		if d == nil {
			continue
		}
		nb := d.bytes()
		if string(nb) == string(orig[n]) {
			continue
		}
		if err := atomicfile.WriteFile(a.p(n), nb, 0o644); err != nil {
			errs := []error{fmt.Errorf("write %s: %w", n, err)}
			for _, w := range written {
				if rerr := atomicfile.WriteFile(a.p(w), orig[w], 0o644); rerr != nil {
					errs = append(errs, fmt.Errorf("undo %s: %w", w, rerr))
				}
			}
			return errors.Join(errs...)
		}
		written = append(written, n)
	}
	return nil
}

// ---- AccountBackend ----

func (a *FileAccounts) Lookup(_ context.Context, name string) (Account, bool, error) {
	pw, _, err := a.load("passwd", true)
	if err != nil {
		return Account{}, false, err
	}
	l := pw.find(name)
	if l == nil || len(l.f) < 7 {
		return Account{}, false, nil
	}
	acct := Account{Name: name, Home: l.f[5], Shell: l.f[6]}
	acct.UID, _ = strconv.Atoi(l.f[2])
	acct.GID, _ = strconv.Atoi(l.f[3])
	sh, ok, err := a.load("shadow", false)
	if err != nil {
		return Account{}, false, err
	}
	if ok {
		if sl := sh.find(name); sl != nil {
			h := sl.get(1)
			acct.Locked = strings.HasPrefix(h, "!") || h == "*"
		}
	}
	return acct, true, nil
}

func (a *FileAccounts) shadowHash(name string) (string, bool, error) {
	sh, ok, err := a.load("shadow", false)
	if err != nil || !ok {
		return "", false, err
	}
	l := sh.find(name)
	if l == nil {
		return "", false, nil
	}
	return l.get(1), true, nil
}

func (a *FileAccounts) PasswordIs(_ context.Context, name, plain string) (bool, error) {
	h, ok, err := a.shadowHash(name)
	if err != nil || !ok {
		return false, err
	}
	match, err := CheckPassword(h, plain)
	if err != nil {
		return false, nil // other scheme or locked: not equal to what we would set
	}
	return match, nil
}

func (a *FileAccounts) days() string { return strconv.FormatInt(a.now().Unix()/86400, 10) }

func validHash(h string) error {
	if h == "" || strings.ContainsAny(h, ":\n\r") {
		return errors.New("invalid password hash")
	}
	return nil
}

func (a *FileAccounts) SetPassword(ctx context.Context, name, plain, hash string, mustChange bool) error {
	if hash == "" {
		var err error
		if hash, err = HashPassword(plain); err != nil {
			return err
		}
	}
	if err := validHash(hash); err != nil {
		return err
	}
	rel, err := a.lock(ctx)
	if err != nil {
		return err
	}
	defer rel()
	return a.edit([]string{"passwd", "shadow"}, nil, func(m map[string]*db) error {
		if m["passwd"].find(name) == nil {
			return fmt.Errorf("no such user %q", name)
		}
		lc := a.days()
		if mustChange {
			lc = "0"
		}
		if l := m["shadow"].find(name); l != nil {
			l.set(1, hash)
			l.set(2, lc) // passwd(1) also resets only the last-change date; min/max/warn/inactive/expire untouched
		} else {
			m["shadow"].add(name, hash, lc, "0", "99999", "7", "", "", "")
		}
		return nil
	})
}

func (a *FileAccounts) SetLocked(ctx context.Context, name string, locked bool) error {
	rel, err := a.lock(ctx)
	if err != nil {
		return err
	}
	defer rel()
	return a.edit([]string{"passwd", "shadow"}, nil, func(m map[string]*db) error {
		if m["passwd"].find(name) == nil {
			return fmt.Errorf("no such user %q", name)
		}
		l := m["shadow"].find(name)
		if l == nil {
			if !locked {
				return nil
			}
			m["shadow"].add(name, "!", a.days(), "0", "99999", "7", "", "", "")
			return nil
		}
		h := l.get(1)
		isLocked := strings.HasPrefix(h, "!") || h == "*"
		switch {
		case locked && !isLocked:
			l.set(1, "!"+h)
		case !locked && isLocked:
			if !strings.HasPrefix(h, "!") {
				return errors.New("account has no usable password (*); cannot unlock")
			}
			nh := h[1:]
			if nh == "" || strings.HasPrefix(nh, "!") || nh == "*" {
				return errors.New("unlocking would leave no usable password")
			}
			l.set(1, nh)
		}
		return nil
	})
}

func idsIn(d *db, idx int) map[int]bool {
	out := map[int]bool{}
	for _, l := range d.lines {
		if l.f != nil && len(l.f) > idx {
			if n, err := strconv.Atoi(l.f[idx]); err == nil {
				out[n] = true
			}
		}
	}
	return out
}

func allocID(used map[int]bool, system bool) (int, error) {
	if system {
		for id := 999; id >= 100; id-- {
			if !used[id] {
				return id, nil
			}
		}
		return 0, errors.New("no free system id")
	}
	ids := make([]int, 0, len(used))
	for id := range used {
		if id >= 1000 && id < 60000 {
			ids = append(ids, id)
		}
	}
	sort.Ints(ids)
	next := 1000
	if len(ids) > 0 {
		next = ids[len(ids)-1] + 1
	}
	if next >= 60000 {
		for id := 1000; id < 60000; id++ {
			if !used[id] {
				return id, nil
			}
		}
		return 0, errors.New("no free id")
	}
	return next, nil
}

func (a *FileAccounts) Create(ctx context.Context, c CreateSpec) error {
	rel, err := a.lock(ctx)
	if err != nil {
		return err
	}
	defer rel()
	home, shell := c.Home, c.Shell
	if home == "" {
		home = "/home/" + c.Name
		if c.System {
			home = "/"
		}
	}
	if shell == "" {
		shell = "/bin/bash"
		if c.System {
			shell = "/usr/sbin/nologin"
		}
	}
	hash := c.Hash
	if hash == "" && c.Password != "" {
		if hash, err = HashPassword(c.Password); err != nil {
			return err
		}
	}
	if hash == "" {
		hash = "!"
	} else if err := validHash(hash); err != nil {
		return err
	}
	var uid, gid int
	err = a.edit([]string{"passwd", "shadow", "group", "gshadow"}, map[string]bool{"gshadow": true}, func(m map[string]*db) error {
		if m["passwd"].find(c.Name) != nil {
			return fmt.Errorf("user %q exists", c.Name)
		}
		uid = c.UID
		usedU, usedG := idsIn(m["passwd"], 2), idsIn(m["group"], 2)
		if uid < 0 {
			var err error
			if uid, err = allocID(usedU, c.System); err != nil {
				return err
			}
		} else if usedU[uid] {
			return fmt.Errorf("uid %d in use", uid)
		}
		gid = c.GID
		if gid < 0 {
			if m["group"].find(c.Name) != nil {
				return fmt.Errorf("group %q exists; pass gid", c.Name)
			}
			gid = uid
			if usedG[gid] {
				var err error
				if gid, err = allocID(usedG, c.System); err != nil {
					return err
				}
			}
			m["group"].add(c.Name, "x", strconv.Itoa(gid), "")
			if m["gshadow"] != nil {
				m["gshadow"].add(c.Name, "!", "", "")
			}
		} else if !usedG[gid] {
			return fmt.Errorf("gid %d does not exist", gid)
		}
		m["passwd"].add(c.Name, "x", strconv.Itoa(uid), strconv.Itoa(gid), c.Comment, home, shell)
		m["shadow"].add(c.Name, hash, a.days(), "0", "99999", "7", "", "", "")
		return nil
	})
	if err != nil {
		return err
	}
	if c.CreateHome {
		hd := a.homePath(home)
		if err := os.MkdirAll(hd, 0o700); err != nil {
			return err
		}
		if err := chownIfRoot(hd, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func (a *FileAccounts) homePath(home string) string {
	root := a.Root
	if root == "" {
		root = "/"
	}
	return filepath.Join(root, filepath.Clean("/"+home))
}

func (a *FileAccounts) Delete(ctx context.Context, name string) error {
	rel, err := a.lock(ctx)
	if err != nil {
		return err
	}
	defer rel()
	return a.edit([]string{"passwd", "shadow", "group", "gshadow"}, map[string]bool{"gshadow": true}, func(m map[string]*db) error {
		pl := m["passwd"].find(name)
		if pl == nil {
			return nil
		}
		pgid := pl.get(3)
		m["passwd"].remove(name)
		m["shadow"].remove(name)
		for _, gn := range []string{"group", "gshadow"} {
			if m[gn] == nil {
				continue
			}
			for _, l := range m[gn].lines {
				if l.f == nil {
					continue
				}
				for _, idx := range []int{2, 3} {
					if gn == "group" && idx == 2 {
						continue // gid
					}
					list, hit := removeFrom(splitList(l.get(idx)), name)
					if hit {
						l.set(idx, strings.Join(list, ","))
					}
				}
			}
		}
		// Drop the private group when nothing else uses it.
		if gl := m["group"].find(name); gl != nil && gl.get(2) == pgid && gl.get(3) == "" {
			inUse := false
			for _, l := range m["passwd"].lines {
				if l.f != nil && l.get(3) == pgid {
					inUse = true
				}
			}
			if !inUse {
				m["group"].remove(name)
				if m["gshadow"] != nil {
					m["gshadow"].remove(name)
				}
			}
		}
		return nil
	})
}

func (a *FileAccounts) Members(_ context.Context, group string) ([]string, bool, error) {
	g, _, err := a.load("group", true)
	if err != nil {
		return nil, false, err
	}
	l := g.find(group)
	if l == nil {
		return nil, false, nil
	}
	return splitList(l.get(3)), true, nil
}

func (a *FileAccounts) SetMembers(ctx context.Context, group string, add, remove []string) error {
	rel, err := a.lock(ctx)
	if err != nil {
		return err
	}
	defer rel()
	return a.edit([]string{"group", "gshadow"}, map[string]bool{"gshadow": true}, func(m map[string]*db) error {
		if m["group"].find(group) == nil {
			return fmt.Errorf("no such group %q", group)
		}
		for _, gn := range []string{"group", "gshadow"} {
			if m[gn] == nil {
				continue
			}
			l := m[gn].find(group)
			if l == nil {
				continue
			}
			list := splitList(l.get(3))
			for _, r := range remove {
				list, _ = removeFrom(list, r)
				if gn == "gshadow" {
					adm, hit := removeFrom(splitList(l.get(2)), r)
					if hit {
						l.set(2, strings.Join(adm, ","))
					}
				}
			}
			for _, ad := range add {
				if !contains(list, ad) {
					list = append(list, ad)
				}
			}
			l.set(3, strings.Join(list, ","))
		}
		return nil
	})
}

func contains(l []string, s string) bool {
	for _, e := range l {
		if e == s {
			return true
		}
	}
	return false
}

func (a *FileAccounts) Snapshot(context.Context) (Rollback, error) {
	return snapshotRollback(a.p("passwd"), a.p("shadow"), a.p("group"), a.p("gshadow"))
}
