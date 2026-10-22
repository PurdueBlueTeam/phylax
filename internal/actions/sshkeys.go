package actions

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
)

type sshAuthorizedKeys struct{}

func (sshAuthorizedKeys) Spec() Spec {
	return Spec{Name: "ssh.authorized_keys", Risk: RiskLockout,
		Doc: "Manage a user's authorized_keys: mode set (exact list), add, or remove. Keys written carry the plan tag in their comment.",
		Params: []ParamSpec{
			{Name: "user", Type: String, Required: true, Check: validName},
			{Name: "keys", Type: StringList, Required: true, Max: 1000},
			{Name: "mode", Type: Enum, Enum: []string{"set", "add", "remove"}, Default: "set"},
			{Name: "path", Type: Path}}}
}
func (sshAuthorizedKeys) Locks(Params) []string { return []string{LockAccounts} }
func (sshAuthorizedKeys) Touches(p Params) []Touch {
	return []Touch{acctTouch(p.Str("user"), OpModify)}
}

type authKey struct {
	line string // full line as it will be written
	id   string // type + " " + blob
}

var keyTypes = []string{"ssh-rsa", "ssh-ed25519", "ssh-dss", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-"}

func isKeyType(s string) bool {
	for _, k := range keyTypes {
		if strings.HasPrefix(s, k) {
			return true
		}
	}
	return false
}

// splitFields splits on spaces/tabs outside double quotes.
func splitFields(s string) []string {
	var out []string
	var cur strings.Builder
	inQ, esc := false, false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\' && inQ:
			cur.WriteRune(r)
			esc = true
		case r == '"':
			inQ = !inQ
			cur.WriteRune(r)
		case (r == ' ' || r == '\t') && !inQ:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// parseKeyLine validates one authorized_keys line (options optional).
func parseKeyLine(line string) (authKey, error) {
	if strings.ContainsAny(line, "\n\r\x00") {
		return authKey{}, errors.New("key must be a single line")
	}
	f := splitFields(strings.TrimSpace(line))
	for i := 0; i < len(f)-1; i++ {
		if !isKeyType(f[i]) {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(f[i+1])
		if err != nil || len(blob) < 8 {
			return authKey{}, errors.New("invalid key: bad base64")
		}
		n := binary.BigEndian.Uint32(blob[:4])
		if int(n) > len(blob)-4 || string(blob[4:4+n]) != f[i] {
			return authKey{}, errors.New("invalid key: type does not match key blob")
		}
		return authKey{line: strings.Join(f, " "), id: f[i] + " " + f[i+1]}, nil
	}
	return authKey{}, errors.New("invalid key: no recognised key type")
}

func parseKeys(lines []string) ([]authKey, error) {
	var out []authKey
	for _, l := range lines {
		k, err := parseKeyLine(l)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

func (sshAuthorizedKeys) target(ctx context.Context, env *Env, p Params) (path string, uid, gid int, err error) {
	uid, gid = -1, -1
	if env.Accounts != nil {
		a, ok, lerr := env.Accounts.Lookup(ctx, p.Str("user"))
		if lerr != nil {
			return "", 0, 0, lerr
		}
		if ok {
			uid, gid = a.UID, a.GID
			if !p.Has("path") {
				return env.Resolve(filepath.Join(a.Home, ".ssh", "authorized_keys")), uid, gid, nil
			}
		}
	}
	if p.Has("path") {
		return env.Resolve(p.Str("path")), uid, gid, nil
	}
	return "", 0, 0, fmt.Errorf("no such user %q (or give path)", p.Str("user"))
}

func tagAuthKey(k authKey, tag Tag) authKey {
	if strings.Contains(k.line, "phylax") {
		return k
	}
	k.line += " " + tag.String()
	return k
}

// desired computes the new file content from the current content.
func (sshAuthorizedKeys) desired(ctx context.Context, p Params, cur string) (string, error) {
	keys, err := parseKeys(p.List("keys"))
	if err != nil {
		return "", err
	}
	tag := TagFrom(ctx)
	type kl struct {
		raw string
		id  string
		key bool
	}
	var existing []kl
	for _, l := range strings.Split(strings.TrimSuffix(cur, "\n"), "\n") {
		if cur == "" {
			break
		}
		if k, err := parseKeyLine(l); err == nil {
			existing = append(existing, kl{l, k.id, true})
		} else {
			existing = append(existing, kl{raw: l})
		}
	}
	has := map[string]bool{}
	for _, e := range existing {
		if e.key {
			has[e.id] = true
		}
	}
	var out []string
	switch p.Str("mode") {
	case "add":
		for _, e := range existing {
			out = append(out, e.raw)
		}
		for _, k := range keys {
			if !has[k.id] {
				out = append(out, tagAuthKey(k, tag).line)
				has[k.id] = true
			}
		}
	case "remove":
		rm := map[string]bool{}
		for _, k := range keys {
			rm[k.id] = true
		}
		for _, e := range existing {
			if !(e.key && rm[e.id]) {
				out = append(out, e.raw)
			}
		}
	default: // set
		if sameIDs(existing2ids(existing, func(e kl) (string, bool) { return e.id, e.key }), keys) {
			return cur, nil // same key set (any order): leave the file alone
		}
		keep := map[string]string{}
		for _, e := range existing {
			if e.key {
				if _, dup := keep[e.id]; !dup {
					keep[e.id] = e.raw
				}
			}
		}
		seen := map[string]bool{}
		for _, k := range keys {
			if seen[k.id] {
				continue
			}
			seen[k.id] = true
			if raw, ok := keep[k.id]; ok {
				out = append(out, raw)
			} else {
				out = append(out, tagAuthKey(k, tag).line)
			}
		}
	}
	if len(out) == 0 {
		return "", nil
	}
	return strings.Join(out, "\n") + "\n", nil
}

func (s sshAuthorizedKeys) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	path, _, _, err := s.target(ctx, env, p)
	if err != nil {
		return Plan{}, err
	}
	b, rerr := os.ReadFile(path)
	if rerr != nil && !os.IsNotExist(rerr) {
		return Plan{}, rerr
	}
	want, err := s.desired(ctx, p, string(b))
	if err != nil {
		return Plan{}, err
	}
	if want == string(b) {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: lineDiff(string(b), want)}, nil
}

func (s sshAuthorizedKeys) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	path, _, _, err := s.target(ctx, env, p)
	if err != nil {
		return Rollback{}, err
	}
	return snapshotRollback(path)
}

func (s sshAuthorizedKeys) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	path, uid, gid, err := s.target(ctx, env, p)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	_, derr := os.Stat(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if os.IsNotExist(derr) && uid >= 0 {
		if err := chownIfRoot(dir, uid, gid); err != nil {
			return nil, err
		}
	}
	err = atomicfile.Modify(path, 0o600, func(old []byte, exists bool) ([]byte, error) {
		want, err := s.desired(ctx, p, string(old))
		return []byte(want), err
	})
	if err != nil {
		return nil, err
	}
	if uid >= 0 {
		if st, serr := os.Stat(path); serr == nil {
			if u, g, ok := ownerOf(st); ok && (u != uid || g != gid) {
				return nil, chownIfRoot(path, uid, gid)
			}
		}
	}
	return nil, nil
}

// chownIfRoot changes ownership; unprivileged runs (tests) cannot chown to
// other users and are not an error.
func chownIfRoot(path string, uid, gid int) error {
	if err := os.Lchown(path, uid, gid); err != nil && os.Geteuid() == 0 {
		return err
	}
	return nil
}

func (s sshAuthorizedKeys) Verify(ctx context.Context, env *Env, p Params) error {
	path, _, _, err := s.target(ctx, env, p)
	if err != nil {
		return err
	}
	b, _ := os.ReadFile(path)
	want, err := s.desired(ctx, p, string(b))
	if err != nil {
		return err
	}
	if want != string(b) {
		return errors.New("authorized_keys differs after write")
	}
	return nil
}

func existing2ids[T any](l []T, f func(T) (string, bool)) map[string]bool {
	out := map[string]bool{}
	for _, e := range l {
		if id, ok := f(e); ok {
			out[id] = true
		}
	}
	return out
}

func sameIDs(have map[string]bool, want []authKey) bool {
	w := map[string]bool{}
	for _, k := range want {
		w[k.id] = true
	}
	if len(w) != len(have) {
		return false
	}
	for id := range w {
		if !have[id] {
			return false
		}
	}
	return true
}
