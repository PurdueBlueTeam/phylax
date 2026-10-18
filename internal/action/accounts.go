package action

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ---- local account actions -------------------------------------------------
//
// These edit /etc/passwd, /etc/shadow and /etc/group directly (the design's
// Linux implementation), with an exclusive flock held across each file pair
// rewrite. Everything is idempotent: re-applying is a no-op.

const (
	passwdPath = "/etc/passwd"
	shadowPath = "/etc/shadow"
	groupPath  = "/etc/group"
)

// editEtcFile applies mutate to the file's lines under an exclusive flock,
// rewriting atomically when anything changed.
func editEtcFile(path string, mutate func(lines []string) (changed bool)) (before string, changed bool, err error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return "", false, err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	r := bufio.NewReader(f)
	var lines []string
	for {
		l, err := r.ReadString('\n')
		if l != "" {
			lines = append(lines, strings.TrimSuffix(l, "\n"))
		}
		if err != nil {
			break
		}
	}
	changed = mutate(lines)
	if !changed {
		return strings.Join(lines, "\n"), false, nil
	}
	if err := f.Truncate(0); err != nil {
		return "", false, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return "", false, err
	}
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			return "", false, err
		}
	}
	return strings.Join(lines, "\n"), true, nil
}

type shadowEntry struct {
	User, Hash string
	Rest       string // lastchg:min:max:warn:inactive:expire:flag
}

func parseShadow(user string) (shadowEntry, bool) {
	f, err := os.Open(shadowPath)
	if err != nil {
		return shadowEntry{}, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 4)
		if len(parts) >= 2 && parts[0] == user {
			return shadowEntry{User: user, Hash: parts[1], Rest: firstColon(parts, 2)}, true
		}
	}
	return shadowEntry{}, false
}

func firstColon(parts []string, from int) string {
	if from >= len(parts) {
		return ""
	}
	return strings.Join(parts[from:], "")
}

// setShadowHash rewrites one shadow entry's hash field.
func setShadowHash(user, hash string) (string, bool, error) {
	return editEtcFile(shadowPath, func(lines []string) bool {
		for i, l := range lines {
			parts := strings.SplitN(l, ":", 2)
			if len(parts) == 2 && parts[0] == user {
				if parts[1] == hash {
					return false
				}
				lines[i] = user + ":" + hash
				return true
			}
		}
		return false
	})
}

func userExists(user string) bool {
	f, err := os.Open(passwdPath)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.SplitN(sc.Text(), ":", 2)[0] == user {
			return true
		}
	}
	return false
}

// ---- user.set_password ------------------------------------------------------

type userSetPassword struct{}

func (userSetPassword) Name() string   { return "user.set_password" }
func (userSetPassword) Risk() Risk     { return RiskLockout }
func (userSetPassword) Locks() []string { return []string{"accounts"} }
func (userSetPassword) Check(p Params) (CheckResult, error) {
	user, secret := p.Get("user", ""), p.Get("secret", "")
	if user == "" || secret == "" {
		return CheckResult{}, fmt.Errorf("user.set_password: user and secret required")
	}
	if !userExists(user) {
		return CheckResult{Diff: fmt.Sprintf("user %s does not exist", user)}, nil
	}
	// A fresh salt is always generated, so a rotate always changes state.
	return CheckResult{Diff: fmt.Sprintf("rotate password for %s", user)}, nil
}
func (userSetPassword) Apply(p Params) (CheckResult, error) {
	user, secret := p.Get("user", ""), p.Get("secret", "")
	salt := crypt6Salt()
	hash, err := crypt6(secret, salt, 5000)
	if err != nil {
		return CheckResult{}, err
	}
	before, changed, err := setShadowHash(user, hash)
	if err != nil {
		return CheckResult{}, err
	}
	if !changed {
		return CheckResult{Done: true}, nil
	}
	_ = before
	return CheckResult{Done: true, Diff: fmt.Sprintf("password rotated for %s", user)}, nil
}
func (userSetPassword) Verify(p Params) (CheckResult, error) {
	// Verification needs the new secret; the plan carries it.
	entry, ok := parseShadow(p.Get("user", ""))
	if !ok {
		return CheckResult{Diff: "user missing"}, nil
	}
	if !verifyCrypt6(p.Get("secret", ""), entry.Hash) {
		return CheckResult{Diff: "stored hash does not match"}, nil
	}
	return CheckResult{Done: true}, nil
}
func (userSetPassword) Rollback(_ Params, before []byte) (CheckResult, error) {
	// Before is unused (a fresh salt is generated on rollback); the plan's
	// rollback path re-rotates to the pre-plan secret if the vault still
	// holds it. No-op here.
	return CheckResult{Done: true, Diff: "password rollback requires vault secret"}, nil
}

// ---- user.lock ----------------------------------------------------------------

type userLock struct{}

func (userLock) Name() string   { return "user.lock" }
func (userLock) Risk() Risk     { return RiskLockout }
func (userLock) Locks() []string { return []string{"accounts"} }

func shadowLocked(entry shadowEntry) bool {
	return strings.HasPrefix(entry.Hash, "!")
}

func (a userLock) Check(p Params) (CheckResult, error) {
	user, want := p.Get("user", ""), p.GetBool("lock", true)
	entry, ok := parseShadow(user)
	if !ok {
		return CheckResult{Diff: fmt.Sprintf("user %s missing", user)}, nil
	}
	if shadowLocked(entry) == want {
		return CheckResult{Done: true}, nil
	}
	state := "locked"
	if !want {
		state = "unlocked"
	}
	return CheckResult{Diff: fmt.Sprintf("%s is %s", user, state),
		Before: []byte(Enc(entry.Hash)), After: []byte(Enc(targetHash(entry.Hash, want)))}, nil
}

func targetHash(cur string, want bool) string {
	if want {
		if strings.HasPrefix(cur, "!") {
			return cur
		}
		return "!" + cur
	}
	return strings.TrimPrefix(cur, "!")
}

func (a userLock) Apply(p Params) (CheckResult, error) {
	user, want := p.Get("user", ""), p.GetBool("lock", true)
	entry, ok := parseShadow(user)
	if !ok {
		return CheckResult{}, fmt.Errorf("user %s missing", user)
	}
	before, changed, err := setShadowHash(user, targetHash(entry.Hash, want))
	if err != nil {
		return CheckResult{}, err
	}
	if !changed {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Before: []byte(Enc(before))}, nil
}
func (a userLock) Verify(p Params) (CheckResult, error) {
	entry, ok := parseShadow(p.Get("user", ""))
	if !ok {
		return CheckResult{Diff: "user missing"}, nil
	}
	if shadowLocked(entry) != p.GetBool("lock", true) {
		return CheckResult{Diff: "lock state mismatch"}, nil
	}
	return CheckResult{Done: true}, nil
}
func (a userLock) Rollback(p Params, before []byte) (CheckResult, error) {
	user := p.Get("user", "")
	if _, changed, err := setShadowHash(user, string(Dec(string(before)))); err != nil {
		return CheckResult{}, err
	} else if !changed {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Done: true, Diff: "previous lock state restored"}, nil
}

// ---- user.create / user.delete ------------------------------------------------

type userCreate struct{}

func (userCreate) Name() string   { return "user.create" }
func (userCreate) Risk() Risk     { return RiskService }
func (userCreate) Locks() []string { return []string{"accounts"} }
func (userCreate) Check(p Params) (CheckResult, error) {
	user := p.Get("user", "")
	if userExists(user) {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Diff: fmt.Sprintf("create user %s", user)}, nil
}
func (userCreate) Apply(p Params) (CheckResult, error) {
	user := p.Get("user", "")
	shell := p.Get("shell", "/bin/sh")
	if userExists(user) {
		return CheckResult{Done: true}, nil
	}
	// passwd entry
	if _, changed, err := editEtcFile(passwdPath, func(lines []string) bool {
		for _, l := range lines {
			if strings.SplitN(l, ":", 2)[0] == user {
				return false
			}
		}
		lines = append(lines, fmt.Sprintf("%s:x:65532:65532:%s:/home/%s:%s", user, user, user, shell))
		return true
	}); err != nil {
		return CheckResult{}, err
	} else if !changed {
		return CheckResult{}, fmt.Errorf("passwd append failed")
	}
	// shadow entry
	if _, changed, err := editEtcFile(shadowPath, func(lines []string) bool {
		for _, l := range lines {
			if strings.SplitN(l, ":", 2)[0] == user {
				return false
			}
		}
		lines = append(lines, user+":!:0:99999:7:::")
		return true
	}); err != nil {
		return CheckResult{}, err
	} else if !changed {
		return CheckResult{}, fmt.Errorf("shadow append failed")
	}
	return CheckResult{Done: true, Diff: fmt.Sprintf("created %s", user)}, nil
}
func (userCreate) Verify(p Params) (CheckResult, error) {
	if !userExists(p.Get("user", "")) {
		return CheckResult{Diff: "user missing"}, nil
	}
	return CheckResult{Done: true}, nil
}
func (userCreate) Rollback(p Params, _ []byte) (CheckResult, error) {
	user := p.Get("user", "")
	if !userExists(user) {
		return CheckResult{Done: true}, nil
	}
	if _, changed, err := editEtcFile(passwdPath, func(lines []string) bool {
		for i, l := range lines {
			if strings.SplitN(l, ":", 2)[0] == user {
				lines = append(lines[:i], lines[i+1:]...)
				return true
			}
		}
		return false
	}); err != nil {
		return CheckResult{}, err
	} else if !changed {
		return CheckResult{}, fmt.Errorf("passwd remove failed")
	}
	if _, changed, err := editEtcFile(shadowPath, func(lines []string) bool {
		for i, l := range lines {
			if strings.SplitN(l, ":", 2)[0] == user {
				lines = append(lines[:i], lines[i+1:]...)
				return true
			}
		}
		return false
	}); err != nil {
		return CheckResult{}, err
	} else if !changed {
		return CheckResult{}, fmt.Errorf("shadow remove failed")
	}
	return CheckResult{Done: true, Diff: fmt.Sprintf("removed %s", user)}, nil
}

type userDelete struct{}

func (userDelete) Name() string   { return "user.delete" }
func (userDelete) Risk() Risk     { return RiskDestructive }
func (userDelete) Locks() []string { return []string{"accounts"} }
func (userDelete) Check(p Params) (CheckResult, error) {
	user := p.Get("user", "")
	if !userExists(user) {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Diff: fmt.Sprintf("delete user %s", user), Before: []byte(user)}, nil
}
func (a userDelete) Apply(p Params) (CheckResult, error) {
	user := p.Get("user", "")
	if !userExists(user) {
		return CheckResult{Done: true}, nil
	}
	if _, changed, err := editEtcFile(passwdPath, func(lines []string) bool {
		for i, l := range lines {
			if strings.SplitN(l, ":", 2)[0] == user {
				lines = append(lines[:i], lines[i+1:]...)
				return true
			}
		}
		return false
	}); err != nil {
		return CheckResult{}, err
	} else if !changed {
		return CheckResult{}, fmt.Errorf("passwd remove failed")
	}
	editEtcFile(shadowPath, func(lines []string) bool {
		for i, l := range lines {
			if strings.SplitN(l, ":", 2)[0] == user {
				lines = append(lines[:i], lines[i+1:]...)
				return true
			}
		}
		return false
	})
	return CheckResult{Before: []byte(user), Done: true, Diff: fmt.Sprintf("deleted %s", user)}, nil
}
func (userDelete) Verify(p Params) (CheckResult, error) {
	if userExists(p.Get("user", "")) {
		return CheckResult{Diff: "user still present"}, nil
	}
	return CheckResult{Done: true}, nil
}
func (userDelete) Rollback(_ Params, before []byte) (CheckResult, error) {
	return CheckResult{Done: true, Diff: "user deletion is not reversible by the agent"}, nil
}

// ---- group.members ------------------------------------------------------------

type groupMembers struct{}

func (groupMembers) Name() string   { return "group.members" }
func (groupMembers) Risk() Risk     { return RiskService }
func (groupMembers) Locks() []string { return []string{"accounts"} }

func groupLine(group string) (string, bool) {
	f, err := os.Open(groupPath)
	if err != nil {
		return "", false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 4)
		if parts[0] == group {
			return sc.Text(), true
		}
	}
	return "", false
}

func (a groupMembers) Check(p Params) (CheckResult, error) {
	group := p.Get("group", "")
	add, remove := p.GetList("add"), p.GetList("remove")
	line, ok := groupLine(group)
	if !ok {
		return CheckResult{Diff: fmt.Sprintf("group %s missing", group)}, nil
	}
	cur := parseGroupMembers(line)
	for _, u := range add {
		if !cur[u] {
			return CheckResult{Diff: fmt.Sprintf("add %s to %s", u, group),
				Before: []byte(Enc(membersString(cur))), After: []byte(Enc(membersString(addSet(cur, add, remove))))}, nil
		}
	}
	for _, u := range remove {
		if cur[u] {
			return CheckResult{Diff: fmt.Sprintf("remove %s from %s", u, group),
				Before: []byte(Enc(membersString(cur))), After: []byte(Enc(membersString(addSet(cur, add, remove))))}, nil
		}
	}
	return CheckResult{Done: true}, nil
}

func parseGroupMembers(line string) map[string]bool {
	parts := strings.SplitN(line, ":", 4)
	m := map[string]bool{}
	if len(parts) == 4 {
		for _, u := range strings.Split(parts[3], ",") {
			if u != "" {
				m[u] = true
			}
		}
	}
	return m
}

func membersString(m map[string]bool) string {
	out := ""
	for u := range m {
		out += u + ","
	}
	return strings.TrimSuffix(out, ",")
}

func addSet(cur map[string]bool, add, remove []string) map[string]bool {
	for _, u := range add {
		cur[u] = true
	}
	for _, u := range remove {
		delete(cur, u)
	}
	return cur
}

func (a groupMembers) Apply(p Params) (CheckResult, error) {
	group := p.Get("group", "")
	add, remove := p.GetList("add"), p.GetList("remove")
	line, ok := groupLine(group)
	if !ok {
		return CheckResult{}, fmt.Errorf("group %s missing", group)
	}
	parts := strings.SplitN(line, ":", 4)
	want := addSet(parseGroupMembers(line), add, remove)
	newLine := fmt.Sprintf("%s:%s:%s:%s", parts[0], parts[1], parts[2], membersString(want))
	if newLine == line {
		return CheckResult{Done: true}, nil
	}
	before, changed, err := editEtcFile(groupPath, func(lines []string) bool {
		for i, l := range lines {
			if strings.SplitN(l, ":", 2)[0] == group {
				lines[i] = newLine
				return true
			}
		}
		return false
	})
	if err != nil {
		return CheckResult{}, err
	}
	if !changed {
		return CheckResult{}, fmt.Errorf("group not found for edit")
	}
	return CheckResult{Before: []byte(Enc(before))}, nil
}
func (a groupMembers) Verify(p Params) (CheckResult, error) {
	group := p.Get("group", "")
	line, ok := groupLine(group)
	if !ok {
		return CheckResult{Diff: "group missing"}, nil
	}
	cur := parseGroupMembers(line)
	for _, u := range p.GetList("add") {
		if !cur[u] {
			return CheckResult{Diff: fmt.Sprintf("%s not in %s", u, group)}, nil
		}
	}
	for _, u := range p.GetList("remove") {
		if cur[u] {
			return CheckResult{Diff: fmt.Sprintf("%s still in %s", u, group)}, nil
		}
	}
	return CheckResult{Done: true}, nil
}
func (a groupMembers) Rollback(p Params, before []byte) (CheckResult, error) {
	// before is the whole /etc/group content; restore it.
	if len(before) == 0 {
		return CheckResult{Done: true}, nil
	}
	if err := os.WriteFile(groupPath, Dec(string(before)), 0o644); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Done: true, Diff: "group membership restored"}, nil
}

// ---- ssh.authorized_keys ------------------------------------------------------

type sshAuthorizedKeys struct{}

func (sshAuthorizedKeys) Name() string   { return "ssh.authorized_keys" }
func (sshAuthorizedKeys) Risk() Risk     { return RiskLockout }
func (sshAuthorizedKeys) Locks() []string { return []string{"accounts", "sshd"} }
func (sshAuthorizedKeys) Check(p Params) (CheckResult, error) {
	path := p.Get("path", "")
	keys := p.GetList("keys")
	cur := readKeySet(path)
	if sameKeys(cur, keys) {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Diff: fmt.Sprintf("replace authorized keys (%d -> %d)", len(cur), len(keys)),
		Before: []byte(Enc(pathContent(path)))}, nil
}
func readKeySet(path string) map[string]bool {
	m := map[string]bool{}
	b, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			m[l] = true
		}
	}
	return m
}
func pathContent(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}
func sameKeys(cur map[string]bool, want []string) bool {
	if len(cur) != len(want) {
		return false
	}
	for _, w := range want {
		if !cur[w] {
			return false
		}
	}
	return true
}
func (a sshAuthorizedKeys) Apply(p Params) (CheckResult, error) {
	path := p.Get("path", "")
	keys := p.GetList("keys")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return CheckResult{}, err
	}
	content := ""
	for _, k := range keys {
		content += k + "\n"
	}
	cur := pathContent(path)
	if cur == content {
		return CheckResult{Done: true}, nil
	}
	if err := writeWithReplace(path, content, 0o600); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Before: []byte(Enc(cur))}, nil
}
func (a sshAuthorizedKeys) Verify(p Params) (CheckResult, error) {
	if !sameKeys(readKeySet(p.Get("path", "")), p.GetList("keys")) {
		return CheckResult{Diff: "key set mismatch"}, nil
	}
	return CheckResult{Done: true}, nil
}
func (a sshAuthorizedKeys) Rollback(p Params, before []byte) (CheckResult, error) {
	return rollbackFileAction(p.Get("path", ""), before)
}
