package action

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ---- sysctl.set ---------------------------------------------------------------

type sysctlSet struct{}

func (sysctlSet) Name() string   { return "sysctl.set" }
func (sysctlSet) Risk() Risk     { return RiskService }
func (sysctlSet) Locks() []string { return nil }

func sysctlPath(key string) string {
	return filepath.Join("/proc/sys", strings.ReplaceAll(key, ".", "/"))
}

func (a sysctlSet) Check(p Params) (CheckResult, error) {
	key, value := p.Get("key", ""), p.Get("value", "")
	cur, err := os.ReadFile(sysctlPath(key))
	if err != nil {
		return CheckResult{Diff: fmt.Sprintf("%s: %v", key, err)}, nil
	}
	if strings.TrimSpace(string(cur)) == value {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Diff: fmt.Sprintf("%s: %s -> %s", key, strings.TrimSpace(string(cur)), value),
		Before: cur}, nil
}
func (a sysctlSet) Apply(p Params) (CheckResult, error) {
	key, value := p.Get("key", ""), p.Get("value", "")
	path := sysctlPath(key)
	before, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Before: before}, nil
}
func (a sysctlSet) Verify(p Params) (CheckResult, error) {
	key, value := p.Get("key", ""), p.Get("value", "")
	cur, err := os.ReadFile(sysctlPath(key))
	if err != nil {
		return CheckResult{Diff: fmt.Sprintf("%s: %v", key, err)}, nil
	}
	if strings.TrimSpace(string(cur)) != value {
		return CheckResult{Diff: fmt.Sprintf("%s is %s", key, strings.TrimSpace(string(cur)))}, nil
	}
	return CheckResult{Done: true}, nil
}
func (a sysctlSet) Rollback(p Params, before []byte) (CheckResult, error) {
	key := p.Get("key", "")
	if len(before) == 0 {
		return CheckResult{Done: true}, nil
	}
	if err := os.WriteFile(sysctlPath(key), before, 0o644); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Done: true, Diff: fmt.Sprintf("%s restored", key)}, nil
}

// ---- module.block -------------------------------------------------------------

// modprobeBlacklistPath is where the agent writes its block rules.
const modprobeBlacklistPath = "/etc/modprobe.d/99-phylax-blacklist.conf"

func modprobeManagedLine(l string) bool {
	return strings.HasPrefix(l, "# phylax module.block: ") ||
		strings.HasPrefix(l, "blacklist ") ||
		(strings.HasPrefix(l, "install ") && strings.HasSuffix(l, "/bin/false"))
}

type moduleBlock struct{}

func (moduleBlock) Name() string    { return "module.block" }
func (moduleBlock) Risk() Risk      { return RiskService }
func (moduleBlock) Locks() []string { return []string{"packages"} }
func (moduleBlock) Check(p Params) (CheckResult, error) {
	modules := p.GetList("modules")
	content, _ := readOrEmpty(modprobeBlacklistPath)
	var missing []string
	for _, m := range modules {
		if !modprobeHasModule(content, m) {
			missing = append(missing, m)
		}
	}
	if len(missing) == 0 {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Diff: fmt.Sprintf("block modules %s", strings.Join(missing, ", ")),
		Before: []byte(Enc(content))}, nil
}
func modprobeHasModule(content, module string) bool {
	for _, l := range strings.Split(content, "\n") {
		if l == fmt.Sprintf("blacklist %s", module) {
			return true
		}
	}
	return false
}
func (moduleBlock) Apply(p Params) (CheckResult, error) {
	modules := p.GetList("modules")
	before, _ := readOrEmpty(modprobeBlacklistPath)
	var kept []string
	for _, l := range strings.Split(before, "\n") {
		if !modprobeManagedLine(l) {
			kept = append(kept, l)
		}
	}
	for _, m := range modules {
		kept = append(kept,
			fmt.Sprintf("# phylax module.block: %s", m),
			fmt.Sprintf("blacklist %s", m),
			fmt.Sprintf("install %s /bin/false", m),
		)
	}
	content := strings.TrimRight(strings.Join(kept, "\n"), "\n")
	if content != "" {
		content += "\n"
	}
	if err := writeWithReplace(modprobeBlacklistPath, content, 0o644); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Before: []byte(Enc(before))}, nil
}
func (moduleBlock) Verify(p Params) (CheckResult, error) {
	content, _ := readOrEmpty(modprobeBlacklistPath)
	for _, m := range p.GetList("modules") {
		if !modprobeHasModule(content, m) {
			return CheckResult{Diff: fmt.Sprintf("%s not blocked", m)}, nil
		}
	}
	return CheckResult{Done: true}, nil
}
func (moduleBlock) Rollback(_ Params, before []byte) (CheckResult, error) {
	if err := rollbackFile(modprobeBlacklistPath, before); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Done: true, Diff: "previous modprobe config restored"}, nil
}

// ---- hosts.file -----------------------------------------------------------------

// hostsMarker delimits the phylax-managed block in /etc/hosts.
const hostsMarker = "# phylax-managed-begin"

const hostsMarkerEnd = "# phylax-managed-end"

func hostsManagedBlock(entries []string) string {
	b := hostsMarker + "\n"
	for _, e := range entries {
		b += e + "\n"
	}
	return b + hostsMarkerEnd + "\n"
}

func hostsCurrentEntries(content string) []string {
	var out []string
	in := false
	for _, l := range strings.Split(content, "\n") {
		switch l {
		case hostsMarker:
			in = true
			continue
		case hostsMarkerEnd:
			in = false
			continue
		}
		if in && strings.TrimSpace(l) != "" {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

type hostsFile struct{}

func (hostsFile) Name() string   { return "hosts.file" }
func (hostsFile) Risk() Risk     { return RiskService }
func (hostsFile) Locks() []string { return nil }
func (hostsFile) Check(p Params) (CheckResult, error) {
	entries := p.GetList("entries")
	content, _ := readOrEmpty("/etc/hosts")
	cur := hostsCurrentEntries(content)
	if sameStringSet(cur, entries) {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Diff: fmt.Sprintf("hosts entries: %v -> %v", cur, entries),
		Before: []byte(Enc(content))}, nil
}
func (hostsFile) Apply(p Params) (CheckResult, error) {
	entries := p.GetList("entries")
	before, _ := readOrEmpty("/etc/hosts")
	base := before
	if i := strings.Index(base, hostsMarker); i >= 0 {
		end := strings.Index(base, hostsMarkerEnd)
		if end >= 0 {
			end += len(hostsMarkerEnd)
			if nl := strings.IndexByte(base[end:], '\n'); nl >= 0 {
				end += nl + 1
			}
			base = strings.TrimSuffix(base[:i], "\n") + "\n" + base[end:]
		}
	}
	content := strings.TrimRight(base, "\n") + "\n" + hostsManagedBlock(entries)
	if content == before {
		return CheckResult{Done: true}, nil
	}
	if err := writeWithReplace("/etc/hosts", content, 0o644); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Before: []byte(Enc(before))}, nil
}
func (hostsFile) Verify(p Params) (CheckResult, error) {
	content, _ := readOrEmpty("/etc/hosts")
	if !sameStringSet(hostsCurrentEntries(content), p.GetList("entries")) {
		return CheckResult{Diff: "hosts entries mismatch"}, nil
	}
	return CheckResult{Done: true}, nil
}
func (hostsFile) Rollback(_ Params, before []byte) (CheckResult, error) {
	if err := rollbackFile("/etc/hosts", before); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Done: true, Diff: "previous hosts file restored"}, nil
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
		if m[x] < 0 {
			return false
		}
	}
	return true
}

// ---- cron.disable / unit.disable ----------------------------------------------

// cron.disable renames the user's crontab files to *.phylax-disabled so the
// scheduler stops running them; the content is kept for restore.

type cronDisable struct{}

func (cronDisable) Name() string    { return "cron.disable" }
func (cronDisable) Risk() Risk      { return RiskService }
func (cronDisable) Locks() []string { return []string{"audit"} }

func cronFilesForUser(user string) []string {
	var out []string
	sp := "/var/spool/cron/crontabs/" + user
	if _, err := os.Stat(sp); err == nil {
		out = append(out, sp)
	}
	if d, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, e := range d {
			b, _ := os.ReadFile("/etc/cron.d/" + e.Name())
			if userInCronFile(string(b), user) {
				out = append(out, "/etc/cron.d/"+e.Name())
			}
		}
	}
	return out
}

func userInCronFile(content, user string) bool {
	for _, l := range strings.Split(content, "\n") {
		fields := strings.Fields(l)
		if len(fields) >= 7 && !strings.HasPrefix(l, "#") && fields[6] == user {
			return true
		}
	}
	return false
}

const disabledSuffix = ".phylax-disabled"

func (a cronDisable) Check(p Params) (CheckResult, error) {
	user := p.Get("user", "")
	var active []string
	for _, f := range cronFilesForUser(user) {
		if !strings.HasSuffix(f, disabledSuffix) {
			active = append(active, f)
		}
	}
	if len(active) == 0 {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Diff: fmt.Sprintf("disable cron %v", active),
		Before: []byte(Enc(strings.Join(active, ",")))}, nil
}
func (a cronDisable) Apply(p Params) (CheckResult, error) {
	user := p.Get("user", "")
	var active []string
	for _, f := range cronFilesForUser(user) {
		if !strings.HasSuffix(f, disabledSuffix) {
			active = append(active, f)
		}
	}
	for _, f := range active {
		if err := os.Rename(f, f+disabledSuffix); err != nil {
			return CheckResult{}, err
		}
	}
	if len(active) == 0 {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Before: []byte(Enc(strings.Join(active, ",")))}, nil
}
func (a cronDisable) Verify(p Params) (CheckResult, error) {
	for _, f := range cronFilesForUser(p.Get("user", "")) {
		if !strings.HasSuffix(f, disabledSuffix) {
			return CheckResult{Diff: fmt.Sprintf("%s still active", f)}, nil
		}
	}
	return CheckResult{Done: true}, nil
}
func (a cronDisable) Rollback(_ Params, before []byte) (CheckResult, error) {
	for _, f := range strings.Split(string(Dec(string(before))), ",") {
		if f == "" {
			continue
		}
		if err := os.Rename(f+disabledSuffix, f); err != nil {
			return CheckResult{}, err
		}
	}
	return CheckResult{Done: true, Diff: "cron entries re-enabled"}, nil
}

// unit.disable renames a systemd unit file (its wants symlinks are inert
// once the unit file is gone). The plan node declares the per-service lock
// (service:<unit>) in its own lock list.
type unitDisable struct{}

func (unitDisable) Name() string    { return "unit.disable" }
func (unitDisable) Risk() Risk      { return RiskService }
func (unitDisable) Locks() []string { return nil }

func (a unitDisable) Check(p Params) (CheckResult, error) {
	unit := p.Get("unit", "")
	if unitFileExists(unit) {
		return CheckResult{Diff: fmt.Sprintf("disable unit %s", unit), Before: []byte(unit)}, nil
	}
	return CheckResult{Done: true}, nil
}
func (a unitDisable) Apply(p Params) (CheckResult, error) {
	unit := p.Get("unit", "")
	path, ok := unitFilePath(unit)
	if !ok {
		return CheckResult{Done: true}, nil
	}
	if strings.HasSuffix(path, disabledSuffix) {
		return CheckResult{Done: true}, nil
	}
	if err := os.Rename(path, path+disabledSuffix); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Before: []byte(unit)}, nil
}
func (a unitDisable) Verify(p Params) (CheckResult, error) {
	if unitFileExists(p.Get("unit", "")) {
		return CheckResult{Diff: "unit still enabled"}, nil
	}
	return CheckResult{Done: true}, nil
}
func (a unitDisable) Rollback(_ Params, before []byte) (CheckResult, error) {
	unit := string(before)
	path, ok := unitFilePath(unit + disabledSuffix)
	if !ok {
		return CheckResult{Done: true}, nil
	}
	if err := os.Rename(path, strings.TrimSuffix(path, disabledSuffix)); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Done: true, Diff: fmt.Sprintf("unit %s re-enabled", unit)}, nil
}

func unitFilePath(unit string) (string, bool) {
	for _, dir := range []string{"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"} {
		p := dir + "/" + unit
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	return "", false
}

func unitFileExists(unit string) bool {
	_, ok := unitFilePath(unit)
	return ok
}

// ---- proc.kill_tree -------------------------------------------------------------

type procKillTree struct{}

func (procKillTree) Name() string   { return "proc.kill_tree" }
func (procKillTree) Risk() Risk     { return RiskDestructive }
func (procKillTree) Locks() []string { return nil }

func (a procKillTree) Check(p Params) (CheckResult, error) {
	uid, _ := strconv.Atoi(p.Get("pid", ""))
	if uid == 0 || !procExists(uid) {
		return CheckResult{Done: true}, nil
	}
	return CheckResult{Diff: fmt.Sprintf("kill process tree %d", uid),
		Before: []byte(strconv.Itoa(uid))}, nil
}
func procExists(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	// A zombie is already dead; its parent just hasn't reaped it.
	if i := strings.LastIndex(string(b), ")"); i > 0 {
		fields := strings.Fields(string(b[i+1:]))
		return len(fields) > 0 && fields[0] != "Z"
	}
	return true
}
func (a procKillTree) Apply(p Params) (CheckResult, error) {
	uid, _ := strconv.Atoi(p.Get("pid", ""))
	if uid == 0 || !procExists(uid) {
		return CheckResult{Done: true}, nil
	}
	children := procChildren(uid)
	_ = syscall.Kill(-uid, syscall.SIGTERM) // process group if leader
	for _, c := range children {
		_ = syscall.Kill(c, syscall.SIGTERM)
	}
	_ = syscall.Kill(uid, syscall.SIGTERM)
	for i := 0; i < 20; i++ {
		if !procExists(uid) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = syscall.Kill(-uid, syscall.SIGKILL)
	for _, c := range children {
		_ = syscall.Kill(c, syscall.SIGKILL)
	}
	_ = syscall.Kill(uid, syscall.SIGKILL)
	return CheckResult{Before: []byte(strconv.Itoa(uid)), Done: true}, nil
}
func procChildren(pid int) []int {
	var out []int
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		st, perr := os.ReadFile("/proc/" + e.Name() + "/stat")
		if perr != nil {
			continue
		}
		// stat: pid (comm) state ppid ...
		s := string(st)
		if i := strings.LastIndex(s, ")"); i > 0 {
			fields := strings.Fields(s[i+1:])
			if len(fields) >= 2 && fields[1] == strconv.Itoa(pid) {
				if c, err := strconv.Atoi(e.Name()); err == nil {
					out = append(out, c)
				}
			}
		}
	}
	return out
}
func (a procKillTree) Verify(p Params) (CheckResult, error) {
	uid, _ := strconv.Atoi(p.Get("pid", ""))
	if uid != 0 && procExists(uid) {
		return CheckResult{Diff: fmt.Sprintf("pid %d still alive", uid)}, nil
	}
	return CheckResult{Done: true}, nil
}
func (a procKillTree) Rollback(_ Params, _ []byte) (CheckResult, error) {
	return CheckResult{Done: true, Diff: "kills are not reversible"}, nil
}
