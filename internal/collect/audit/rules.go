//go:build linux

package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/elastic/go-libaudit/v2/rule"
	"github.com/elastic/go-libaudit/v2/rule/flags"
)

// persistenceWatches are the fixed persistence, account and trust paths
// (design Appendices B and C): accounts, sudoers, PAM, ld.so, systemd unit
// directories, cron and at spools, sshd config, shell startup files.
var persistenceWatches = []string{
	"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
	"/etc/sudoers", "/etc/sudoers.d",
	"/etc/pam.d", "/etc/security",
	"/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
	"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system",
	"/etc/systemd/user", "/usr/lib/systemd/user", "/run/systemd/system",
	"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly",
	"/etc/crontab", "/etc/anacrontab", "/var/spool/cron", "/var/spool/at", "/var/spool/anacron",
	"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d", "/root/.ssh",
	"/etc/profile", "/etc/profile.d", "/etc/bash.bashrc", "/etc/environment",
	"/etc/rc.local", "/etc/init.d", "/etc/udev/rules.d", "/etc/modules-load.d",
	"/etc/audit",
}

// RuleSet is the desired kernel rule set. Lines are auditctl-syntax strings;
// Wire holds the encoded rules in the same order.
type RuleSet struct {
	Lines []string
	Wire  []rule.WireFormat
}

// WatchPaths returns the full list of paths to watch for cfg (persistence
// paths, extra watches, web roots), deduplicated and sorted.
func (c *Config) WatchPaths() []string {
	seen := map[string]bool{}
	var out []string
	for _, lst := range [][]string{persistenceWatches, c.ExtraWatches, c.WebRoots} {
		for _, p := range lst {
			p = filepath.Clean(p)
			if p != "." && p != "/" && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out
}

func archFlags() []string {
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		return []string{"b64", "b32"}
	}
	return []string{"b64"}
}

// BuildRuleLines renders the rule lines for cfg. exists reports whether a
// path exists and is a directory.
func BuildRuleLines(cfg *Config, exists func(string) (exists, isDir bool)) []string {
	sfx := cfg.TestKeySuffix
	var lines []string
	for _, a := range archFlags() {
		lines = append(lines, fmt.Sprintf("-a always,exit -F arch=%s -S execve,execveat -k %s%s", a, KeyExec, sfx))
	}
	if cfg.NetRules {
		// b64 only: 32-bit x86 has no accept/connect syscalls (socketcall).
		lines = append(lines, fmt.Sprintf("-a always,exit -F arch=b64 -S connect,accept,accept4 -F success=1 -k %s%s", KeyNet, sfx))
	}
	add := func(p, key string) {
		if strings.ContainsAny(p, " \t\"'") {
			return // rule text is shell-split; such paths are left to the sweep
		}
		ex, isDir := exists(p)
		switch {
		case ex && isDir:
			// dir= is recursive (unlike -w, which sees only direct children).
			lines = append(lines, fmt.Sprintf("-a always,exit -F dir=%s -F perm=wa -k %s%s", p, key, sfx))
		case ex:
			lines = append(lines, fmt.Sprintf("-w %s -p wa -k %s%s", p, key, sfx))
		default:
			// Not there yet (e.g. /etc/ld.so.preload on a stock host): a file
			// watch works if the parent directory exists.
			if pe, pd := exists(filepath.Dir(p)); pe && pd {
				lines = append(lines, fmt.Sprintf("-w %s -p wa -k %s%s", p, key, sfx))
			}
		}
	}
	for _, p := range cfg.WatchPaths() {
		add(p, KeyFIM)
	}
	self := append([]string(nil), cfg.SelfPaths...)
	sort.Strings(self)
	for _, p := range self {
		add(filepath.Clean(p), KeySelf)
	}
	return lines
}

func osExists(p string) (bool, bool) {
	st, err := os.Stat(p)
	if err != nil {
		return false, false
	}
	return true, st.IsDir()
}

// NewRuleSet parses and encodes rule lines.
func NewRuleSet(lines []string) (*RuleSet, error) {
	rs := &RuleSet{}
	for _, l := range lines {
		r, err := flags.Parse(l)
		if err != nil {
			return nil, fmt.Errorf("audit rule %q: %w", l, err)
		}
		wf, err := rule.Build(r)
		if err != nil {
			return nil, fmt.Errorf("audit rule %q: %w", l, err)
		}
		rs.Lines = append(rs.Lines, l)
		rs.Wire = append(rs.Wire, wf)
	}
	return rs, nil
}

// canonLine renders kernel wire bytes to the canonical command-line text.
func canonLine(wf []byte) (string, error) { return rule.ToCommandLine(wf, false) }

// isOurs reports whether a rendered rule carries one of our keys.
// Syscall rules render the key as "-F key=", watches as "-k".
func isOurs(line string) bool {
	return strings.Contains(line, "-k "+KeyPrefix) || strings.Contains(line, "key="+KeyPrefix)
}

// isNever flags foreign rules that would blind us.
func isNever(line string) bool {
	return strings.HasPrefix(line, "-a never,") || strings.Contains(line, "task,never")
}

// HashLines hashes a set of rule lines order-independently.
func HashLines(lines []string) string {
	c := append([]string(nil), lines...)
	sort.Strings(c)
	h := sha256.Sum256([]byte(strings.Join(c, "\n")))
	return hex.EncodeToString(h[:])
}

// RuleView is a classified snapshot of the kernel rule list.
type RuleView struct {
	Ours    []string // canonical lines of rules with our keys, sorted
	Foreign int
	Never   []string // foreign never-rules
}

// ClassifyKernelRules renders and splits what GetRules returned.
func ClassifyKernelRules(raw [][]byte) RuleView {
	var v RuleView
	for _, wf := range raw {
		l, err := canonLine(wf)
		if err != nil {
			v.Foreign++
			continue
		}
		if isOurs(l) {
			v.Ours = append(v.Ours, l)
			continue
		}
		v.Foreign++
		if isNever(l) {
			v.Never = append(v.Never, l)
		}
	}
	sort.Strings(v.Ours)
	return v
}

// Missing returns the lines in want that are absent from have (multiset).
func Missing(want, have []string) []string {
	set := make(map[string]int, len(have))
	for _, h := range have {
		set[h]++
	}
	var out []string
	for _, w := range want {
		if set[w] > 0 {
			set[w]--
			continue
		}
		out = append(out, w)
	}
	return out
}
