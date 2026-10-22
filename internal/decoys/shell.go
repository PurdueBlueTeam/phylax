package decoys

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/PurdueBlueTeam/phylax/pools"
)

// The fake shell. It is a pure function from a command line to canned text over
// an in-memory filesystem built from pools/fs. It imports no process-execution
// package and has no path to the real filesystem or network: nothing a client
// types is ever run (design: Deception, "Record only"). A test enforces the
// import rule.

const (
	maxShellFiles   = 128  // files the attacker can create in the in-memory FS
	maxShellFileLen = 4096 // bytes per created file
	maxLineLen      = 4096
	maxPathLen      = 256
)

type fsNode struct {
	dir     bool
	content string
}

// Shell is one fake shell session. Not safe for concurrent use.
type Shell struct {
	host    string
	user    string
	cwd     string
	fs      map[string]*fsNode
	cmds    map[string]string
	history []string
	env     map[string]string
	created int
}

// NewShell builds a shell for a host name from the embedded pools.
func NewShell(host, user string) *Shell {
	s := &Shell{host: host, user: user, cwd: "/root", fs: map[string]*fsNode{}, cmds: map[string]string{},
		env: map[string]string{"HOME": "/root", "USER": user, "SHELL": "/bin/bash", "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "en_US.UTF-8"}}
	sub := strings.NewReplacer("{{HOST}}", host, "{{USER}}", user)
	for _, l := range pools.Lines("fs/files.txt") {
		f := strings.Split(l, "\t")
		if len(f) < 2 {
			continue
		}
		n := &fsNode{dir: f[1] == "d"}
		if !n.dir && len(f) > 2 && f[2] != "" {
			if b, err := pools.Read("fs/content/" + f[2]); err == nil {
				n.content = sub.Replace(string(b))
			}
		}
		s.fs[f[0]] = n
	}
	for _, l := range pools.Lines("fs/commands.txt") {
		if k, v, ok := strings.Cut(l, "\t"); ok {
			s.cmds[k] = sub.Replace(strings.ReplaceAll(v, `\n`, "\n"))
		}
	}
	return s
}

// Prompt is the string shown before each command.
func (s *Shell) Prompt() string {
	cwd := s.cwd
	if cwd == "/root" {
		cwd = "~"
	}
	ch := "#"
	if s.user != "root" {
		ch = "$"
	}
	return fmt.Sprintf("%s@%s:%s%s ", s.user, s.host, cwd, ch)
}

// Run executes one line against the fake state and returns the text to send
// and whether the session should end. Output uses \n; callers translate.
func (s *Shell) Run(line string) (out string, exit bool) {
	if len(line) > maxLineLen {
		line = line[:maxLineLen]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false
	}
	s.history = append(s.history, line)
	if len(s.history) > 200 {
		s.history = s.history[1:]
	}
	var b strings.Builder
	for _, seg := range splitCommands(line) {
		o, ex := s.runOne(seg)
		b.WriteString(o)
		if ex {
			return b.String(), true
		}
	}
	return b.String(), false
}

// splitCommands splits on ; && || | (quoting is not interpreted: the pieces
// are only looked up, never executed).
func splitCommands(line string) []string {
	r := strings.NewReplacer("&&", ";", "||", ";", "|", ";", "&", ";")
	var out []string
	for _, p := range strings.Split(r.Replace(line), ";") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Shell) abs(p string) string {
	if len(p) > maxPathLen {
		p = p[:maxPathLen]
	}
	if p == "~" || strings.HasPrefix(p, "~/") {
		p = "/root" + p[1:]
	}
	if !strings.HasPrefix(p, "/") {
		p = s.cwd + "/" + p
	}
	return path.Clean(p)
}

func (s *Shell) children(dir string) []string {
	var out []string
	for p := range s.fs {
		if p != dir && path.Dir(p) == dir {
			out = append(out, path.Base(p))
		}
	}
	sort.Strings(out)
	return out
}

func (s *Shell) runOne(seg string) (string, bool) {
	// Redirection writes only the in-memory FS.
	redir := ""
	appendMode := false
	if i := strings.Index(seg, ">"); i >= 0 {
		rest := seg[i+1:]
		if strings.HasPrefix(rest, ">") {
			appendMode, rest = true, rest[1:]
		}
		redir = strings.TrimSpace(rest)
		seg = strings.TrimSpace(seg[:i])
	}
	f := strings.Fields(seg)
	if len(f) == 0 {
		return "", false
	}
	for len(f) > 1 && (f[0] == "sudo" || f[0] == "nohup" || f[0] == "env" && !strings.Contains(f[1], "=") && f[1] != "") {
		f = f[1:]
	}
	cmd, args := f[0], f[1:]
	out, exit := s.dispatch(cmd, args, strings.Join(f, " "))
	if redir != "" {
		s.write(redir, out, appendMode)
		return "", exit
	}
	return out, exit
}

func (s *Shell) write(p, content string, appendMode bool) {
	p = s.abs(strings.Fields(p + " ")[0])
	n := s.fs[p]
	if n == nil {
		if s.created >= maxShellFiles || s.fs[path.Dir(p)] == nil || !s.fs[path.Dir(p)].dir {
			return
		}
		n = &fsNode{}
		s.fs[p] = n
		s.created++
	}
	if n.dir {
		return
	}
	if appendMode {
		content = n.content + content
	}
	if len(content) > maxShellFileLen {
		content = content[:maxShellFileLen]
	}
	n.content = content
}

func (s *Shell) dispatch(cmd string, args []string, full string) (string, bool) {
	switch cmd {
	case "exit", "logout":
		return "logout\n", true
	case "pwd":
		return s.cwd + "\n", false
	case "cd":
		t := "/root"
		if len(args) > 0 {
			t = s.abs(args[0])
		}
		n := s.fs[t]
		switch {
		case n == nil:
			return fmt.Sprintf("bash: cd: %s: No such file or directory\n", clip(args[0])), false
		case !n.dir:
			return fmt.Sprintf("bash: cd: %s: Not a directory\n", clip(args[0])), false
		}
		s.cwd = t
		return "", false
	case "ls", "dir", "ll":
		return s.ls(args, cmd == "ll"), false
	case "cat", "more", "less", "head", "tail":
		var b strings.Builder
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			n := s.fs[s.abs(a)]
			switch {
			case n == nil:
				fmt.Fprintf(&b, "%s: %s: No such file or directory\n", cmd, clip(a))
			case n.dir:
				fmt.Fprintf(&b, "%s: %s: Is a directory\n", cmd, clip(a))
			default:
				b.WriteString(n.content)
			}
		}
		return b.String(), false
	case "echo":
		return strings.Join(args, " ") + "\n", false
	case "hostname":
		return s.host + "\n", false
	case "whoami":
		return s.user + "\n", false
	case "history":
		var b strings.Builder
		for i, h := range s.history {
			fmt.Fprintf(&b, "%5d  %s\n", i+1, h)
		}
		return b.String(), false
	case "env", "printenv", "export":
		if cmd == "export" {
			return "", false
		}
		keys := make([]string, 0, len(s.env))
		for k := range s.env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			b.WriteString(k + "=" + s.env[k] + "\n")
		}
		return b.String(), false
	case "touch":
		for _, a := range args {
			if !strings.HasPrefix(a, "-") && s.fs[s.abs(a)] == nil {
				s.write(a, "", false)
			}
		}
		return "", false
	case "mkdir":
		for _, a := range args {
			p := s.abs(a)
			if !strings.HasPrefix(a, "-") && s.fs[p] == nil && s.created < maxShellFiles && s.fs[path.Dir(p)] != nil {
				s.fs[p] = &fsNode{dir: true}
				s.created++
			}
		}
		return "", false
	case "rm":
		for _, a := range args {
			if p := s.abs(a); !strings.HasPrefix(a, "-") && s.fs[p] != nil && p != "/" {
				delete(s.fs, p)
			}
		}
		return "", false
	case "wget", "curl", "fetch", "tftp", "ftp":
		return "curl: (28) Failed to connect: Connection timed out\n", false
	case "nc", "ncat", "netcat", "socat", "ssh", "scp", "telnet", "ping":
		return fmt.Sprintf("%s: connect: Network is unreachable\n", cmd), false
	case "chmod", "chown", "chgrp", "su", "clear", "set", "unset", "alias", "umask", "sync", "true", "source", ".", "sleep":
		return "", false
	case "systemctl", "service":
		return "Failed to connect to bus: No such file or directory\n", false
	case "crontab":
		return "no crontab for " + s.user + "\n", false
	case "python", "python3", "perl", "bash", "sh", "zsh", "php", "ruby", "gcc", "make":
		return "", false
	}
	// Canned outputs keyed by the full command, then by the bare command.
	if o, ok := s.cmds[full]; ok {
		return o + "\n", false
	}
	if o, ok := s.cmds[cmd]; ok {
		return o + "\n", false
	}
	return fmt.Sprintf("bash: %s: command not found\n", clip(cmd)), false
}

func (s *Shell) ls(args []string, long bool) string {
	all := false
	target := s.cwd
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "-"):
			if strings.ContainsAny(a, "l") {
				long = true
			}
			if strings.ContainsAny(a, "a") {
				all = true
			}
		default:
			target = s.abs(a)
		}
	}
	n := s.fs[target]
	if n == nil {
		return fmt.Sprintf("ls: cannot access '%s': No such file or directory\n", clip(target))
	}
	if !n.dir {
		return path.Base(target) + "\n"
	}
	var b strings.Builder
	for _, c := range s.children(target) {
		if strings.HasPrefix(c, ".") && !all {
			continue
		}
		cn := s.fs[path.Join(target, c)]
		if long {
			mode := "-rw-r--r--"
			if cn.dir {
				mode = "drwxr-xr-x"
			}
			size := len(cn.content)
			if cn.dir {
				size = 4096
			}
			fmt.Fprintf(&b, "%s 1 root root %5d Mar  5 10:11 %s\n", mode, size, c)
		} else {
			b.WriteString(c + "  ")
		}
	}
	if !long && b.Len() > 0 {
		b.WriteString("\n")
	}
	return b.String()
}

// clip bounds attacker text echoed back (it is only ever written to the same
// socket; the recorded copy is bounded separately).
func clip(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}
