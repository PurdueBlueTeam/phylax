// Package vyostest is a fake VyOS 1.4 router for tests: an SSH server
// (golang.org/x/crypto/ssh) that interprets the small vbash/op-mode/systemd
// command set the adapter uses, plus the HTTP API (/show, /retrieve). It keeps
// a running config, a saved boot config, a commit history and systemd-run
// timers that really fire. It emulates the device; it never contacts one.
package vyostest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Server is the fake router.
type Server struct {
	HTTP    *httptest.Server
	SSHAddr string
	HostKey ssh.PublicKey
	APIKey  string

	mu       sync.Mutex
	running  map[string]bool
	saved    map[string]bool
	files    map[string]map[string]bool
	commits  []commit
	nclock   int
	timers   map[string]*time.Timer
	timerCmd map[string]string
	users    map[string]string
	who      []string
	ops      []string
	ln       net.Listener
	conns    []net.Conn
	closed   bool

	// Knobs for tests.
	FailCommit string                    // commit prints "Commit failed: ..." and changes nothing
	OnCommit   func(lines []string)      // called after every commit with the running lines
	BlockSSH   func(lines []string) bool // true: new SSH logins are refused
	BlockHTTP  func(lines []string) bool // true: HTTP requests are refused
	Version    string
}

type commit struct{ when, user, via string }

// New starts the fake with user phylax/pw and API key "k".
func New() *Server {
	s := &Server{
		running: map[string]bool{}, saved: map[string]bool{}, files: map[string]map[string]bool{},
		timers: map[string]*time.Timer{}, timerCmd: map[string]string{}, users: map[string]string{"phylax": "pw", "evil": "pw"},
		APIKey: "k", Version: "VyOS 1.4.0",
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	_ = pub
	s.HostKey = signer.PublicKey()
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.BlockSSH != nil && s.BlockSSH(s.lines(s.running)) {
			return nil, fmt.Errorf("blocked by firewall input rule")
		}
		if p, ok := s.users[c.User()]; ok && p == string(pw) {
			return nil, nil
		}
		return nil, fmt.Errorf("denied")
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	s.ln, s.SSHAddr = ln, ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, c)
			s.mu.Unlock()
			go s.serve(c, cfg)
		}
	}()
	s.HTTP = httptest.NewTLSServer(http.HandlerFunc(s.handleHTTP))
	return s
}

// Close stops everything, including pending timers.
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	for _, t := range s.timers {
		t.Stop()
	}
	for _, c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.ln.Close()
	s.HTTP.Close()
}

// ---- state helpers for tests ----

func (s *Server) lines(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for l := range m {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// Lines is the running config as sorted `set` lines.
func (s *Server) Lines() []string { s.mu.Lock(); defer s.mu.Unlock(); return s.lines(s.running) }

// SavedLines is the boot (saved) config.
func (s *Server) SavedLines() []string { s.mu.Lock(); defer s.mu.Unlock(); return s.lines(s.saved) }

// Has reports whether the running config has exactly this line.
func (s *Server) Has(line string) bool { s.mu.Lock(); defer s.mu.Unlock(); return s.running[line] }

// Seed sets running and saved config and records one initial commit by "vyos".
func (s *Server) Seed(lines ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running, s.saved = map[string]bool{}, map[string]bool{}
	for _, l := range lines {
		s.running[l], s.saved[l] = true, true
	}
	s.record("vyos", "boot-config-loader")
}

// ExternalCommit applies and commits lines as another admin (not saved).
func (s *Server) ExternalCommit(user string, add []string, del ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range add {
		s.running[l] = true
	}
	for _, l := range del {
		delete(s.running, l)
	}
	s.record(user, "cli")
}

// EditBootFile changes the saved config behind the router's back.
func (s *Server) EditBootFile(line string) { s.mu.Lock(); s.saved[line] = true; s.mu.Unlock() }

// TimerArmed reports a pending systemd-run timer.
func (s *Server) TimerArmed(unit string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.timers[unit] != nil
}

// Ops is the log of exec commands received.
func (s *Server) Ops() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.ops...)
}

// SetWho sets the output lines of `who`.
func (s *Server) SetWho(lines ...string) { s.mu.Lock(); s.who = lines; s.mu.Unlock() }

// HasFile reports a saved config file on the router.
func (s *Server) HasFile(p string) bool { s.mu.Lock(); defer s.mu.Unlock(); return s.files[p] != nil }

// CommitCount is the number of history entries.
func (s *Server) CommitCount() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.commits) }

func (s *Server) record(user, via string) {
	s.nclock++
	t := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC).Add(time.Duration(s.nclock) * time.Second)
	s.commits = append([]commit{{t.Format("2006-01-02 15:04:05"), user, via}}, s.commits...)
}

// ---- ssh ----

func (s *Server) serve(c net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go s.session(sc.User(), ch, creqs)
	}
}

func (s *Server) session(user string, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for r := range reqs {
		if r.Type != "exec" {
			r.Reply(false, nil)
			continue
		}
		var p struct{ Cmd string }
		ssh.Unmarshal(r.Payload, &p)
		r.Reply(true, nil)
		var stdin string
		if strings.HasPrefix(p.Cmd, "vbash") {
			b, _ := io.ReadAll(io.LimitReader(ch, 1<<20))
			stdin = string(b)
		}
		out, errOut, code := s.exec(user, p.Cmd, stdin)
		io.WriteString(ch, out)
		io.WriteString(ch.Stderr(), errOut)
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
		return
	}
}

var (
	onActiveRE = regexp.MustCompile(`--on-active=(\S+)`)
	unitRE     = regexp.MustCompile(`--unit=(\S+)`)
	loadRE     = regexp.MustCompile(`load (\S+);`)
)

func (s *Server) exec(user, cmd, stdin string) (out, errOut string, code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ops = append(s.ops, user+": "+cmd)
	const wrap = "/opt/vyatta/bin/vyatta-op-cmd-wrapper "
	switch {
	case strings.HasPrefix(cmd, "vbash"):
		return s.script(user, stdin), "", 0
	case strings.HasPrefix(cmd, wrap):
		return s.opCmd(strings.TrimPrefix(cmd, wrap))
	case strings.HasPrefix(cmd, "mkdir -p"):
		return "", "", 0
	case strings.HasPrefix(cmd, "rm -f "):
		delete(s.files, strings.TrimSpace(strings.TrimPrefix(cmd, "rm -f ")))
		return "", "", 0
	case cmd == "who":
		return strings.Join(s.who, "\n") + "\n", "", 0
	case strings.HasPrefix(cmd, "sha256sum /config/config.boot"):
		h := sha256.Sum256([]byte(strings.Join(s.lines(s.saved), "\n")))
		return hex.EncodeToString(h[:]) + "  /config/config.boot\n", "", 0
	case strings.HasPrefix(cmd, "sudo systemd-run"):
		unit := unitRE.FindStringSubmatch(cmd)
		dur := onActiveRE.FindStringSubmatch(cmd)
		file := loadRE.FindStringSubmatch(cmd)
		if unit == nil || dur == nil || file == nil {
			return "", "bad systemd-run\n", 1
		}
		if s.timers[unit[1]] != nil {
			return "", "Failed to start transient timer unit: Unit " + unit[1] + ".timer was already loaded or has a fragment file.\n", 1
		}
		d, err := time.ParseDuration(dur[1])
		if err != nil {
			return "", "bad time\n", 1
		}
		name, path := unit[1], file[1]
		s.timerCmd[name] = path
		s.timers[name] = time.AfterFunc(d, func() { s.fire(name) })
		return "", "", 0
	case strings.HasPrefix(cmd, "sudo systemctl stop "):
		u := strings.TrimSuffix(strings.TrimPrefix(cmd, "sudo systemctl stop "), ".timer")
		if t := s.timers[u]; t != nil {
			t.Stop()
			delete(s.timers, u)
			return "", "", 0
		}
		return "", "Unit " + u + ".timer not loaded.\n", 5
	case strings.HasPrefix(cmd, "sudo systemctl start "):
		u := strings.TrimSuffix(strings.TrimPrefix(cmd, "sudo systemctl start "), ".service")
		if t := s.timers[u]; t != nil {
			t.Stop()
			s.revert(u)
		}
		return "", "", 0
	case strings.HasPrefix(cmd, "systemctl is-active "):
		u := strings.TrimSuffix(strings.TrimPrefix(cmd, "systemctl is-active "), ".timer")
		if s.timers[u] != nil {
			return "active\n", "", 0
		}
		return "inactive\n", "", 3
	}
	return "", "unknown command: " + cmd + "\n", 127
}

func (s *Server) fire(unit string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.timers[unit] == nil {
		return
	}
	s.revert(unit)
}

// revert is what the armed vbash does: load the snapshot, commit, as root.
func (s *Server) revert(unit string) {
	path := s.timerCmd[unit]
	delete(s.timers, unit)
	if f := s.files[path]; f != nil {
		s.commitTo(clone(f), "root", "cli")
	}
}

func clone(m map[string]bool) map[string]bool {
	c := make(map[string]bool, len(m))
	for k := range m {
		c[k] = true
	}
	return c
}

func (s *Server) opCmd(c string) (string, string, int) {
	switch c {
	case "show version":
		return "Version:          " + s.Version + "\nHostname:         vyos1\nHardware S/N:     abc123\n", "", 0
	case "show configuration commands":
		return strings.Join(s.lines(s.running), "\n") + "\n", "", 0
	case "show system commit":
		return s.commitText(), "", 0
	case "show interfaces":
		return "Interface  IP Address  S/L\neth0  10.0.0.1/24  u/u\n", "", 0
	case "show ip route":
		return "S>* 0.0.0.0/0 [1/0] via 10.0.0.254, eth0\n", "", 0
	}
	return "", "unknown op command\n", 1
}

func (s *Server) commitText() string {
	var b strings.Builder
	for i, c := range s.commits {
		fmt.Fprintf(&b, "%d   %s by %s via %s\n", i, c.when, c.user, c.via)
	}
	return b.String()
}

// ---- vbash interpreter ----

type tok struct{ raw, val string }

func tokenize(l string) []tok {
	var out []tok
	i := 0
	for i < len(l) {
		for i < len(l) && l[i] == ' ' {
			i++
		}
		if i >= len(l) {
			break
		}
		start := i
		if l[i] == '\'' {
			j := strings.IndexByte(l[i+1:], '\'')
			if j < 0 {
				out = append(out, tok{l[i:], l[i+1:]})
				break
			}
			out = append(out, tok{l[i : i+j+2], l[i+1 : i+1+j]})
			i += j + 2
			continue
		}
		for i < len(l) && l[i] != ' ' {
			i++
		}
		out = append(out, tok{l[start:i], l[start:i]})
	}
	return out
}

func join(ts []tok) string {
	var p []string
	for _, t := range ts {
		p = append(p, t.raw)
	}
	return strings.Join(p, " ")
}

func hasPrefixVals(line []tok, prefix []tok) bool {
	if len(prefix) > len(line) {
		return false
	}
	for i := range prefix {
		if line[i].val != prefix[i].val {
			return false
		}
	}
	return true
}

func (s *Server) script(user, script string) string {
	var out strings.Builder
	var work map[string]bool
	inConf := false
	for _, raw := range strings.Split(script, "\n") {
		l := strings.TrimSpace(raw)
		if l == "" || strings.HasPrefix(l, "source ") {
			continue
		}
		ts := tokenize(l)
		switch ts[0].val {
		case "configure":
			work, inConf = clone(s.running), true
		case "exit":
			inConf = false
		case "set", "delete":
			if !inConf || len(ts) < 2 {
				out.WriteString("Invalid command: " + l + "\n")
				continue
			}
			if ts[0].val == "set" {
				work[join(ts)] = true
				continue
			}
			prefix := ts[1:]
			n := 0
			for line := range work {
				lt := tokenize(line)
				if hasPrefixVals(lt[1:], prefix) {
					delete(work, line)
					n++
				}
			}
			if n == 0 {
				out.WriteString("Nothing to delete (the specified node does not exist)\n")
			}
		case "compare":
			if !inConf {
				continue
			}
			if len(ts) > 1 && ts[1].val == "saved" {
				added, removed := diff(s.saved, work)
				for _, a := range added {
					out.WriteString("+" + a + "\n")
				}
				for _, r := range removed {
					out.WriteString("-" + r + "\n")
				}
				if len(added)+len(removed) == 0 {
					out.WriteString("No changes between working and saved configurations.\n")
				}
				continue
			}
			added, removed := diff(s.running, work)
			for _, a := range added {
				out.WriteString(a + "\n")
			}
			for _, r := range removed {
				out.WriteString("delete " + strings.TrimPrefix(r, "set ") + "\n")
			}
			if len(added)+len(removed) == 0 {
				out.WriteString("No changes between working and active configurations.\n")
			}
		case "commit":
			if !inConf {
				continue
			}
			if s.FailCommit != "" {
				out.WriteString("Commit failed: " + s.FailCommit + "\n")
				s.FailCommit = "" // one-shot, so the revert can commit
				continue
			}
			if a, r := diff(s.running, work); len(a)+len(r) == 0 {
				out.WriteString("No configuration changes to commit\n")
				continue
			}
			s.commitTo(clone(work), user, "cli")
		case "save":
			if !inConf {
				continue
			}
			if len(ts) > 1 {
				s.files[ts[1].val] = clone(work)
			} else {
				s.saved = clone(work)
			}
		case "load":
			if !inConf || len(ts) < 2 {
				continue
			}
			f := s.files[ts[1].val]
			if f == nil {
				out.WriteString("Failed to load: file not found: " + ts[1].val + "\n")
				continue
			}
			work = clone(f)
		default:
			out.WriteString("Invalid command: " + l + "\n")
		}
	}
	return out.String()
}

func (s *Server) commitTo(lines map[string]bool, user, via string) {
	s.running = lines
	s.record(user, via)
	if s.OnCommit != nil {
		s.OnCommit(s.lines(s.running))
	}
}

func diff(from, to map[string]bool) (added, removed []string) {
	for l := range to {
		if !from[l] {
			added = append(added, l)
		}
	}
	for l := range from {
		if !to[l] {
			removed = append(removed, l)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return
}

// ---- http ----

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reply := func(code int, ok bool, data any, errMsg string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		var e any
		if errMsg != "" {
			e = errMsg
		}
		json.NewEncoder(w).Encode(map[string]any{"success": ok, "data": data, "error": e})
	}
	if s.BlockHTTP != nil && s.BlockHTTP(s.lines(s.running)) {
		reply(403, false, nil, "blocked")
		return
	}
	if err := r.ParseForm(); err != nil || r.Form.Get("key") != s.APIKey {
		reply(401, false, nil, "Invalid API key")
		return
	}
	var d struct {
		Op   string   `json:"op"`
		Path []string `json:"path"`
	}
	if err := json.Unmarshal([]byte(r.Form.Get("data")), &d); err != nil {
		reply(400, false, nil, "bad data")
		return
	}
	switch r.URL.Path {
	case "/show":
		switch strings.Join(d.Path, " ") {
		case "version":
			o, _, _ := s.opCmd("show version")
			reply(200, true, o, "")
		case "system commit":
			reply(200, true, s.commitText(), "")
		default:
			reply(400, false, nil, "unsupported show")
		}
	case "/retrieve":
		prefix := tokenizeVals(d.Path)
		switch d.Op {
		case "exists":
			for l := range s.running {
				if hasPrefixVals(tokenize(l)[1:], prefix) {
					reply(200, true, true, "")
					return
				}
			}
			reply(200, true, false, "")
		case "returnValue":
			for l := range s.running {
				lt := tokenize(l)[1:]
				if hasPrefixVals(lt, prefix) && len(lt) == len(prefix)+1 {
					reply(200, true, lt[len(lt)-1].val, "")
					return
				}
			}
			reply(400, false, nil, "path is empty")
		case "showConfig":
			tree := map[string]any{}
			for l := range s.running {
				lt := tokenize(l)[1:]
				if !hasPrefixVals(lt, prefix) {
					continue
				}
				cur := tree
				for i, t := range lt[len(prefix):] {
					if i == len(lt)-len(prefix)-1 {
						cur["_value"] = t.val
						break
					}
					nx, _ := cur[t.val].(map[string]any)
					if nx == nil {
						nx = map[string]any{}
						cur[t.val] = nx
					}
					cur = nx
				}
			}
			reply(200, true, tree, "")
		default:
			reply(400, false, nil, "unsupported retrieve")
		}
	default:
		reply(404, false, nil, "no such endpoint")
	}
}

func tokenizeVals(p []string) []tok {
	var out []tok
	for _, s := range p {
		out = append(out, tok{s, s})
	}
	return out
}
