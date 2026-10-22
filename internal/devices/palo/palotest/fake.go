// Package palotest is a stateful fake of the PAN-OS XML API for tests: one
// candidate and one running config, per-admin pending changes (the journal),
// the config lock, jobs, admin-scoped partial commit, the config log, and
// permitted-IP enforcement on new connections. It emulates the device; it
// never talks to a real one.
package palotest

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/devices/palo/xmlapi"
)

// DevicePath is the single device entry.
const DevicePath = "/config/devices/entry[@name='localhost.localdomain']"

// VsysPath is vsys1.
const VsysPath = DevicePath + "/vsys/entry[@name='vsys1']"

// PermittedIPPath is the management ACL.
const PermittedIPPath = DevicePath + "/deviceconfig/system/permitted-ip"

type jentry struct{ xpath, admin, cmd string }

type job struct {
	id, typ, result string
	details         []string
	polls, needed   int
}

type lockInfo struct{ admin, comment string }

// Server is the fake device.
type Server struct {
	*httptest.Server

	mu       sync.Mutex
	running  *xmlapi.Node
	cand     *xmlapi.Node
	keys     map[string]string // key -> admin
	passwd   map[string]string // admin -> password
	lock     *lockInfo
	journal  []jentry
	jobs     map[string]*job
	nextJob  int
	nextSeq  int
	logs     map[string][]map[string]string
	saved    map[string]*xmlapi.Node
	allowed  map[string]bool // remote addrs whose connection already passed the ACL
	sessions []xmlapi.Admin
	cfgAdmin []string
	ops      []string // log of operational/commit calls
	logJobs  map[string]logJob

	// Knobs for tests.
	FailCommit   string // commit job ends FAIL with this detail
	FailValidate string
	JobPolls     int    // polls before a job reports FIN
	Uptime       string // "0 days, 1:02:03"
	Version      string
}

// New starts a fake with an empty config and admin "admin"/"admin".
func New() *Server {
	s := &Server{
		running: &xmlapi.Node{Name: "config", Attrs: []xmlapi.Attr{{Name: "version", Value: "11.0.0"}}},
		keys:    map[string]string{}, passwd: map[string]string{}, jobs: map[string]*job{},
		logs: map[string][]map[string]string{}, saved: map[string]*xmlapi.Node{}, allowed: map[string]bool{},
		Uptime: "0 days, 1:02:03", Version: "11.0.2",
	}
	s.cand = s.running.Clone()
	s.AddAdmin("admin", "admin")
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.handle))
	return s
}

// AddAdmin creates an admin with a password and returns its API key.
func (s *Server) AddAdmin(name, pw string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.passwd[name] = pw
	key := "key-" + name
	s.keys[key] = name
	s.cfgAdmin = append(s.cfgAdmin, name)
	return key
}

// SeedRunning sets both running and candidate config from XML (<config>...</config>).
func (s *Server) SeedRunning(xml string) {
	n, err := xmlapi.ParseNode([]byte(xml))
	if err != nil {
		panic(err)
	}
	s.mu.Lock()
	s.running, s.cand = n, n.Clone()
	s.mu.Unlock()
}

// Running returns a copy of the running config.
func (s *Server) Running() *xmlapi.Node { s.mu.Lock(); defer s.mu.Unlock(); return s.running.Clone() }

// Candidate returns a copy of the candidate config.
func (s *Server) Candidate() *xmlapi.Node { s.mu.Lock(); defer s.mu.Unlock(); return s.cand.Clone() }

// Ops is the recorded op/commit command log.
func (s *Server) Ops() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.ops...)
}

// HoldLock makes admin hold the config lock.
func (s *Server) HoldLock(admin, comment string) {
	s.mu.Lock()
	s.lock = &lockInfo{admin, comment}
	s.mu.Unlock()
}

// ReleaseLock drops any config lock.
func (s *Server) ReleaseLock() { s.mu.Lock(); s.lock = nil; s.mu.Unlock() }

// LockOwner is the current config lock holder or "".
func (s *Server) LockOwner() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return ""
	}
	return s.lock.admin
}

// AddLog appends a record to the system or traffic log.
func (s *Server) AddLog(typ string, rec map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextSeq++
	if rec["seqno"] == "" {
		rec["seqno"] = strconv.Itoa(s.nextSeq)
	}
	s.logs[typ] = append(s.logs[typ], rec)
}

// SetSessions sets the live admin sessions.
func (s *Server) SetSessions(a []xmlapi.Admin) { s.mu.Lock(); s.sessions = a; s.mu.Unlock() }

// JournalLen is the number of pending changes.
func (s *Server) JournalLen() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.journal) }

// Saved reports whether a named config exists.
func (s *Server) Saved(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saved[name] != nil
}

// ---- http ----

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	typ := r.Form.Get("type")
	if typ == "keygen" {
		user, pw := r.Form.Get("user"), r.Form.Get("password")
		if p, ok := s.passwd[user]; !ok || p != pw {
			s.reply(w, 403, errResp("403", "Invalid credentials."))
			return
		}
		s.reply(w, 200, `<response status="success"><result><key>key-`+esc(user)+`</key></result></response>`)
		return
	}
	key := r.Header.Get("X-PAN-KEY")
	if key == "" {
		key = r.Form.Get("key")
	}
	admin, ok := s.keys[key]
	if !ok {
		s.reply(w, 403, errResp("403", "Invalid credentials."))
		return
	}
	if !s.connAllowed(r) {
		s.reply(w, 403, errResp("403", "Forbidden: source not in permitted IP list"))
		return
	}
	switch typ {
	case "config":
		s.doConfig(w, r, admin)
	case "op":
		s.doOp(w, r, admin)
	case "commit":
		s.doCommit(w, r, admin)
	case "log":
		s.doLog(w, r)
	case "export":
		s.reply(w, 200, string(s.running.Marshal()))
	default:
		s.reply(w, 200, errResp("17", "Unknown type"))
	}
}

// connAllowed enforces the management ACL on connections that are new since
// the ACL last allowed them; established connections keep working.
func (s *Server) connAllowed(r *http.Request) bool {
	if s.allowed[r.RemoteAddr] {
		return true
	}
	acl := s.running.Select(mustSteps(PermittedIPPath))
	ok := true
	if acl != nil && len(acl.Children) > 0 {
		ok = false
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip, err := netip.ParseAddr(host)
		if err == nil {
			for _, e := range acl.Children {
				if matchAddr(e.Attr("name"), ip) {
					ok = true
				}
			}
		}
	}
	if ok {
		s.allowed[r.RemoteAddr] = true
	}
	return ok
}

func matchAddr(spec string, ip netip.Addr) bool {
	if p, err := netip.ParsePrefix(spec); err == nil {
		return p.Contains(ip)
	}
	if a, err := netip.ParseAddr(spec); err == nil {
		return a == ip
	}
	return false
}

func (s *Server) reply(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body))
}

func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func errResp(code, msg string) string {
	return `<response status="error" code="` + code + `"><msg><line>` + esc(msg) + `</line></msg></response>`
}

func ok(result string) string {
	return `<response status="success" code="19"><result>` + result + `</result></response>`
}

func mustSteps(x string) []xmlapi.Step {
	st, err := xmlapi.ParseXPath(x)
	if err != nil {
		panic(err)
	}
	return st
}

// ---- config ----

func (s *Server) logConfig(admin, cmd, path string) {
	s.nextSeq++
	s.logs["config"] = append(s.logs["config"], map[string]string{
		"seqno": strconv.Itoa(s.nextSeq), "admin": admin, "host": "127.0.0.1", "cmd": cmd, "path": path,
		"time_generated": time.Now().UTC().Format("2006/01/02 15:04:05"),
	})
}

func (s *Server) lockedAgainst(admin string) string {
	if s.lock != nil && s.lock.admin != admin {
		return s.lock.admin
	}
	return ""
}

func (s *Server) doConfig(w http.ResponseWriter, r *http.Request, admin string) {
	action := r.Form.Get("action")
	xpath := r.Form.Get("xpath")
	switch action {
	case "get", "show":
		tree := s.cand
		if action == "show" {
			tree = s.running
		}
		steps, err := xmlapi.ParseXPath(xpath)
		if err != nil {
			s.reply(w, 200, errResp("12", err.Error()))
			return
		}
		n := tree.Select(steps)
		if n == nil {
			s.reply(w, 200, `<response status="success" code="7"><result total-count="0" count="0"/></response>`)
			return
		}
		s.reply(w, 200, `<response status="success"><result total-count="1" count="1">`+string(n.Marshal())+`</result></response>`)
	case "set", "edit", "delete":
		if who := s.lockedAgainst(admin); who != "" {
			s.reply(w, 200, errResp("15", "Config is currently locked by admin "+who))
			return
		}
		if err := s.mutate(admin, action, xpath, r.Form.Get("element")); err != nil {
			s.reply(w, 200, errResp("12", err.Error()))
			return
		}
		s.reply(w, 200, `<response status="success" code="20"><msg>command succeeded</msg></response>`)
	case "multi-config":
		if who := s.lockedAgainst(admin); who != "" {
			s.reply(w, 200, errResp("15", "Config is currently locked by admin "+who))
			return
		}
		root, err := xmlapi.ParseNode([]byte(r.Form.Get("element")))
		if err != nil || root.Name != "multi-config" {
			s.reply(w, 200, errResp("12", "bad multi-config"))
			return
		}
		backup, bj := s.cand.Clone(), append([]jentry(nil), s.journal...)
		for _, op := range root.Children {
			el := ""
			if len(op.Children) > 0 {
				var b strings.Builder
				for _, c := range op.Children {
					b.Write(c.Marshal())
				}
				el = b.String()
			}
			if err := s.mutate(admin, op.Name, op.Attr("xpath"), el); err != nil {
				if r.Form.Get("strict-transactional") == "yes" {
					s.cand, s.journal = backup, bj
				}
				s.reply(w, 200, errResp("12", err.Error()))
				return
			}
		}
		s.reply(w, 200, `<response status="success" code="20"><msg>command succeeded</msg></response>`)
	default:
		s.reply(w, 200, errResp("17", "unsupported config action "+action))
	}
}

func (s *Server) mutate(admin, action, xpath, element string) error {
	steps, err := xmlapi.ParseXPath(xpath)
	if err != nil {
		return err
	}
	switch action {
	case "set":
		frag, err := xmlapi.ParseFragment([]byte(element))
		if err != nil {
			return err
		}
		tgt := s.cand.EnsurePath(steps)
		if tgt == nil {
			return fmt.Errorf("bad xpath %s", xpath)
		}
		for _, f := range frag {
			tgt.Merge(&xmlapi.Node{Name: tgt.Name, Children: []*xmlapi.Node{f}})
		}
	case "edit":
		frag, err := xmlapi.ParseFragment([]byte(element))
		if err != nil || len(frag) != 1 {
			return fmt.Errorf("edit needs one element")
		}
		parent := s.cand.EnsurePath(steps[:len(steps)-1])
		if parent == nil {
			return fmt.Errorf("bad xpath %s", xpath)
		}
		last := steps[len(steps)-1]
		replaced := false
		for i, c := range parent.Children {
			if c.Name == last.Name && (last.Entry == "" || c.Attr("name") == last.Entry) {
				parent.Children[i] = frag[0]
				replaced = true
				break
			}
		}
		if !replaced {
			parent.Children = append(parent.Children, frag[0])
		}
	case "delete":
		parent, last := s.cand.SelectParent(steps)
		if parent == nil || !parent.Remove(last) {
			return fmt.Errorf("Object not present")
		}
	default:
		return fmt.Errorf("bad action %s", action)
	}
	s.journal = append(s.journal, jentry{xpath, admin, action})
	s.logConfig(admin, action, xpath)
	s.collapse(xpath, steps)
	return nil
}

// collapse drops journal entries for a path whose candidate equals running
// again (an edit that was undone leaves nothing to commit).
func (s *Server) collapse(xpath string, steps []xmlapi.Step) {
	c, r := s.cand.Select(steps), s.running.Select(steps)
	same := c == nil && r == nil || c != nil && r != nil && string(xmlapi.Canonical(c)) == string(xmlapi.Canonical(r))
	if !same {
		return
	}
	kept := s.journal[:0]
	for _, j := range s.journal {
		if j.xpath != xpath {
			kept = append(kept, j)
		}
	}
	s.journal = kept
}

// ---- op ----

func path(n *xmlapi.Node, names ...string) *xmlapi.Node {
	for _, nm := range names {
		if n = n.Child(nm); n == nil {
			return nil
		}
	}
	return n
}

func (s *Server) doOp(w http.ResponseWriter, r *http.Request, admin string) {
	cmd, err := xmlapi.ParseNode([]byte(r.Form.Get("cmd")))
	if err != nil {
		s.reply(w, 200, errResp("12", "bad cmd"))
		return
	}
	s.ops = append(s.ops, cmd.Name+" "+firstChain(cmd))
	switch {
	case cmd.Name == "show" && path(cmd, "system", "info") != nil:
		s.reply(w, 200, ok(`<system><hostname>fake-pa</hostname><sw-version>`+esc(s.Version)+`</sw-version><serial>0123456789</serial><uptime>`+esc(s.Uptime)+`</uptime><time>`+time.Now().UTC().Format("Mon Jan 2 15:04:05 2006")+`</time></system>`))
	case cmd.Name == "show" && path(cmd, "jobs") != nil:
		s.showJobs(w, path(cmd, "jobs"))
	case cmd.Name == "show" && path(cmd, "config-locks") != nil:
		if s.lock == nil {
			s.reply(w, 200, ok(`<config-locks/>`))
		} else {
			s.reply(w, 200, ok(`<config-locks><entry name="`+esc(s.lock.admin)+`"><type>config-lock</type><comment>`+esc(s.lock.comment)+`</comment></entry></config-locks>`))
		}
	case cmd.Name == "show" && path(cmd, "config", "list", "changes") != nil:
		var b strings.Builder
		b.WriteString("<journal>")
		for _, j := range s.journal {
			b.WriteString("<entry><xpath>" + esc(j.xpath) + "</xpath><admin>" + esc(j.admin) + "</admin><command>" + j.cmd + "</command></entry>")
		}
		b.WriteString("</journal>")
		s.reply(w, 200, ok(b.String()))
	case cmd.Name == "show" && path(cmd, "admins") != nil:
		var b strings.Builder
		b.WriteString("<admins>")
		if path(cmd, "admins", "all") != nil {
			for _, a := range s.cfgAdmin {
				b.WriteString("<entry><name>" + esc(a) + "</name></entry>")
			}
		} else {
			for _, a := range s.sessions {
				b.WriteString("<entry><admin>" + esc(a.Name) + "</admin><from>" + esc(a.From) + "</from><type>" + esc(a.Type) + "</type></entry>")
			}
		}
		b.WriteString("</admins>")
		s.reply(w, 200, ok(b.String()))
	case cmd.Name == "request" && path(cmd, "config-lock", "add") != nil:
		if s.lock != nil && s.lock.admin != admin {
			s.reply(w, 200, errResp("15", "Config for scope shared is currently locked by admin "+s.lock.admin))
			return
		}
		s.lock = &lockInfo{admin, path(cmd, "config-lock", "add").ChildText("comment")}
		s.reply(w, 200, `<response status="success"><result>Successfully acquired lock</result></response>`)
	case cmd.Name == "request" && path(cmd, "config-lock", "remove") != nil:
		if s.lock == nil || (s.lock.admin != admin) {
			s.reply(w, 200, errResp("13", "Config is not currently locked for scope shared"))
			return
		}
		s.lock = nil
		s.reply(w, 200, `<response status="success"><result>Config lock released</result></response>`)
	case cmd.Name == "validate" && path(cmd, "full") != nil:
		j := s.newJob("Validate")
		if s.FailValidate != "" {
			j.result, j.details = "FAIL", []string{s.FailValidate}
		}
		s.reply(w, 200, `<response status="success" code="19"><result><msg><line>Validate job enqueued with jobid `+j.id+`</line></msg><job>`+j.id+`</job></result></response>`)
	case cmd.Name == "save" && path(cmd, "config", "to") != nil:
		s.saved[path(cmd, "config", "to").Text] = s.cand.Clone()
		s.reply(w, 200, `<response status="success"><result>Config saved</result></response>`)
	case cmd.Name == "load" && path(cmd, "config", "from") != nil:
		name := path(cmd, "config", "from").Text
		var src *xmlapi.Node
		if name == "running-config.xml" {
			src = s.running
		} else {
			src = s.saved[name]
		}
		if src == nil {
			s.reply(w, 200, errResp("12", "no such config "+name))
			return
		}
		// A load replaces the candidate; our fake journals it as one root edit by the loader.
		s.cand = src.Clone()
		s.journal = append(s.journal, jentry{"/config", admin, "load"})
		s.logConfig(admin, "load", "/config")
		s.reply(w, 200, `<response status="success"><result>Config loaded</result></response>`)
	case cmd.Name == "test" && path(cmd, "security-policy-match") != nil:
		s.policyMatch(w, path(cmd, "security-policy-match"))
	default:
		s.reply(w, 200, errResp("17", "unsupported op "+cmd.String()))
	}
}

func firstChain(n *xmlapi.Node) string {
	out := ""
	for len(n.Children) > 0 {
		n = n.Children[0]
		out += n.Name + "/"
	}
	return out
}

// ---- jobs and commit ----

func (s *Server) newJob(typ string) *job {
	s.nextJob++
	j := &job{id: strconv.Itoa(s.nextJob), typ: typ, result: "OK", needed: s.JobPolls}
	s.jobs[j.id] = j
	return j
}

func (j *job) xml() string {
	status, res, prog := "FIN", j.result, "100"
	if j.polls < j.needed {
		status, res, prog = "ACT", "PEND", "50"
	}
	var d strings.Builder
	d.WriteString("<details>")
	for _, l := range j.details {
		d.WriteString("<line>" + esc(l) + "</line>")
	}
	d.WriteString("</details>")
	return `<job><id>` + j.id + `</id><type>` + j.typ + `</type><status>` + status + `</status><result>` + res + `</result><progress>` + prog + `</progress>` + d.String() + `</job>`
}

func (s *Server) showJobs(w http.ResponseWriter, n *xmlapi.Node) {
	if id := n.ChildText("id"); id != "" {
		j := s.jobs[id]
		if j == nil {
			s.reply(w, 200, errResp("12", "job not found"))
			return
		}
		j.polls++
		s.reply(w, 200, ok(j.xml()))
		return
	}
	var b strings.Builder
	for i := 1; i <= s.nextJob; i++ {
		if j := s.jobs[strconv.Itoa(i)]; j != nil {
			b.WriteString(j.xml())
		}
	}
	s.reply(w, 200, ok(b.String()))
}

func (s *Server) doCommit(w http.ResponseWriter, r *http.Request, admin string) {
	cmd, err := xmlapi.ParseNode([]byte(r.Form.Get("cmd")))
	if err != nil || cmd.Name != "commit" {
		s.reply(w, 200, errResp("12", "bad commit"))
		return
	}
	admins := map[string]bool{}
	scope := "plain"
	if p := cmd.Child("partial"); p != nil && p.Child("admin") != nil {
		var names []string
		for _, m := range p.Child("admin").Children {
			admins[m.Text] = true
			names = append(names, m.Text)
		}
		scope = "admins=" + strings.Join(names, ",")
	} else {
		// A plain commit publishes everyone's pending edits.
		for _, j := range s.journal {
			admins[j.admin] = true
		}
	}
	s.ops = append(s.ops, "commit action="+r.Form.Get("action")+" "+scope)
	var mine []jentry
	var rest []jentry
	for _, j := range s.journal {
		if admins[j.admin] {
			mine = append(mine, j)
		} else {
			rest = append(rest, j)
		}
	}
	if len(mine) == 0 {
		s.reply(w, 200, `<response status="success" code="19"><msg>There are no changes to commit.</msg></response>`)
		return
	}
	j := s.newJob("Commit")
	if s.FailCommit != "" {
		j.result, j.details = "FAIL", []string{s.FailCommit}
	} else {
		for _, e := range mine {
			if e.cmd == "load" {
				s.running = s.cand.Clone()
				continue
			}
			s.applyToRunning(e.xpath)
		}
		s.journal = rest
		s.logConfig(admin, "commit", "/config")
		if s.lock != nil && s.lock.admin == admin {
			s.lock = nil // PAN-OS drops the committer's lock after the commit
		}
	}
	s.reply(w, 200, `<response status="success" code="19"><result><msg><line>Commit job enqueued with jobid `+j.id+`</line></msg><job>`+j.id+`</job></result></response>`)
}

func (s *Server) applyToRunning(xpath string) {
	steps, err := xmlapi.ParseXPath(xpath)
	if err != nil {
		return
	}
	src := s.cand.Select(steps)
	if src == nil {
		if parent, last := s.running.SelectParent(steps); parent != nil {
			parent.Remove(last)
		}
		return
	}
	parent := s.running.EnsurePath(steps[:len(steps)-1])
	last := steps[len(steps)-1]
	for i, c := range parent.Children {
		if c.Name == last.Name && (last.Entry == "" || c.Attr("name") == last.Entry) {
			parent.Children[i] = src.Clone()
			return
		}
	}
	parent.Children = append(parent.Children, src.Clone())
}

// ---- logs ----

func (s *Server) doLog(w http.ResponseWriter, r *http.Request) {
	if r.Form.Get("action") == "get" {
		id := r.Form.Get("job-id")
		raw, ok2 := s.logJobs[id]
		if !ok2 {
			s.reply(w, 200, errResp("12", "no such log job"))
			return
		}
		s.reply(w, 200, `<response status="success"><result><job><id>`+id+`</id><status>FIN</status></job><log><logs count="`+strconv.Itoa(raw.n)+`">`+raw.xml+`</logs></log></result></response>`)
		return
	}
	typ := r.Form.Get("log-type")
	minSeq := 0
	if q := r.Form.Get("query"); strings.Contains(q, "seqno geq") {
		f := strings.Fields(strings.Trim(q, "() "))
		if len(f) == 3 {
			minSeq, _ = strconv.Atoi(f[2])
		}
	}
	var b strings.Builder
	n := 0
	recs := s.logs[typ]
	for i := len(recs) - 1; i >= 0; i-- { // newest first
		rec := recs[i]
		if sq, _ := strconv.Atoi(rec["seqno"]); sq < minSeq {
			continue
		}
		b.WriteString("<entry>")
		for k, v := range rec {
			b.WriteString("<" + k + ">" + esc(v) + "</" + k + ">")
		}
		b.WriteString("</entry>")
		n++
	}
	s.nextJob++
	id := strconv.Itoa(s.nextJob)
	if s.logJobs == nil {
		s.logJobs = map[string]logJob{}
	}
	s.logJobs[id] = logJob{xml: b.String(), n: n}
	s.reply(w, 200, `<response status="success" code="19"><result><msg><line>query job enqueued with jobid `+id+`</line></msg><job>`+id+`</job></result></response>`)
}

type logJob struct {
	xml string
	n   int
}

// ---- policy match ----

func (s *Server) policyMatch(w http.ResponseWriter, n *xmlapi.Node) {
	from, to := n.ChildText("from"), n.ChildText("to")
	src, dst := n.ChildText("source"), n.ChildText("destination")
	port, _ := strconv.Atoi(n.ChildText("destination-port"))
	proto, _ := strconv.Atoi(n.ChildText("protocol"))
	vsys := s.running.Select(mustSteps(VsysPath))
	name, action := "interzone-default", "deny"
	if from == to {
		name = "intrazone-default"
		action = "allow"
	}
	if vsys != nil {
		if rules := path(vsys, "rulebase", "security", "rules"); rules != nil {
			for _, e := range rules.Children {
				if members(e, "from", from) && members(e, "to", to) &&
					s.addrMatch(vsys, e, "source", src) && s.addrMatch(vsys, e, "destination", dst) &&
					s.svcMatch(vsys, e, port, proto) {
					name, action = e.Attr("name"), e.ChildText("action")
					break
				}
			}
		}
	}
	s.reply(w, 200, ok(`<rules><entry name="`+esc(name)+`"><action>`+esc(action)+`</action></entry></rules>`))
}

func members(e *xmlapi.Node, field, want string) bool {
	c := e.Child(field)
	if c == nil {
		return true
	}
	for _, m := range c.Children {
		if m.Text == "any" || m.Text == want {
			return true
		}
	}
	return false
}

func (s *Server) addrMatch(vsys, e *xmlapi.Node, field, want string) bool {
	c := e.Child(field)
	if c == nil {
		return true
	}
	ip, _ := netip.ParseAddr(want)
	for _, m := range c.Children {
		v := m.Text
		if v == "any" {
			return true
		}
		if obj := path(vsys, "address"); obj != nil {
			for _, a := range obj.Children {
				if a.Attr("name") == v && a.ChildText("ip-netmask") != "" {
					v = a.ChildText("ip-netmask")
				}
			}
		}
		if matchAddr(v, ip) {
			return true
		}
	}
	return false
}

func (s *Server) svcMatch(vsys, e *xmlapi.Node, port, proto int) bool {
	if proto == 1 { // icmp: application based
		if app := e.Child("application"); app != nil {
			for _, m := range app.Children {
				if m.Text == "any" || m.Text == "icmp" || m.Text == "ping" {
					return true
				}
			}
		}
		return false
	}
	c := e.Child("service")
	if c == nil || port == 0 {
		return true
	}
	pname := "tcp"
	if proto == 17 {
		pname = "udp"
	}
	for _, m := range c.Children {
		if m.Text == "any" {
			return true
		}
		if m.Text == "application-default" {
			return true
		}
		if svcs := path(vsys, "service"); svcs != nil {
			for _, sv := range svcs.Children {
				if sv.Attr("name") != m.Text {
					continue
				}
				if p := path(sv, "protocol", pname, "port"); p != nil && portIn(p.Text, port) {
					return true
				}
			}
		}
	}
	return false
}

func portIn(spec string, port int) bool {
	for _, part := range strings.Split(spec, ",") {
		lo, hi, isR := strings.Cut(strings.TrimSpace(part), "-")
		l, _ := strconv.Atoi(lo)
		h := l
		if isR {
			h, _ = strconv.Atoi(hi)
		}
		if port >= l && port <= h {
			return true
		}
	}
	return false
}
