//go:build linux

package audit

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/go-libaudit/v2/auparse"
)

// Limits caps the size of one assembled event so that an attacker-controlled
// command line cannot blow up the spool.
type Limits struct {
	MaxArgs      int
	MaxArgBytes  int
	MaxArgvBytes int
	MaxPaths     int
}

func (l Limits) withDefaults() Limits {
	if l.MaxArgs <= 0 {
		l.MaxArgs = 512
	}
	if l.MaxArgBytes <= 0 {
		l.MaxArgBytes = 4096
	}
	if l.MaxArgvBytes <= 0 {
		l.MaxArgvBytes = 32768
	}
	if l.MaxPaths <= 0 {
		l.MaxPaths = 16
	}
	return l
}

// Common holds the SYSCALL-record fields shared by all event classes. IDs are
// -1 when unset (auid/ses 4294967295).
type Common struct {
	Time    time.Time
	Serial  uint32
	Syscall string
	Success bool
	Exit    int64
	PID     int
	PPID    int
	UID     int64
	GID     int64
	EUID    int64
	EGID    int64
	AUID    int64
	SES     int64
	TTY     string
	Comm    string
	Exe     string
	Cwd     string
	Key     string
}

// ExecEvent is a reassembled execve/execveat.
type ExecEvent struct {
	Common
	Argv           []string
	Argc           int
	ArgvTruncated  bool // caps hit
	ArgvIncomplete bool // EXECVE records missing or short (loss, kernel limit)
	Proctitle      string
	ExecPath       string // PATH item naming the executed file, as passed
}

// PathItem is one PATH record.
type PathItem struct {
	Name     string
	Nametype string // NORMAL, PARENT, CREATE, DELETE, UNKNOWN
	Inode    string
	Mode     string
	OUID     int64
}

// FileEvent is a watch/rule hit with its PATH records.
type FileEvent struct {
	Common
	Paths          []PathItem
	PathsTruncated bool
	Op             string // create, delete, rename, attr, modify
}

// NetEvent is a connect/accept with its SOCKADDR.
type NetEvent struct {
	Common
	Family string
	Addr   string
	Port   int
}

// rawField is one key=value token with its quoting preserved: in audit text a
// quoted value is literal and an unquoted one that looks like hex is encoded.
type rawField struct {
	val    string
	quoted bool
}

// parseFields tokenises the body of one audit record (after "audit(..): ").
// The first occurrence of a key wins.
func parseFields(body string) map[string]rawField {
	out := make(map[string]rawField, 24)
	i, n := 0, len(body)
	for i < n {
		for i < n && body[i] == ' ' {
			i++
		}
		start := i
		for i < n && body[i] != '=' && body[i] != ' ' {
			i++
		}
		if i >= n || body[i] != '=' {
			continue
		}
		key := body[start:i]
		i++ // '='
		var f rawField
		if i < n && (body[i] == '"' || body[i] == '\'') {
			q := body[i]
			j := strings.IndexByte(body[i+1:], q)
			if j < 0 {
				f = rawField{val: body[i+1:], quoted: true}
				i = n
			} else {
				f = rawField{val: body[i+1 : i+1+j], quoted: true}
				i = i + 1 + j + 1
			}
		} else {
			vs := i
			for i < n && body[i] != ' ' {
				i++
			}
			f = rawField{val: body[vs:i]}
		}
		if _, dup := out[key]; !dup && key != "" {
			out[key] = f
		}
	}
	return out
}

func bodyOf(m *auparse.AuditMessage) string {
	if i := strings.Index(m.RawData, "): "); i >= 0 {
		return m.RawData[i+3:]
	}
	return ""
}

// text decodes a field: quoted values are literal, unquoted even-length hex is
// decoded, "(null)" is empty.
func (f rawField) text() string {
	if f.quoted {
		return f.val
	}
	if f.val == "(null)" {
		return ""
	}
	if len(f.val) >= 2 && len(f.val)%2 == 0 {
		if b, err := hex.DecodeString(f.val); err == nil {
			return string(b)
		}
	}
	return f.val
}

// bytesLimited decodes like text but never allocates more than max+1 bytes.
func (f rawField) bytesLimited(max int) (s string, truncated bool) {
	if f.quoted || f.val == "(null)" || len(f.val)%2 != 0 || len(f.val) < 2 {
		s = f.text()
	} else {
		v := f.val
		if len(v) > 2*(max+1) {
			v = v[:2*(max+1)]
		}
		if b, err := hex.DecodeString(v); err == nil {
			s = string(b)
		} else {
			s = f.val
		}
	}
	if len(s) > max {
		return strings.ToValidUTF8(s[:max], "�"), true
	}
	return strings.ToValidUTF8(s, "�"), false
}

func (f rawField) i64(def int64) int64 {
	if f.val == "" || f.val == "unset" || f.val == "(null)" {
		return def
	}
	v, err := strconv.ParseInt(f.val, 10, 64)
	if err != nil {
		return def
	}
	return v
}

// idField maps the kernel's unset marker 4294967295 to -1.
func idField(f rawField, ok bool) int64 {
	if !ok {
		return -1
	}
	if f.val == "unset" {
		return -1
	}
	v, err := strconv.ParseUint(f.val, 10, 64)
	if err != nil || v == 0xFFFFFFFF {
		return -1
	}
	return int64(v)
}

func (c *Common) fromSyscall(m *auparse.AuditMessage) {
	f := parseFields(bodyOf(m))
	c.Time = m.Timestamp
	c.Serial = m.Sequence
	c.Syscall = f["syscall"].val
	if d, err := m.Data(); err == nil && d["syscall"] != "" {
		c.Syscall = d["syscall"]
	}
	c.Success = f["success"].val == "yes"
	c.Exit = f["exit"].i64(0)
	if v := f["pid"].i64(-1); v >= 0 {
		c.PID = int(v)
	}
	if v := f["ppid"].i64(-1); v >= 0 {
		c.PPID = int(v)
	}
	g := func(k string) int64 { v, ok := f[k]; return idField(v, ok) }
	c.UID, c.GID, c.EUID, c.EGID, c.AUID, c.SES = g("uid"), g("gid"), g("euid"), g("egid"), g("auid"), g("ses")
	c.TTY = f["tty"].val
	c.Comm = f["comm"].text()
	c.Exe = f["exe"].text()
	c.Key = splitKeys(f["key"])
}

// splitKeys renders the key field; multiple keys are separated by 0x01 in the
// kernel and appear hex-encoded or with \x01.
func splitKeys(f rawField) string {
	s := f.text()
	s = strings.ReplaceAll(s, "\x01", ",")
	return strings.Trim(s, `",`)
}

// Assemble turns one complete (reassembled) audit event into a typed record:
// *ExecEvent, *FileEvent, *NetEvent, or nil for events we do not classify.
func Assemble(msgs []*auparse.AuditMessage, lim Limits) any {
	lim = lim.withDefaults()
	var sys *auparse.AuditMessage
	var execve, paths, sockaddr, cwd, proctitle []*auparse.AuditMessage
	for _, m := range msgs {
		switch m.RecordType {
		case auparse.AUDIT_SYSCALL:
			if sys == nil {
				sys = m
			}
		case auparse.AUDIT_EXECVE:
			execve = append(execve, m)
		case auparse.AUDIT_PATH:
			paths = append(paths, m)
		case auparse.AUDIT_SOCKADDR:
			sockaddr = append(sockaddr, m)
		case auparse.AUDIT_CWD:
			cwd = append(cwd, m)
		case auparse.AUDIT_PROCTITLE:
			proctitle = append(proctitle, m)
		}
	}
	if sys == nil {
		return nil
	}
	var c Common
	c.fromSyscall(sys)
	if len(cwd) > 0 {
		c.Cwd, _ = parseFields(bodyOf(cwd[0]))["cwd"].bytesLimited(lim.MaxArgBytes)
	}
	switch {
	case c.Syscall == "execve" || c.Syscall == "execveat":
		return assembleExec(c, execve, paths, proctitle, lim)
	case c.Syscall == "connect" || strings.HasPrefix(c.Syscall, "accept"):
		if len(sockaddr) == 0 {
			return nil
		}
		ne := &NetEvent{Common: c}
		if d, err := sockaddr[0].Data(); err == nil {
			ne.Family, ne.Addr = d["family"], d["addr"]
			ne.Port, _ = strconv.Atoi(d["port"])
		}
		return ne
	case strings.HasPrefix(c.Key, KeyFIM) || strings.HasPrefix(c.Key, KeySelf):
		return assembleFile(c, paths, lim)
	}
	return nil
}

func assembleExec(c Common, execve, paths, proctitle []*auparse.AuditMessage, lim Limits) *ExecEvent {
	e := &ExecEvent{Common: c}
	merged := map[string]rawField{}
	for _, m := range execve {
		for k, v := range parseFields(bodyOf(m)) {
			if _, dup := merged[k]; !dup {
				merged[k] = v
			}
		}
	}
	if len(proctitle) > 0 {
		pt, _ := parseFields(bodyOf(proctitle[0]))["proctitle"].bytesLimited(lim.MaxArgBytes)
		e.Proctitle = strings.ReplaceAll(pt, "\x00", " ")
	}
	if len(paths) > 0 {
		e.ExecPath = parseFields(bodyOf(paths[0]))["name"].text()
	}
	if len(execve) == 0 {
		// No EXECVE records: fall back to the (kernel-truncated) proctitle.
		e.ArgvIncomplete = true
		if len(proctitle) > 0 {
			raw, _ := parseFields(bodyOf(proctitle[0]))["proctitle"].bytesLimited(lim.MaxArgBytes)
			e.Argv = strings.Split(strings.TrimRight(raw, "\x00"), "\x00")
		}
		return e
	}
	argc := int(merged["argc"].i64(0))
	if argc < 0 {
		argc = 0
	}
	e.Argc = argc
	n := argc
	if n > lim.MaxArgs {
		n, e.ArgvTruncated = lim.MaxArgs, true
	}
	total := 0
	for i := 0; i < n; i++ {
		key := "a" + strconv.Itoa(i)
		var arg string
		if f, ok := merged[key]; ok {
			var tr bool
			arg, tr = f.bytesLimited(lim.MaxArgBytes)
			e.ArgvTruncated = e.ArgvTruncated || tr
		} else if _, ok := merged[key+"[0]"]; ok {
			// Long argument split into a<i>[0], a<i>[1], ... chunks.
			var sb strings.Builder
			for j := 0; j < 4096; j++ {
				cf, ok := merged[fmt.Sprintf("%s[%d]", key, j)]
				if !ok {
					break
				}
				if sb.Len() > lim.MaxArgBytes {
					e.ArgvTruncated = true
					break
				}
				sb.WriteString(cf.text())
			}
			arg = sb.String()
			if len(arg) > lim.MaxArgBytes {
				arg, e.ArgvTruncated = strings.ToValidUTF8(arg[:lim.MaxArgBytes], "�"), true
			} else {
				arg = strings.ToValidUTF8(arg, "�")
			}
		} else {
			e.ArgvIncomplete = true
			break
		}
		if total += len(arg); total > lim.MaxArgvBytes {
			e.ArgvTruncated = true
			break
		}
		e.Argv = append(e.Argv, arg)
	}
	return e
}

func assembleFile(c Common, paths []*auparse.AuditMessage, lim Limits) *FileEvent {
	fe := &FileEvent{Common: c}
	for _, m := range paths {
		if len(fe.Paths) >= lim.MaxPaths {
			fe.PathsTruncated = true
			break
		}
		f := parseFields(bodyOf(m))
		name, _ := f["name"].bytesLimited(lim.MaxArgBytes)
		fe.Paths = append(fe.Paths, PathItem{
			Name: name, Nametype: f["nametype"].val, Inode: f["inode"].val,
			Mode: f["mode"].val, OUID: f["ouid"].i64(-1),
		})
	}
	fe.Op = fileOp(c.Syscall, fe.Paths)
	return fe
}

// fileOp derives the operation from PATH nametypes first (the kernel records
// CREATE/DELETE precisely) and the syscall second.
func fileOp(syscall string, ps []PathItem) string {
	var create, del bool
	for _, p := range ps {
		switch p.Nametype {
		case "CREATE":
			create = true
		case "DELETE":
			del = true
		}
	}
	switch {
	case create && del, strings.HasPrefix(syscall, "rename"):
		return "rename"
	case create:
		return "create"
	case del, syscall == "unlink", syscall == "unlinkat", syscall == "rmdir":
		return "delete"
	}
	switch {
	case strings.Contains(syscall, "chmod"), strings.Contains(syscall, "chown"),
		strings.Contains(syscall, "xattr"), strings.HasPrefix(syscall, "utime"),
		syscall == "futimesat", syscall == "setattr":
		return "attr"
	}
	return "modify"
}
