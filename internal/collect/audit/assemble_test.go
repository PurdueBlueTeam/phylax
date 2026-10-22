//go:build linux

package audit

import (
	"bufio"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/elastic/go-libaudit/v2/auparse"
)

// loadFixture parses an audit log fixture into messages (grouped per event by
// the caller).
func loadFixture(t *testing.T, name string) []*auparse.AuditMessage {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []*auparse.AuditMessage
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" {
			continue
		}
		m, err := auparse.ParseLogLine(l)
		if err != nil {
			t.Fatalf("%s: %v: %q", name, err, l)
		}
		out = append(out, m)
	}
	return out
}

func TestExecHexArgs(t *testing.T) {
	e, ok := Assemble(loadFixture(t, "exec_hex.log"), Limits{}).(*ExecEvent)
	if !ok {
		t.Fatal("not an ExecEvent")
	}
	if want := []string{"sh", "-c", "id; true"}; !reflect.DeepEqual(e.Argv, want) {
		t.Fatalf("argv = %q, want %q", e.Argv, want)
	}
	if e.Syscall != "execve" || !e.Success || e.Exit != 0 {
		t.Fatalf("syscall/result: %+v", e.Common)
	}
	if e.PID != 1001 || e.PPID != 1000 || e.UID != 1000 || e.AUID != 1000 || e.EUID != 1000 || e.SES != 3 || e.TTY != "pts0" {
		t.Fatalf("ids: %+v", e.Common)
	}
	if e.Exe != "/usr/bin/dash" || e.Comm != "sh" || e.Cwd != "/home/alice" || e.Key != "phylax_exec" {
		t.Fatalf("strings: %+v", e.Common)
	}
	if e.ExecPath != "/bin/sh" {
		t.Fatalf("exec path %q", e.ExecPath)
	}
	if e.Proctitle != "sh -c id; true" {
		t.Fatalf("proctitle %q", e.Proctitle)
	}
	if e.ArgvIncomplete || e.ArgvTruncated {
		t.Fatal("flags set")
	}
	if e.Time.Unix() != 1700000000 || e.Serial != 4242 {
		t.Fatalf("time/serial %v %d", e.Time, e.Serial)
	}
}

func TestExecManyArgsAcrossRecordsAndSplitArg(t *testing.T) {
	e := Assemble(loadFixture(t, "exec_many.log"), Limits{}).(*ExecEvent)
	want := []string{"printf", "%s", "aaa", "line1\nline2", "1234567890", "end"}
	if !reflect.DeepEqual(e.Argv, want) {
		t.Fatalf("argv = %q, want %q", e.Argv, want)
	}
	if e.Argc != 6 || e.ArgvIncomplete {
		t.Fatalf("argc=%d incomplete=%v", e.Argc, e.ArgvIncomplete)
	}
}

func TestExecFailed(t *testing.T) {
	e := Assemble(loadFixture(t, "exec_failed.log"), Limits{}).(*ExecEvent)
	if e.Success || e.Exit != -2 {
		t.Fatalf("success=%v exit=%d", e.Success, e.Exit)
	}
	if !reflect.DeepEqual(e.Argv, []string{"/nonexistent/tool", "--x"}) || e.ExecPath != "/nonexistent/tool" {
		t.Fatalf("argv %q path %q", e.Argv, e.ExecPath)
	}
	if e.Exe != "/usr/bin/bash" {
		t.Fatalf("exe %q: a failed exec keeps the caller's image", e.Exe)
	}
}

func TestExecWithoutExecveRecordFallsBackToProctitle(t *testing.T) {
	e := Assemble(loadFixture(t, "exec_noexecve.log"), Limits{}).(*ExecEvent)
	if !e.ArgvIncomplete || !reflect.DeepEqual(e.Argv, []string{"x", "one"}) {
		t.Fatalf("%+v", e)
	}
}

func TestExecCaps(t *testing.T) {
	e := Assemble(loadFixture(t, "exec_many.log"), Limits{MaxArgs: 3}).(*ExecEvent)
	if len(e.Argv) != 3 || !e.ArgvTruncated || e.Argc != 6 {
		t.Fatalf("max args: %q trunc=%v", e.Argv, e.ArgvTruncated)
	}
	e = Assemble(loadFixture(t, "exec_many.log"), Limits{MaxArgBytes: 4}).(*ExecEvent)
	if !e.ArgvTruncated || e.Argv[0] != "prin" {
		t.Fatalf("max arg bytes: %q trunc=%v", e.Argv, e.ArgvTruncated)
	}
	e = Assemble(loadFixture(t, "exec_many.log"), Limits{MaxArgvBytes: 10}).(*ExecEvent)
	if !e.ArgvTruncated || len(e.Argv) >= 6 {
		t.Fatalf("max argv bytes: %q", e.Argv)
	}
}

func TestExecAdversarialArgc(t *testing.T) {
	msgs := loadFixture(t, "exec_hex.log")
	for _, m := range msgs {
		if m.RecordType == auparse.AUDIT_EXECVE {
			m.RawData = strings.Replace(m.RawData, "argc=3", "argc=4294967295", 1)
		}
	}
	e := Assemble(msgs, Limits{}).(*ExecEvent)
	if !e.ArgvIncomplete || len(e.Argv) != 3 {
		t.Fatalf("expected 3 args and incomplete, got %q incomplete=%v", e.Argv, e.ArgvIncomplete)
	}
}

func TestFileCreate(t *testing.T) {
	f := Assemble(loadFixture(t, "file_create.log"), Limits{}).(*FileEvent)
	if f.Op != "create" || f.Syscall != "openat" || f.Key != "phylax_fim" {
		t.Fatalf("%+v", f)
	}
	if len(f.Paths) != 2 || f.Paths[0].Nametype != "PARENT" || f.Paths[1].Name != "/etc/cron.d/evil" || f.Paths[1].Nametype != "CREATE" {
		t.Fatalf("paths %+v", f.Paths)
	}
	if f.Exe != "/usr/bin/tee" || f.UID != 0 || f.AUID != 1000 || f.PID != 5001 || f.PPID != 900 {
		t.Fatalf("writer identity %+v", f.Common)
	}
}

func TestFileRenameAndUnsetAuid(t *testing.T) {
	f := Assemble(loadFixture(t, "file_rename.log"), Limits{}).(*FileEvent)
	if f.Op != "rename" || len(f.Paths) != 4 {
		t.Fatalf("%+v", f)
	}
	f = Assemble(loadFixture(t, "file_modify_unsetauid.log"), Limits{}).(*FileEvent)
	if f.Op != "modify" || f.AUID != -1 || f.UID != 0 || f.Paths[0].Name != "/etc/passwd" {
		t.Fatalf("%+v auid=%d", f, f.AUID)
	}
}

func TestFileHexPathAndMaxPaths(t *testing.T) {
	f := Assemble(loadFixture(t, "file_hexname.log"), Limits{}).(*FileEvent)
	if f.Paths[0].Name != "/etc/cron.d/a b" {
		t.Fatalf("hex path not decoded: %q", f.Paths[0].Name)
	}
	f = Assemble(loadFixture(t, "file_rename.log"), Limits{MaxPaths: 2}).(*FileEvent)
	if len(f.Paths) != 2 || !f.PathsTruncated {
		t.Fatalf("%+v", f)
	}
}

func TestNetConnect(t *testing.T) {
	n, ok := Assemble(loadFixture(t, "net_connect.log"), Limits{}).(*NetEvent)
	if !ok || n.Family != "ipv4" || n.Addr != "10.0.0.1" || n.Port != 8080 || n.Syscall != "connect" {
		t.Fatalf("%+v", n)
	}
}

func TestForeignEventsIgnored(t *testing.T) {
	// An auditd rule of the host (other key) writing to a file is not ours.
	msgs := loadFixture(t, "file_create.log")
	for _, m := range msgs {
		m.RawData = strings.Replace(m.RawData, `key="phylax_fim"`, `key="host_rule"`, 1)
	}
	if got := Assemble(msgs, Limits{}); got != nil {
		t.Fatalf("classified a foreign-key file event: %+v", got)
	}
}

func TestParseFieldsQuotingAndHex(t *testing.T) {
	f := parseFields(`a="x y" b=6869 c=(null) d="" e=zz`)
	if f["a"].text() != "x y" || f["b"].text() != "hi" || f["c"].text() != "" || f["d"].text() != "" || f["e"].text() != "zz" {
		t.Fatalf("%+v", f)
	}
	// An unquoted token is always encoded; a quoted one that merely looks like
	// hex is literal.
	if parseFields(`a="6869"`)["a"].text() != "6869" {
		t.Fatal("quoted hex-looking value was decoded")
	}
}
