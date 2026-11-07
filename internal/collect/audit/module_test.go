//go:build linux

package audit

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	libaudit "github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/elastic/go-libaudit/v2/rule"
	"github.com/elastic/go-libaudit/v2/rule/flags"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

type collector struct {
	mu sync.Mutex
	ev []event.Event
}

func (c *collector) emit(e event.Event) error {
	c.mu.Lock()
	c.ev = append(c.ev, e)
	c.mu.Unlock()
	return nil
}
func (c *collector) all() []event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]event.Event(nil), c.ev...)
}
func (c *collector) kind(k string) []event.Event {
	var out []event.Event
	for _, e := range c.all() {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testModule(t *testing.T, mut func(*Config)) (*Module, *collector) {
	t.Helper()
	cfg := Config{NoRules: true, Logger: quietLog(), ProcRoot: t.TempDir(), selfPID: 4242424}
	if mut != nil {
		mut(&cfg)
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := &collector{}
	m.emit = c.emit
	return m, c
}

// fakeProc writes a minimal /proc entry.
func fakeProc(t *testing.T, root string, pid, ppid int, start uint64, exe, comm, cmdline string) {
	t.Helper()
	d := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	stat := fmt.Sprintf("%d (%s) S %d 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 %d 1000 1 0", pid, comm, ppid, start)
	os.WriteFile(filepath.Join(d, "stat"), []byte(stat), 0o644)
	os.WriteFile(filepath.Join(d, "comm"), []byte(comm+"\n"), 0o644)
	os.WriteFile(filepath.Join(d, "cmdline"), []byte(strings.ReplaceAll(cmdline, " ", "\x00")+"\x00"), 0o644)
	os.WriteFile(filepath.Join(d, "cgroup"), []byte("0::/system.slice/ssh.service\n"), 0o644)
	if exe != "" {
		os.Symlink(exe, filepath.Join(d, "exe"))
	}
}

func TestProcessStartEvent(t *testing.T) {
	m, c := testModule(t, nil)
	root := m.cfg.ProcRoot
	os.WriteFile(filepath.Join(root, "stat"), []byte("btime 1600000000\n"), 0o644)
	// Parent started well before the event; child pid is gone.
	fakeProc(t, root, 1000, 1, 5000, "/usr/bin/bash", "bash", "-bash")
	m.handle(loadFixture(t, "exec_hex.log"))
	evs := c.kind(KindProcessStart)
	if len(evs) != 1 {
		t.Fatalf("got %d process_start events (%d total)", len(evs), len(c.all()))
	}
	e := evs[0]
	if e.Priority != event.PriorityHigh || e.Time.Unix() != 1700000000 {
		t.Fatalf("prio/time: %v %v", e.Priority, e.Time)
	}
	f := e.Fields
	argv, _ := f["argv"].([]string)
	if len(argv) != 3 || argv[2] != "id; true" || f["cmdline"] != "sh -c id; true" {
		t.Fatalf("argv %v", f["argv"])
	}
	for k, want := range map[string]any{"pid": 1001, "ppid": 1000, "uid": int64(1000), "auid": int64(1000), "euid": int64(1000),
		"ses": int64(3), "tty": "pts0", "exe": "/usr/bin/dash", "image": "/usr/bin/dash", "cwd": "/home/alice",
		"success": true, "pexe": "/usr/bin/bash", "pcomm": "bash", "source": "audit"} {
		if f[k] != want {
			t.Errorf("field %s = %v (%T), want %v", k, f[k], f[k], want)
		}
	}
	par := f["parent"].(map[string]any)
	if par["exe"] != "/usr/bin/bash" || par["cmdline"] != "-bash" || par["start_ticks"] != uint64(5000) {
		t.Fatalf("parent %v", par)
	}
}

func TestParentFromCacheAfterExit(t *testing.T) {
	m, c := testModule(t, nil)
	// No /proc entry for pid 1000 at all: the parent exited. An earlier exec
	// event of that pid is in the cache.
	m.procs.Remember(ProcInfo{PID: 1000, Exe: "/usr/sbin/sshd", Comm: "sshd", Cmdline: "sshd: alice"})
	m.handle(loadFixture(t, "exec_hex.log"))
	f := c.kind(KindProcessStart)[0].Fields
	if f["pexe"] != "/usr/sbin/sshd" || f["parent"].(map[string]any)["live"] != false {
		t.Fatalf("parent %v", f["parent"])
	}
}

func TestPidReuseNotTrusted(t *testing.T) {
	m, c := testModule(t, nil)
	root := m.cfg.ProcRoot
	os.WriteFile(filepath.Join(root, "stat"), []byte("btime 1700000000\n"), 0o644)
	// pid 1000 now belongs to a process that started 1000 s *after* the event.
	fakeProc(t, root, 1000, 1, 100000, "/usr/bin/evil", "evil", "evil")
	m.procs.Remember(ProcInfo{PID: 1000, Exe: "/usr/bin/bash", Comm: "bash"})
	m.handle(loadFixture(t, "exec_hex.log"))
	f := c.kind(KindProcessStart)[0].Fields
	if f["pexe"] != "/usr/bin/bash" {
		t.Fatalf("reused pid's /proc data leaked into the event: %v", f["parent"])
	}
}

func TestOwnProcessAndPathsExcluded(t *testing.T) {
	m, c := testModule(t, func(cfg *Config) {
		cfg.selfPID = 1001 // exec_hex.log's pid
		cfg.ExcludePaths = []string{"/etc/cron.d"}
	})
	m.handle(loadFixture(t, "exec_hex.log"))
	if len(c.all()) != 0 {
		t.Fatalf("agent's own exec was reported: %v", c.all())
	}
	// File event under an excluded path: dropped.
	m.handle(loadFixture(t, "file_create.log"))
	if len(c.all()) != 0 {
		t.Fatalf("excluded path reported: %v", c.all())
	}
	// File event from the agent's own pid: dropped even on a watched path.
	m2, c2 := testModule(t, func(cfg *Config) { cfg.selfPID = 5201 })
	m2.handle(loadFixture(t, "file_modify_unsetauid.log"))
	if len(c2.all()) != 0 {
		t.Fatal("own write reported")
	}
	if m.Status().OwnDropped != 2 || m2.Status().OwnDropped != 1 {
		t.Fatalf("own_dropped %d %d", m.Status().OwnDropped, m2.Status().OwnDropped)
	}
	// Same path from another process is reported (exclusion is not by name).
	m3, c3 := testModule(t, nil)
	m3.handle(loadFixture(t, "file_modify_unsetauid.log"))
	if len(c3.kind(KindFileChange)) != 1 {
		t.Fatal("foreign write not reported")
	}
}

func TestFileChangeEvent(t *testing.T) {
	m, c := testModule(t, nil)
	m.handle(loadFixture(t, "file_rename.log"))
	f := c.kind(KindFileChange)[0].Fields
	if f["op"] != "rename" || f["path"] != "/etc/passwd" || f["old_path"] != "/etc/passwd.new" {
		t.Fatalf("%v", f)
	}
	if f["exe"] != "/usr/bin/mv" || f["pid"] != 5001 || f["uid"] != int64(0) || f["auid"] != int64(1000) {
		t.Fatalf("writer identity missing: %v", f)
	}
	m.handle(loadFixture(t, "file_create.log"))
	f = c.kind(KindFileChange)[1].Fields
	if f["op"] != "create" || f["path"] != "/etc/cron.d/evil" || f["exe"] != "/usr/bin/tee" {
		t.Fatalf("%v", f)
	}
	if c.kind(KindFileChange)[0].Priority != event.PriorityCritical {
		t.Fatal("file_change must be critical priority")
	}
}

func TestNetEvent(t *testing.T) {
	m, c := testModule(t, nil)
	m.handle(loadFixture(t, "net_connect.log"))
	f := c.kind(KindNetConnect)[0].Fields
	if f["addr"] != "10.0.0.1" || f["port"] != 8080 || f["direction"] != "outbound" {
		t.Fatalf("%v", f)
	}
}

// reassembly through the real go-libaudit Reassembler: interleaved events and
// a missing sequence number.
func TestReassemblyInterleavedAndGap(t *testing.T) {
	m, c := testModule(t, nil)
	ra, err := libaudit.NewReassembler(16, 50*time.Millisecond, reasm{m})
	if err != nil {
		t.Fatal(err)
	}
	a := loadFixture(t, "exec_hex.log")    // serial 4242
	b := loadFixture(t, "exec_many.log")   // serial 4300
	d := loadFixture(t, "file_create.log") // serial 5000
	// Interleave record by record, then a gap: serials 4242, 4300, 5000 are
	// far apart, so the reassembler sees them as in-order events only if each
	// completes; add records of a new event after a skipped sequence.
	for i := 0; i < 8; i++ {
		for _, set := range [][]*auparse.AuditMessage{a, b, d} {
			if i < len(set) {
				ra.PushMessage(set[i])
			}
		}
	}
	ra.Close()
	if n := len(c.kind(KindProcessStart)); n != 2 {
		t.Fatalf("process_start events: %d", n)
	}
	if n := len(c.kind(KindFileChange)); n != 1 {
		t.Fatalf("file_change events: %d", n)
	}
}

func TestSequenceGapBecomesTelemetryGap(t *testing.T) {
	m, c := testModule(t, nil)
	ra, _ := libaudit.NewReassembler(8, 20*time.Millisecond, reasm{m})
	mk := func(seq int) []*auparse.AuditMessage {
		var out []*auparse.AuditMessage
		for _, l := range []string{
			fmt.Sprintf(`type=SYSCALL msg=audit(1700000100.000:%d): arch=c000003e syscall=59 success=yes exit=0 items=0 ppid=1 pid=%d auid=0 uid=0 gid=0 euid=0 tty=(none) ses=1 comm="x" exe="/bin/x" key="phylax_exec"`, seq, seq),
			fmt.Sprintf(`type=EOE msg=audit(1700000100.000:%d): `, seq),
		} {
			msg, err := auparse.ParseLogLine(l)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, msg)
		}
		return out
	}
	for _, seq := range []int{100, 101, 105, 106} { // 102-104 never arrive
		for _, msg := range mk(seq) {
			ra.PushMessage(msg)
		}
	}
	time.Sleep(60 * time.Millisecond)
	ra.Maintain()
	ra.Close()
	m.flushGaps(true)
	gaps := c.kind(KindGap)
	if len(gaps) != 1 {
		t.Fatalf("gap events: %v", c.all())
	}
	g := gaps[0].Fields
	if g["source"] != "audit" || g["reason"] != "sequence_gap" || g["count"].(uint64) < 3 {
		t.Fatalf("gap: %v", g)
	}
	if len(c.kind(KindProcessStart)) != 4 {
		t.Fatalf("delivered %d events", len(c.kind(KindProcessStart)))
	}
	if m.Status().SeqLost < 3 {
		t.Fatalf("status seq_lost %d", m.Status().SeqLost)
	}
}

func TestRateLimitReportsGap(t *testing.T) {
	m, c := testModule(t, func(cfg *Config) { cfg.RatePerSec, cfg.Burst = 1, 3 })
	for i := 0; i < 10; i++ {
		m.handle(loadFixture(t, "exec_hex.log"))
	}
	m.flushGaps(true)
	if n := len(c.kind(KindProcessStart)); n != 3 {
		t.Fatalf("passed %d events through a burst of 3", n)
	}
	g := c.kind(KindGap)
	if len(g) != 1 || g[0].Fields["reason"] != "rate_limited" || g[0].Fields["count"].(uint64) != 7 {
		t.Fatalf("gap: %v", g)
	}
	if m.Status().RateDropped != 7 {
		t.Fatalf("rate_dropped %d", m.Status().RateDropped)
	}
}

func TestTokenBucketRefills(t *testing.T) {
	b := newBucket(10, 2)
	now := time.Unix(100, 0)
	if !b.allow(now) || !b.allow(now) || b.allow(now) {
		t.Fatal("burst")
	}
	if !b.allow(now.Add(150 * time.Millisecond)) {
		t.Fatal("refill")
	}
}

// ---- rule set and hash verification against an in-memory kernel ----

type fakeKernel struct {
	mu      sync.Mutex
	rules   [][]byte
	status  libaudit.AuditStatus
	refuse  bool
	enabled bool
}

func (k *fakeKernel) GetStatus() (*libaudit.AuditStatus, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	s := k.status
	return &s, nil
}
func (k *fakeKernel) GetRules() ([][]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([][]byte, len(k.rules))
	for i, r := range k.rules {
		out[i] = append([]byte(nil), r...)
	}
	return out, nil
}
func (k *fakeKernel) AddRule(r []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.refuse {
		return fmt.Errorf("operation not permitted (audit locked)")
	}
	for _, e := range k.rules {
		if bytes.Equal(e, r) {
			return fmt.Errorf("rule exists")
		}
	}
	k.rules = append(k.rules, append([]byte(nil), r...))
	return nil
}
func (k *fakeKernel) DeleteRule(r []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	for i, e := range k.rules {
		if bytes.Equal(e, r) {
			k.rules = append(k.rules[:i], k.rules[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("no such rule")
}
func (k *fakeKernel) SetEnabled(on bool, _ libaudit.WaitMode) error {
	k.mu.Lock()
	k.enabled = on
	if on {
		k.status.Enabled = 1
	}
	k.mu.Unlock()
	return nil
}
func (k *fakeKernel) Close() error { return nil }

func allExist(string) (bool, bool) { return true, true }

func guardedModule(t *testing.T) (*Module, *collector, *fakeKernel, *guard) {
	t.Helper()
	m, c := testModule(t, func(cfg *Config) {
		cfg.NoRules = false
		cfg.WebRoots = []string{"/var/www/html"}
		cfg.SelfPaths = []string{"/usr/local/bin/phylax"}
	})
	rs, err := NewRuleSet(BuildRuleLines(&m.cfg, allExist))
	if err != nil {
		t.Fatal(err)
	}
	m.rs = rs
	k := &fakeKernel{status: libaudit.AuditStatus{Enabled: 1, PID: 77}}
	g, err := newGuard(k, rs, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	return m, c, k, g
}

func TestRuleLinesParseAndCoverRequiredPaths(t *testing.T) {
	cfg := Config{WebRoots: []string{"/var/www"}, SelfPaths: []string{"/usr/local/bin/phylax"}, NetRules: true}
	cfg.defaults()
	lines := BuildRuleLines(&cfg, allExist)
	if _, err := NewRuleSet(lines); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(lines, "\n")
	for _, want := range []string{
		"-S execve,execveat -k phylax_exec", "-S connect,accept,accept4", "dir=/etc/sudoers.d", "dir=/etc/pam.d",
		"dir=/etc/systemd/system", "dir=/var/spool/cron", "dir=/etc/ssh/sshd_config.d", "dir=/var/www", "dir=/etc/cron.d",
		"dir=/usr/local/bin/phylax -F perm=wa -k phylax_self",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("rule set lacks %q", want)
		}
	}
	// Non-existent file whose parent exists is still watched (ld.so.preload).
	lines = BuildRuleLines(&cfg, func(p string) (bool, bool) {
		if p == "/etc/ld.so.preload" {
			return false, false
		}
		return true, true
	})
	found := false
	for _, l := range lines {
		if l == "-w /etc/ld.so.preload -p wa -k phylax_fim" {
			found = true
		}
	}
	if !found {
		t.Error("ld.so.preload not watched when absent")
	}
	// Absent parent: skipped rather than failing the whole install.
	lines = BuildRuleLines(&cfg, func(p string) (bool, bool) { return false, false })
	for _, l := range lines {
		if strings.Contains(l, "-w ") || strings.Contains(l, "dir=") {
			t.Errorf("watch emitted for missing path: %s", l)
		}
	}
}

func TestReconcileInstallsAndHashIsStable(t *testing.T) {
	_, _, k, g := guardedModule(t)
	// A foreign rule (auditd's) must survive reconcile untouched.
	foreign := mustWire(t, "-w /etc/hosts -p w -k hostrule")
	k.AddRule(foreign)
	rep, err := g.Reconcile()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Failed) != 0 || rep.Installed != len(g.want) || rep.Foreign != 1 {
		t.Fatalf("%+v", rep)
	}
	rep2, changed, err := g.Verify()
	if err != nil || changed || rep2.Hash != rep.Hash {
		t.Fatalf("verify after install: changed=%v err=%v", changed, err)
	}
	// Reconcile is idempotent.
	rep3, _ := g.Reconcile()
	if rep3.Hash != rep.Hash || rep3.Repaired {
		t.Fatalf("second reconcile changed things: %+v", rep3)
	}
	raw, _ := k.GetRules()
	hasForeign := false
	for _, r := range raw {
		hasForeign = hasForeign || bytes.Equal(r, foreign)
	}
	if !hasForeign {
		t.Fatal("foreign rule was removed")
	}
}

func mustWire(t *testing.T, line string) []byte {
	t.Helper()
	r, err := flags.Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	wf, err := rule.Build(r)
	if err != nil {
		t.Fatal(err)
	}
	return wf
}

func TestFlushedRulesDetectedReinstalledAndReported(t *testing.T) {
	m, c, k, g := guardedModule(t)
	rep, _ := g.Reconcile()
	baseline := rep.Hash
	// `auditctl -D`
	k.mu.Lock()
	k.rules = nil
	k.mu.Unlock()
	m.verifyOnce(k, g, nil, true)
	evs := c.kind(KindRulesChanged)
	if len(evs) != 1 {
		t.Fatalf("events: %v", c.all())
	}
	f := evs[0].Fields
	if f["expected_hash"] != baseline || f["actual_hash"] == baseline || f["repaired"] != true || f["missing_count"] != len(g.want) {
		t.Fatalf("%v", f)
	}
	if !strings.Contains(f["reason"].(string), "rules_changed") || evs[0].Priority != event.PriorityCritical {
		t.Fatalf("reason/priority: %v", f)
	}
	raw, _ := k.GetRules()
	if v := ClassifyKernelRules(raw); HashLines(v.Ours) != baseline {
		t.Fatal("rules not restored to the baseline hash")
	}
	// Quiet on the next tick.
	m.verifyOnce(k, g, nil, true)
	if len(c.kind(KindRulesChanged)) != 1 {
		t.Fatal("repeated event for a repaired state")
	}
	if !m.Status().RulesOK {
		t.Fatal("status not ok after repair")
	}
}

func TestSingleRuleDeletedAndNeverRuleAndDisabled(t *testing.T) {
	m, c, k, g := guardedModule(t)
	g.Reconcile()
	k.mu.Lock()
	k.rules = k.rules[1:] // an attacker deletes one rule
	k.mu.Unlock()
	m.verifyOnce(k, g, nil, true)
	f := c.kind(KindRulesChanged)[0].Fields
	if f["missing_count"] != 1 {
		t.Fatalf("%v", f)
	}
	// A foreign `-a never,task` appears: reported, not removed.
	k.AddRule(mustWire(t, "-a never,task"))
	k.mu.Lock()
	k.status.Enabled = 0
	k.mu.Unlock()
	m.verifyOnce(k, g, nil, true)
	evs := c.kind(KindRulesChanged)
	if len(evs) != 2 {
		t.Fatalf("events: %d", len(evs))
	}
	r := evs[1].Fields["reason"].(string)
	if !strings.Contains(r, "never_rule") || !strings.Contains(r, "audit_disabled") {
		t.Fatalf("reason %q", r)
	}
	if !k.enabled {
		t.Fatal("audit not re-enabled")
	}
	if m.Status().NeverRules != 1 {
		t.Fatalf("status %+v", m.Status())
	}
}

func TestKernelLostCounterBecomesGap(t *testing.T) {
	m, c, k, g := guardedModule(t)
	g.Reconcile()
	m.verifyOnce(k, g, nil, true)
	k.mu.Lock()
	k.status.Lost = 17
	k.mu.Unlock()
	m.verifyOnce(k, g, nil, true)
	m.flushGaps(true)
	gs := c.kind(KindGap)
	if len(gs) != 1 || gs[0].Fields["reason"] != "kernel_lost" || gs[0].Fields["count"].(uint64) != 17 {
		t.Fatalf("%v", c.all())
	}
}

func TestInstallFailureReported(t *testing.T) {
	_, _, k, g := guardedModule(t)
	k.refuse = true // `-e 2`: kernel refuses rule changes
	rep, err := g.Reconcile()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Failed) != len(g.want) || rep.Installed != 0 {
		t.Fatalf("%d failed, %d installed", len(rep.Failed), rep.Installed)
	}
}

func TestStartRunsAgainstControlClient(t *testing.T) {
	// Full Start path minus the reader socket is covered by the Docker test;
	// here we only check that Start fails cleanly when the kernel refuses.
	m, _ := testModule(t, nil)
	m.openControl = func() (kernelControl, error) { return nil, fmt.Errorf("denied") }
	if err := m.Start(context.Background(), func(event.Event) error { return nil }); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("err = %v", err)
	}
}

func TestWrappedSequenceGapCountsAsOneInexact(t *testing.T) {
	m, c := testModule(t, nil)
	reasm{m}.EventsLost(1<<32 - 1)
	m.flushGaps(true)
	gaps := c.kind(KindGap)
	if len(gaps) != 1 || gaps[0].Fields["count"] != uint64(1) || gaps[0].Fields["count_exact"] != false {
		t.Fatalf("gaps: %+v", gaps)
	}
}
