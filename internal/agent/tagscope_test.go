package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func TestTagScopeChildAndDescendants(t *testing.T) {
	s := NewTagScope()
	s.Register("plan:p1", 100, 5000)
	if got := s.Tag("process_start", map[string]any{"pid": 101, "ppid": 100, "ppid_start": uint64(5000), "start_ticks": uint64(5001)}); got != "plan:p1" {
		t.Fatalf("child: %q", got)
	}
	if got := s.Tag("process_start", map[string]any{"pid": 102, "ppid": 101, "ppid_start": uint64(5001), "start_ticks": uint64(5002)}); got != "plan:p1" {
		t.Fatalf("grandchild: %q", got)
	}
	if got := s.Tag("file_change", map[string]any{"pid": 102, "pid_start": uint64(5002)}); got != "plan:p1" {
		t.Fatalf("file_change from a descendant: %q", got)
	}
}

// TestTagScopePidReuseIsNotTagged is the fail-closed side of R6: when the
// registration has a start time, an event that cannot prove the same process
// (missing or different start) is not tagged.
func TestTagScopePidReuseIsNotTagged(t *testing.T) {
	s := NewTagScope()
	s.Register("plan:p1", 100, 5000)
	for _, f := range []map[string]any{
		{"pid": 100},
		{"pid": 100, "pid_start": uint64(9999)},
	} {
		if got := s.Tag("file_change", f); got != "" {
			t.Errorf("%v tagged %q", f, got)
		}
	}
	// A process_start whose parent event carries no start cannot prove the
	// descent, so neither it nor its later events are tagged.
	if got := s.Tag("process_start", map[string]any{"pid": 101, "ppid": 100}); got != "" {
		t.Fatalf("unproven child: %q", got)
	}
	if got := s.Tag("file_change", map[string]any{"pid": 101}); got != "" {
		t.Fatalf("event from an unregistered child: %q", got)
	}
	// The step's own process, with its matching start, is still tagged.
	if got := s.Tag("file_change", map[string]any{"pid": 100, "pid_start": uint64(5000)}); got != "plan:p1" {
		t.Fatalf("the step's own process: %q", got)
	}
}

// A registration without a start time is the only case where a pid-only event
// matches: the platform could not read the start time when the step started.
func TestTagScopePidOnlyRegistration(t *testing.T) {
	s := NewTagScope()
	s.Register("plan:p0", 200, 0)
	for _, f := range []map[string]any{
		{"pid": 200},
		{"pid": 200, "pid_start": uint64(7)},
	} {
		if got := s.Tag("file_change", f); got != "plan:p0" {
			t.Errorf("%v: %q", f, got)
		}
	}
}

// A descendant whose own start time is unknown is tagged on its process_start
// event but not registered, so its later events cannot be mistaken for ours.
func TestTagScopeUnstartedDescendantNotRegistered(t *testing.T) {
	s := NewTagScope()
	s.Register("plan:p1", 100, 0)
	if got := s.Tag("process_start", map[string]any{"pid": 101, "ppid": 100}); got != "plan:p1" {
		t.Fatalf("the process_start itself: %q", got)
	}
	if got := s.Tag("file_change", map[string]any{"pid": 101}); got != "" {
		t.Fatalf("an unstarted descendant stayed registered: %q", got)
	}
}

func TestTagScopeIgnoresOtherProcesses(t *testing.T) {
	s := NewTagScope()
	s.Register("plan:p1", 100, 5000)
	for _, f := range []map[string]any{{"pid": 900, "ppid": 1}, {"pid": 901, "ppid": 4}, {"pid": 100, "pid_start": uint64(9999)}} {
		if got := s.Tag("process_start", f); got != "" {
			t.Errorf("%v tagged %q", f, got)
		}
	}
}

func TestTagScopeRelease(t *testing.T) {
	s := NewTagScope()
	s.Register("plan:p1", 100, 5000)
	s.Tag("process_start", map[string]any{"pid": 101, "ppid": 100, "ppid_start": uint64(5000), "start_ticks": uint64(5001)})
	s.Release("plan:p1")
	if s.Tag("file_change", map[string]any{"pid": 101, "pid_start": uint64(5001)}) != "" {
		t.Fatal("descendant still tagged after the step ended")
	}
}

// procStartTicks reads a Linux process's start time, so a test event can carry
// the same start time the executor registered for the step's child.
func procStartTicks(t *testing.T, pid int) uint64 {
	t.Helper()
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		t.Fatalf("bad /proc/%d/stat", pid)
	}
	f := strings.Fields(string(b[i+2:]))
	if len(f) < 20 {
		t.Fatalf("short /proc/%d/stat", pid)
	}
	v, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// eventPID reads a process event's pid as the link receiver decoded it (a
// JSON number arrives as float64).
func eventPID(fields map[string]any) int {
	switch v := fields["pid"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	}
	return 0
}

// tagsForPID returns the envelope tag of every spooled process_start for pid,
// in arrival order.
func tagsForPID(ctl *fakeController, pid int) []string {
	evs, _, _ := ctl.snapshot()
	var out []string
	for _, e := range evs {
		if e.Kind == event.KindProcessStart && eventPID(e.Fields) == pid {
			out = append(out, e.Tag)
		}
	}
	return out
}

// TestEmitStampsOnlyTheStepTree runs a real signed host.exec step and checks
// the emit path: the step's own child and its descendants are tagged, any
// other process on the host is not, and the tag ends with the step (R6: all
// red activity is seen; some blue may show as red, never the other way).
func TestEmitStampsOnlyTheStepTree(t *testing.T) {
	ctl, priv, r, _ := startExpiryAgent(t)
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	const planID = "tree"

	p := &plan.Plan{ID: planID, OnFailure: plan.StopDependents, Class: plan.ClassClick, Nodes: []plan.Node{{
		ID: "run", Action: "host.exec", Target: "h", Risk: plan.RiskService,
		Params: map[string]any{"argv": []any{"/bin/sh", "-c", "echo $$ > " + pidFile + "; sleep 3"}},
	}}}
	cat := plan.MapCatalog{"host.exec": {Name: "host.exec", Risk: plan.RiskService}}
	run, err := plan.NewRun(p, cat)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	run.ApprovePlan("operator", now)
	if run.State("run") == plan.StatePending {
		if err := run.ApproveNode("run", plan.Approval{By: "operator", At: now.Unix()}); err != nil {
			t.Fatal(err)
		}
	}
	sg := &plan.Signer{Key: priv, Epoch: 1, Seqs: &plan.MemSeq{}}
	step, err := sg.Issue(p, run, "run", plan.IssueOpts{Phase: plan.PhaseApply})
	if err != nil {
		t.Fatal(err)
	}
	if err := ctl.send(plan.StepToWire(step)); err != nil {
		t.Fatal(err)
	}

	var child int
	eventually(t, 10*time.Second, "the step's child to report its pid", func() bool {
		b, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		child, err = strconv.Atoi(strings.TrimSpace(string(b)))
		return err == nil && child > 0
	})
	unrelated := child + 1000000
	childStart := procStartTicks(t, child)
	emit := func(pid int, start uint64) {
		if err := r.a.emit(core(event.KindProcessStart, event.ProcessStart{PID: pid, PPID: 1, Exe: "/bin/sh", Source: "audit", StartTicks: start})); err != nil {
			t.Fatal(err)
		}
	}
	emit(child, childStart)
	emit(unrelated, 1)

	wantTag := "plan:" + planID
	eventually(t, 10*time.Second, "the step's child to reach the controller", func() bool {
		tags := tagsForPID(ctl, child)
		return len(tags) == 1 && tags[0] == wantTag
	})
	eventually(t, 10*time.Second, "the unrelated process to reach the controller", func() bool {
		tags := tagsForPID(ctl, unrelated)
		return len(tags) == 1 && tags[0] == ""
	})

	eventually(t, 10*time.Second, "the step to finish", func() bool { return len(stepResultsFor(ctl, "run")) == 1 })
	if res := stepResultsFor(ctl, "run")[0]; res.Status != plan.OutcomeApplied {
		t.Fatalf("step: %+v", res)
	}
	eventually(t, 10*time.Second, "the step's tag scope to be released", func() bool {
		return r.a.tags.Tag(event.KindProcessStart, map[string]any{"pid": child}) == ""
	})
	emit(child, childStart)
	eventually(t, 10*time.Second, "the descendant after the step ended", func() bool {
		tags := tagsForPID(ctl, child)
		return len(tags) == 2 && tags[1] == ""
	})
}
