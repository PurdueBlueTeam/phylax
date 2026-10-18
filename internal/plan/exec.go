package plan
import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Phase is one action phase inside a step.
type Phase string

const (
	PhaseCheck    Phase = "check"
	PhaseApply    Phase = "apply"
	PhaseVerify   Phase = "verify"
	PhaseRollback Phase = "rollback"
)

// Op distinguishes a forward step from a rollback step on the wire.
type Op string

const (
	OpRun      Op = "run"
	OpRollback Op = "rollback"
)

// NodeState is the lifecycle of one node.
type NodeState string

const (
	StPending     NodeState = "pending"
	StChecking    NodeState = "checking"
	StApplying    NodeState = "applying"
	StVerifying   NodeState = "verifying"
	StDone        NodeState = "done"
	StSkipped     NodeState = "skipped"
	StFailed      NodeState = "failed"
	StRollingBack NodeState = "rolling_back"
	StRolledBack  NodeState = "rolled_back"
)

// PlanState is the lifecycle of the whole plan.
type PlanState string

const (
	PStRunning     PlanState = "running"
	PStSuccess     PlanState = "success"
	PStDryRun      PlanState = "dry_run"
	PStRollingBack PlanState = "rolling_back"
	PStBlocked     PlanState = "blocked" // link down: paused or rollback pending
	PStRolledBack  PlanState = "rolled_back"
	PStFailed      PlanState = "failed"
)


// Step is one controller→agent dispatch.
type Step struct {
	Plan    string
	Node    string
	Op      Op
	Phase   Phase
	Action  string
	Params  map[string]any
	Before  []byte // rollback target (the captured pre-state)
	Deadman int    // seconds
}

// Result is one agent→controller phase outcome.
type Result struct {
	Node   string
	Phase  Phase
	OK     bool
	Done   bool // check already done / verify matches
	Diff   string
	Detail string
	Before []byte // state snapshot for rollback
}
type Dispatch func(host string, s Step) error


type nodeRec struct {
	node     Node
	state    NodeState
	checkRes *Result
	applied  bool   // an apply step was dispatched (rollback is needed on failure)
	failed   string // failure reason
}

type inFlight struct {
	phase Phase
	timer *time.Timer
}

type event struct {
	kind int
	node string
	res  Result
}

const (
	evResult = iota
	evDeadman
	evHostGone
	evHostBack
)

// Exec is one plan's execution on one host. One step is in flight at a
// time; all state mutates in the loop goroutine.
type Exec struct {
	host  string
	plan  *Plan
	send  Dispatch
	logf  func(format string, args ...any)
	epoch int
	dry   bool

	evCh     chan event
	done     chan struct{}
	safeMode bool

	mu        sync.Mutex
	state     PlanState
	nodes     map[string]*nodeRec
	flight    *inFlight
	flightOf  string // node id of the in-flight step, "" when none
	rollback  []string
	doneOrder []string // completed nodes, in completion order
	hostBack  bool
	finished  bool
	err       error
}

// New creates an executor for one host.
func New(host string, p *Plan, send Dispatch, logf func(string, ...any), epoch int) *Exec {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	e := &Exec{
		host:     host,
		plan:     p,
		send:     send,
		logf:     logf,
		epoch:    epoch,
		evCh:     make(chan event, 128),
		done:     make(chan struct{}),
		nodes:    map[string]*nodeRec{},
		hostBack: true,
		state:    PStRunning,
	}
	for _, n := range p.Nodes {
		e.nodes[n.ID] = &nodeRec{node: n, state: StPending}
	}
	return e
}

// SetSafeMode records the host's safe-mode flag; Start refuses when set.
func (e *Exec) SetSafeMode(on bool) { e.safeMode = on }

// Start launches the event loop. dryRun stops after the check phase.
func (e *Exec) Start(ctx context.Context, dryRun bool) error {
	if e.safeMode {
		return fmt.Errorf("plan %s: host %s is in safe mode", e.plan.Name, e.host)
	}
	if e.plan == nil || e.send == nil {
		return fmt.Errorf("plan %s: incomplete executor", e.plan.Name)
	}
	e.dry = dryRun
	go e.loop(ctx)
	return nil
}

// Result delivers an agent step outcome.
func (e *Exec) Result(node string, res Result) { e.sendEvent(event{kind: evResult, node: node, res: res}) }

// HostGone marks the link lost: the in-flight step fails and progress or
// rollback blocks until HostBack.
func (e *Exec) HostGone() { e.sendEvent(event{kind: evHostGone}) }

// HostBack resumes a blocked plan.
func (e *Exec) HostBack() { e.sendEvent(event{kind: evHostBack}) }

func (e *Exec) sendEvent(ev event) {
	select {
	case e.evCh <- ev:
	default:
		// executor is gone (finished); drop
	}
}

// Done is closed when the plan reaches a terminal state.
func (e *Exec) Done() <-chan struct{} { return e.done }

// NodeView is one node's display state.
type NodeView struct {
	ID      string
	Action  string
	State   NodeState
	Diff    string
	Failure string
}

// Snapshot is a copy of the execution state for display.
type Snapshot struct {
	State    PlanState
	Nodes    map[string]NodeView
	Rollback []string
	Err      error
}

// Status returns the current snapshot.
func (e *Exec) Status() Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := Snapshot{
		State:    e.state,
		Nodes:    map[string]NodeView{},
		Rollback: append([]string(nil), e.rollback...),
		Err:      e.err,
	}
	for id, n := range e.nodes {
		v := NodeView{ID: id, Action: n.node.Action, State: n.state, Failure: n.failed}
		if n.checkRes != nil {
			v.Diff = n.checkRes.Detail
		}
		s.Nodes[id] = v
	}
	return s
}

func (e *Exec) setLocked(st PlanState, err error) {
	e.state = st
	e.err = err
}

// loop is the single executor goroutine.
func (e *Exec) loop(ctx context.Context) {
	defer close(e.done)
	for {
		e.advance()
		if e.finished {
			return
		}
		select {
		case <-ctx.Done():
			e.cancelFlight()
			e.mu.Lock()
			e.setLocked(PStFailed, ctx.Err())
			e.finished = true
			e.mu.Unlock()
			return
		case ev := <-e.evCh:
			e.handle(ev)
		}
	}
}

// advance dispatches the next step when one is due.
func (e *Exec) advance() {
	e.mu.Lock()
	switch e.state {
	case PStRunning:
		if e.flight != nil {
			e.mu.Unlock()
			return
		}
		var next string
		for i := range e.plan.Nodes {
			id := e.plan.Nodes[i].ID
			if e.nodes[id].state != StPending || !e.depsDoneLocked(id) {
				continue
			}
			next = id
			break
		}
		if next == "" {
			st := PStSuccess
			if e.dry {
				st = PStDryRun
			}
			e.setLocked(st, nil)
			e.finished = true
			e.mu.Unlock()
			e.logf("plan %s (%s): %s", e.plan.Name, e.host, st)
			return
		}
		e.nodes[next].state = StChecking
		e.flightOf = next
		e.flight = &inFlight{phase: PhaseCheck}
		e.startTimerLocked(next)
		e.mu.Unlock()
		n := e.nodes[next]
		e.dispatch(Step{Plan: e.plan.Name, Node: next, Op: OpRun, Phase: PhaseCheck,
			Action: n.node.Action, Params: n.node.Params,
			Deadman: e.nodeDeadman(next)})
	case PStRollingBack:
		if e.flight != nil || len(e.rollback) == 0 {
			e.mu.Unlock()
			return
		}
		if !e.hostBack {
			e.setLocked(PStBlocked, nil)
			e.mu.Unlock()
			return
		}
		node := e.rollback[0]
		n := e.nodes[node]
		e.flightOf = node
		e.flight = &inFlight{phase: PhaseRollback}
		e.startTimerLocked(node)
		before := []byte(nil)
		if n != nil && n.checkRes != nil {
			before = n.checkRes.Before
		}
		e.mu.Unlock()
		e.dispatch(Step{Plan: e.plan.Name, Node: node, Op: OpRollback, Phase: PhaseRollback,
			Action: n.node.Action, Params: n.node.Params,
			Before: before, Deadman: e.nodeDeadman(node)})
	default:
		// blocked: wait for the link
		e.mu.Unlock()
	}
}

func (e *Exec) nodeDeadman(id string) int {
	d := e.nodes[id].node.Deadman
	if d <= 0 {
		return DefaultDeadman
	}
	return d
}

// dispatch sends a step off the lock (send is a network op).
func (e *Exec) dispatch(s Step) {
	e.logf("plan %s (%s): dispatch %s %s", e.plan.Name, e.host, s.Node, s.Phase)
	if err := e.send(e.host, s); err != nil {
		e.sendEvent(event{kind: evHostGone})
	}
}

func (e *Exec) depsDoneLocked(id string) bool {
	n, _ := e.plan.Node(id)
	for _, d := range n.Depends {
		if e.nodes[d].state != StDone {
			return false
		}
	}
	return true
}

// markAppliedIfLateLocked records that a step went silent in or after the
// apply phase: the change may have landed, so rollback is required.
func (e *Exec) markAppliedIfLateLocked() {
	if e.flight != nil && (e.flight.phase == PhaseApply || e.flight.phase == PhaseVerify) {
		if n := e.nodes[e.flightOf]; n != nil {
			n.applied = true
		}
	}
}
func (e *Exec) startTimerLocked(id string) {
	d := time.Duration(e.nodeDeadman(id)) * time.Second
	e.flight.timer = time.AfterFunc(d, func() {
		e.sendEvent(event{kind: evDeadman, node: id})
	})
}

func (e *Exec) cancelFlight() {
	e.mu.Lock()
	if e.flight != nil && e.flight.timer != nil {
		e.flight.timer.Stop()
	}
	e.flight = nil
	e.flightOf = ""
	e.mu.Unlock()
}

func (e *Exec) handle(ev event) {
	switch ev.kind {
	case evResult:
		e.handleResult(ev.node, ev.res)
	case evDeadman:
		e.mu.Lock()
		if e.flight == nil || e.flightOf != ev.node {
			// stale timer: the step already completed
			e.mu.Unlock()
			return
		}
		e.markAppliedIfLateLocked()
		e.flight.timer.Stop()
		e.flight = nil
		e.flightOf = ""
		e.mu.Unlock()
		e.failNode(ev.node, "deadman expired")
	case evHostGone:
		e.mu.Lock()
		e.hostBack = false
		inFlight := e.flightOf
		if e.flight != nil {
			e.markAppliedIfLateLocked()
			e.flight.timer.Stop()
			e.flight = nil
			e.flightOf = ""
		}
		rolling := e.state == PStRollingBack
		if e.state == PStRunning {
			e.setLocked(PStBlocked, nil) // pause forward progress
		}
		e.mu.Unlock()
		if inFlight != "" {
			e.failNode(inFlight, "link lost (dead-man)")
		} else if rolling {
			e.mu.Lock()
			if e.state == PStRollingBack {
				e.setLocked(PStBlocked, nil)
			}
			e.mu.Unlock()
		}
	case evHostBack:
		e.mu.Lock()
		e.hostBack = true
		if e.state == PStBlocked {
			if len(e.rollback) > 0 {
				e.setLocked(PStRollingBack, nil)
			} else {
				e.setLocked(PStRunning, nil)
			}
		}
		e.mu.Unlock()
	}
}

// handleResult applies one phase outcome to its node.
func (e *Exec) handleResult(node string, res Result) {
	e.mu.Lock()
	n := e.nodes[node]
	if n == nil || e.flight == nil || e.flightOf != node {
		e.mu.Unlock()
		return
	}
	phase := e.flight.phase
	e.flight.timer.Stop()
	e.flight = nil
	e.flightOf = ""
	e.mu.Unlock()

	switch phase {
	case PhaseCheck:
		if !res.OK {
			e.failNode(node, "check failed: "+res.Detail)
			return
		}
		e.mu.Lock()
		n.checkRes = &res
		if res.Done || e.dry {
			n.state = StDone
			e.doneOrder = append(e.doneOrder, node)
		} else {
			n.state = StApplying
			e.flightOf = node
			e.flight = &inFlight{phase: PhaseApply}
			e.startTimerLocked(node)
		}
		applyDue := !res.Done && !e.dry
		e.mu.Unlock()
		if applyDue {
			e.dispatch(Step{Plan: e.plan.Name, Node: node, Op: OpRun, Phase: PhaseApply,
				Action: n.node.Action, Params: n.node.Params,
				Deadman: e.nodeDeadman(node)})
		}
	case PhaseApply:
		e.mu.Lock()
		n.applied = true
		if res.OK {
			n.state = StVerifying
			e.flightOf = node
			e.flight = &inFlight{phase: PhaseVerify}
			e.startTimerLocked(node)
		}
		ok := res.OK
		e.mu.Unlock()
		if !ok {
			e.failNode(node, "apply failed: "+res.Detail)
			return
		}
		e.dispatch(Step{Plan: e.plan.Name, Node: node, Op: OpRun, Phase: PhaseVerify,
			Action: n.node.Action, Params: n.node.Params,
			Deadman: e.nodeDeadman(node)})
	case PhaseVerify:
		if !res.OK {
			e.failNode(node, "verify failed: "+res.Detail)
			return
		}
		e.mu.Lock()
		n.state = StDone
		e.doneOrder = append(e.doneOrder, node)
		e.mu.Unlock()
	case PhaseRollback:
		e.mu.Lock()
		if len(e.rollback) == 0 || e.rollback[0] != node {
			e.mu.Unlock()
			return
		}
		e.rollback = e.rollback[1:]
		if n != nil {
			n.state = StRolledBack
			if !res.OK {
				n.failed = "rollback failed: " + res.Detail
			}
		}
		done := len(e.rollback) == 0
		if done {
			e.setLocked(PStRolledBack, nil)
			e.finished = true
		}
		e.mu.Unlock()
		if done {
			e.logf("plan %s (%s): rollback complete", e.plan.Name, e.host)
		}
	}
}

// failNode marks the node failed, skips its dependents, and queues the
// ordered rollback. Called from the loop goroutine only.
func (e *Exec) failNode(node, reason string) {
	e.mu.Lock()
	if e.flight != nil && e.flightOf == node {
		if e.flight.timer != nil {
			e.flight.timer.Stop()
		}
		e.flight = nil
		e.flightOf = ""
	}
	n := e.nodes[node]
	if n != nil && n.state != StFailed && n.state != StRolledBack {
		n.state = StFailed
		n.failed = reason
	}
	for dep := range e.plan.Descendants(node) {
		if dn := e.nodes[dep]; dn != nil && dn.state == StPending {
			dn.state = StSkipped
		}
	}
	// a failure stops the whole plan: remaining pending nodes are skipped
	for id, dn := range e.nodes {
		if dn.state == StPending {
			dn.state = StSkipped
			e.logf("plan %s (%s): %s skipped (plan failed at %s)", e.plan.Name, e.host, id, node)
		}
	}
	// build the rollback queue only once (dry runs never applied anything)
	if e.dry {
		e.setLocked(PStFailed, fmt.Errorf("node %s: %s", node, reason))
		e.finished = true
		e.mu.Unlock()
		e.logf("plan %s (%s): %s failed: %s", e.plan.Name, e.host, node, reason)
		return
	}
	if e.state == PStRunning || e.state == PStDryRun || (e.state == PStBlocked && len(e.rollback) == 0) {
		var rq []string
		if n != nil && n.applied && n.checkRes != nil {
			rq = append(rq, node) // partially applied: restore first
		}
		for i := len(e.doneOrder) - 1; i >= 0; i-- {
			id := e.doneOrder[i]
			dn := e.nodes[id]
			if dn != nil && dn.checkRes != nil && !dn.checkRes.Done {
				rq = append(rq, id) // had a real diff: revert it
			}
		}
		e.rollback = rq
		for _, id := range rq {
			if dn := e.nodes[id]; dn != nil && dn.state == StDone {
				dn.state = StRollingBack
			}
		}
		if len(rq) > 0 {
			st := PStRollingBack
			if !e.hostBack {
				st = PStBlocked
			}
			e.setLocked(st, nil)
		} else {
			e.setLocked(PStFailed, fmt.Errorf("node %s: %s", node, reason))
			e.finished = true
		}
	}
	e.mu.Unlock()
	e.logf("plan %s (%s): %s failed: %s; rollback queue %v",
		e.plan.Name, e.host, node, reason, e.rollback)
}
