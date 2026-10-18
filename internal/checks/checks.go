// Package checks implements the platform's active checks (docs: Active
// checks and check discovery): a live, editable list of the platform's own
// end-to-end tests of each scored service. The checker runs every active
// check from its vantage point — the controller or a check_runner agent in a
// segment — on the check's interval (default 60s, 30–60s in production).
//
// Each check is one typed probe of one service:
//
//	http  params: url
//	      expected: status (int), content_sha256 (hex of the normalized
//	      body: trailing whitespace trimmed, optional strip_re list of Go
//	      regexes applied to the body before hashing so injects that change
//	      e.g. timestamps do not flap the check)
//	smtp  params: smtp_host, from, to, subject, body, mailbox_host,
//	      mail_user, mail_pass
//	      expected: subject (string) — the check sends the mail via SMTP,
//	      then retrieves the newest message from the mailbox over POP3 and
//	      compares its Subject header
//	dns   params: server, name, qtype (name or number, default A)
//	      expected: answers ([]string, set equality)
//	ftp   params: host, user, pass, path
//	      expected: list_sha256 (hex of the LIST output normalized: each
//	      line trimmed of trailing whitespace, sorted, joined with \n)
//	tftp  params: host, file
//	      expected: sha256 (hex of the fetched file; minimal RRQ client,
//	      512-byte blocks, 3s exchange timeout, 3 retries)
//	ntp   params: server
//	      expected: reachable (bool, default true) — minimal mode-3
//	      client; Actual also carries offset_ms
//	tcp   params: host (host:port, default port 80)
//	      expected: banner_re (Go regex, unanchored) — connect, read up to
//	      1 KiB for up to 2s; Actual.banner is the first 200 bytes,
//	      truncated at a NUL or the first non-printable byte
//
// Hosts are "host" or "host:port"; the default port per type is: smtp 25,
// pop3 110, dns 53, ftp 21, tftp 69, ntp 123, tcp 80.
//
// Behavior (docs: Active checks):
//
//   - A check turns red after exactly 2 consecutive failures (per
//     check+vantage); a success resets the counter. Sink.Red fires once, on
//     the transition only, after Sink.Result for the same run.
//   - Each run gets the per-check timeout (default 10s, see Timeout). A
//     panicking executor is recorded as a failure with Detail "panic: …";
//     it never takes the checker down.
//   - The scheduler runs each due check in its own goroutine; a check that
//     is still running when it comes due again is skipped (not queued).
//   - A checker only runs checks whose Vantages include the checker's own
//     vantage, or checks with an empty Vantages list (all vantages).
//   - AcceptCurrent(id) resets Expected to the last successful Actual: the
//     "accept current response" action after a legitimate change.
//   - Results per check are kept newest-first, capped at 50.
package checks

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const (
	// StateActive, StatePaused and StateRetired are the Check.State values.
	StateActive  = "active"
	StatePaused  = "paused"
	StateRetired = "retired"

	// DefaultInterval is the per-check interval when Check.Interval is 0.
	DefaultInterval = 60 * time.Second
	// DefaultTimeout is the per-check timeout when Timeout is not set.
	DefaultTimeout = 10 * time.Second
	// maxResults is the per-check result history cap (newest first).
	maxResults = 50

	schedTick = 25 * time.Millisecond
)

// Check is one active check (docs: Active checks).
type Check struct {
	ID       string         `json:"id"`
	Service  string         `json:"service"`
	Type     string         `json:"type"` // http|smtp|dns|ftp|tftp|ntp|tcp
	Params   map[string]any `json:"params"`
	Expected map[string]any `json:"expected"`
	Interval time.Duration  `json:"interval"` // 0 = checker default (60s)
	Vantages []string       `json:"vantages"` // "controller", "segment:<name>"
	Origin   string         `json:"origin"`   // manifest|discovered|manual
	State    string         `json:"state"`    // active|paused|retired
}

// Result is one run of a check from one vantage point.
type Result struct {
	CheckID string         `json:"check"`
	Vantage string         `json:"vantage"`
	TS      time.Time      `json:"ts"`
	OK      bool           `json:"ok"`
	Detail  string         `json:"detail,omitempty"` // human diff on failure
	Actual  map[string]any `json:"actual,omitempty"` // observed values
}

// Sink receives results; Red fires on the transition to red (2 consecutive
// failures from the same vantage), not on every failing run.
type Sink interface {
	Result(r Result)
	Red(r Result)
}

// Checker runs checks from one vantage point.
type Checker struct {
	vantage string
	timeout time.Duration
	wake    chan struct{}

	mu     sync.Mutex
	sink   Sink
	nextID int
	checks map[string]*entry
	order  []string
}

// entry is the mutable per-check scheduler state.
type entry struct {
	Check
	running bool
	fails   int // consecutive failures since the last success
	nextRun time.Time
	lastOK  map[string]any
	results []Result // newest first
}

func (e *entry) interval() time.Duration {
	if e.Interval > 0 {
		return e.Interval
	}
	return DefaultInterval
}

func (e *entry) vantageMatch(v string) bool {
	if len(e.Vantages) == 0 {
		return true
	}
	for _, want := range e.Vantages {
		if want == v {
			return true
		}
	}
	return false
}

// NewChecker returns a checker for the given vantage ("controller" or
// "segment:<name>").
func NewChecker(vantage string) *Checker {
	return &Checker{
		vantage: vantage,
		timeout: DefaultTimeout,
		wake:    make(chan struct{}, 1),
		checks:  make(map[string]*entry),
	}
}

// SetSink installs the result sink; a nil sink disables reporting.
func (c *Checker) SetSink(s Sink) {
	c.mu.Lock()
	c.sink = s
	c.mu.Unlock()
}

func (c *Checker) signalWake() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Upsert adds or replaces a check; a replaced check activates. An empty ID
// is assigned "ck-<n>". An empty State means active.
func (c *Checker) Upsert(ck Check) {
	now := time.Now()
	c.mu.Lock()
	if ck.ID == "" {
		c.nextID++
		ck.ID = fmt.Sprintf("ck-%d", c.nextID)
	}
	if ck.State == "" {
		ck.State = StateActive
	}
	e, ok := c.checks[ck.ID]
	if ok {
		// Replace: the replaced check activates and runs again soon;
		// result history is kept, the failure counter restarts.
		ck.State = StateActive
		e.Check = ck
		e.fails = 0
		e.running = false
		e.nextRun = now
	} else {
		e = &entry{Check: ck, nextRun: now}
		c.checks[ck.ID] = e
		c.order = append(c.order, ck.ID)
	}
	c.mu.Unlock()
	c.signalWake()
}

// Pause stops an active check from running (state paused).
func (c *Checker) Pause(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.checks[id]
	if !ok {
		return fmt.Errorf("checks: unknown check %q", id)
	}
	if e.State != StateActive {
		return fmt.Errorf("checks: check %q is %s, not active", id, e.State)
	}
	e.State = StatePaused
	e.fails = 0
	c.signalWake()
	return nil
}

// Retire marks an active or paused check retired; it stays in the list but
// does not run.
func (c *Checker) Retire(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.checks[id]
	if !ok {
		return fmt.Errorf("checks: unknown check %q", id)
	}
	if e.State != StateActive && e.State != StatePaused {
		return fmt.Errorf("checks: check %q is %s, not active or paused", id, e.State)
	}
	e.State = StateRetired
	e.fails = 0
	c.signalWake()
	return nil
}

// Activate resumes a paused or retired check.
func (c *Checker) Activate(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.checks[id]
	if !ok {
		return fmt.Errorf("checks: unknown check %q", id)
	}
	if e.State != StatePaused && e.State != StateRetired {
		return fmt.Errorf("checks: check %q is %s, not paused or retired", id, e.State)
	}
	e.State = StateActive
	e.fails = 0
	e.nextRun = time.Now()
	c.signalWake()
	return nil
}

// Remove deletes a check from the list. A run already in flight is
// discarded.
func (c *Checker) Remove(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.checks[id]; !ok {
		return fmt.Errorf("checks: unknown check %q", id)
	}
	delete(c.checks, id)
	for i, id2 := range c.order {
		if id2 == id {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
	return nil
}

// AcceptCurrent sets the check's Expected to its last successful Actual
// (docs: "accept current response" after a legitimate change).
func (c *Checker) AcceptCurrent(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.checks[id]
	if !ok {
		return fmt.Errorf("checks: unknown check %q", id)
	}
	if e.lastOK == nil {
		return fmt.Errorf("checks: check %q has no successful result yet", id)
	}
	cp := make(map[string]any, len(e.lastOK))
	for k, v := range e.lastOK {
		cp[k] = v
	}
	e.Expected = cp
	c.signalWake()
	return nil
}

// List returns the checks in insertion order (shallow copies).
func (c *Checker) List() []Check {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Check, 0, len(c.order))
	for _, id := range c.order {
		out = append(out, c.checks[id].Check)
	}
	return out
}

// Results returns the check's result history, newest first, capped at 50.
func (c *Checker) Results(id string) []Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.checks[id]
	if !ok {
		return nil
	}
	out := make([]Result, len(e.results))
	copy(out, e.results)
	return out
}

// Timeout sets the per-check timeout (0 or negative restores the 10s
// default).
func (c *Checker) Timeout(d time.Duration) {
	c.mu.Lock()
	if d > 0 {
		c.timeout = d
	} else {
		c.timeout = DefaultTimeout
	}
	c.mu.Unlock()
}

// Run schedules checks until ctx is done. It never panics out.
func (c *Checker) Run(ctx context.Context) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("checks: scheduler panic: %v", p)
		}
	}()
	ticker := time.NewTicker(schedTick)
	defer ticker.Stop()
	for {
		c.tick(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.wake:
		case <-ticker.C:
		}
	}
}

// tick spawns one goroutine per due, runnable check.
func (c *Checker) tick(ctx context.Context) {
	now := time.Now()
	c.mu.Lock()
	var spawn []struct {
		id string
		ck Check
	}
	for _, id := range c.order {
		e := c.checks[id]
		if e.State != StateActive || !e.vantageMatch(c.vantage) {
			continue
		}
		if now.Before(e.nextRun) {
			continue
		}
		if e.running {
			// Overlap: skip this run (not queued).
			e.nextRun = now.Add(e.interval())
			continue
		}
		e.running = true
		e.nextRun = now.Add(e.interval())
		spawn = append(spawn, struct {
			id string
			ck Check
		}{id, e.Check})
	}
	c.mu.Unlock()
	for _, s := range spawn {
		go c.run(ctx, s.id, s.ck)
	}
}

// run executes one check (timeout + panic recovery), records the result and
// fires the sink.
func (c *Checker) run(ctx context.Context, id string, ck Check) {
	defer func() {
		c.mu.Lock()
		if e, ok := c.checks[id]; ok {
			e.running = false
		}
		c.mu.Unlock()
	}()

	var res Result
	func() {
		defer func() {
			if p := recover(); p != nil {
				res = Result{CheckID: id, Vantage: c.vantage, TS: time.Now(), OK: false, Detail: fmt.Sprintf("panic: %v", p)}
			}
		}()
		c.mu.Lock()
		timeout := c.timeout
		c.mu.Unlock()
		runCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		actual, err := execute(runCtx, ck)
		res = Result{CheckID: id, Vantage: c.vantage, TS: time.Now(), Actual: actual}
		switch {
		case err != nil:
			res.Detail = err.Error()
		default:
			if detail := compare(ck, actual); detail != "" {
				res.Detail = detail
			} else {
				res.OK = true
			}
		}
	}()

	c.record(id, res)
}

// record appends the result, updates the failure counter and fires the
// sink outside the lock.
func (c *Checker) record(id string, res Result) {
	var red bool
	c.mu.Lock()
	e, ok := c.checks[id]
	if !ok {
		// Removed while running: drop the result.
		c.mu.Unlock()
		return
	}
	e.results = append([]Result{res}, e.results...)
	if len(e.results) > maxResults {
		e.results = e.results[:maxResults]
	}
	if res.OK {
		e.fails = 0
		e.lastOK = res.Actual
	} else {
		e.fails++
		red = e.fails == 2
	}
	sink := c.sink
	c.mu.Unlock()

	if sink == nil {
		return
	}
	sink.Result(res)
	if red {
		sink.Red(res)
	}
}
