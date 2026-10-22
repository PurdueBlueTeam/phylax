package scorer

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/creds"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

// TxnState is a PCR transaction state.
type TxnState string

const (
	StatePlanned      TxnState = "planned"       // new password chosen; waiting for the quiet window
	StateHostChanged  TxnState = "host_changed"  // host(s) changed; PCR due before the next enqueue
	StatePCRSubmitted TxnState = "pcr_submitted" // portal confirmed; waiting for a passing scorer login
	StateVerified     TxnState = "verified"      // a passing scorer login by that user was observed
	StateFailed       TxnState = "failed"        // needs rollback
	StateRolledBack   TxnState = "rolled_back"   // host reverted and old value resubmitted (if it had been applied)
)

var allowed = map[TxnState][]TxnState{
	StatePlanned:      {StateHostChanged, StateRolledBack},
	StateHostChanged:  {StatePCRSubmitted, StateFailed, StateRolledBack},
	StatePCRSubmitted: {StateVerified, StateFailed},
	StateFailed:       {StateRolledBack},
}

// Terminal reports whether no further transitions happen.
func (s TxnState) Terminal() bool { return s == StateVerified || s == StateRolledBack }

// Errors.
var (
	ErrPCRPending       = errors.New("a PCR transaction for this account is pending: no further rotation until a passing scorer login is observed")
	ErrScriptedDisabled = errors.New("scripted PCR submission is off: the operator pastes the CSV (organizers must approve scripting)")
	ErrNoSubmitter      = errors.New("no PCR submitter configured")
	ErrBadState         = errors.New("transaction is not in a state that allows this")
	ErrUnknownTxn       = errors.New("unknown transaction")
	ErrNoCredlist       = errors.New("a scored account needs a credlist path: a host change without a PCR is a bug")
)

// NotInWindowError says why the quiet window is not usable.
type NotInWindowError struct{ Window Window }

func (e NotInWindowError) Error() string {
	return "not in the safe window: " + e.Window.Reason
}

// LowConfidenceError means the round clock is too uncertain to time a PCR.
type LowConfidenceError struct{ Have, Need float64 }

func (e LowConfidenceError) Error() string {
	return fmt.Sprintf("round clock confidence %.2f below %.2f", e.Have, e.Need)
}

// Interfaces to the outside world.
type (
	// HostChanger changes (and reverts) the account's password on every host
	// where the user exists. It is all-or-nothing from the engine's view.
	HostChanger interface {
		Change(ctx context.Context, account string, hosts []string, newPass vault.Secret) error
		Revert(ctx context.Context, account string, hosts []string, oldPass vault.Secret) error
	}
	// PCRSubmitter is the scripted portal path, used only when enabled.
	PCRSubmitter interface {
		Submit(ctx context.Context, credlistPath, csv string) (PCRReply, error)
	}
	// Verifier logs in with the new credential through the public path (the Kali).
	Verifier interface {
		Login(ctx context.Context, account string, pass vault.Secret) error
	}
)

// PCRConfig tunes the engine.
type PCRConfig struct {
	Scripted           bool          // scripted PCR path; default off (human pastes the CSV)
	MinWindow          time.Duration // quiet time needed to start a step (30s)
	MinConfidence      float64       // round-clock confidence needed (0.5)
	AllowLowConfidence bool          // operator override
	VerifyTimeout      time.Duration // after this without a passing login, notice (15m); never an automatic rollback
	Policy             CSVPolicy
}

// Generate makes a new password for a scored account with the shared generator.
func Generate(g *creds.Generator, account string) (vault.Secret, error) {
	return g.Generate(creds.Scored, account)
}

func (c *PCRConfig) defaults() {
	if c.MinWindow <= 0 {
		c.MinWindow = 30 * time.Second
	}
	if c.MinConfidence <= 0 {
		c.MinConfidence = 0.5
	}
	if c.VerifyTimeout <= 0 {
		c.VerifyTimeout = 15 * time.Minute
	}
}

// Transition is one state change.
type Transition struct {
	From, To TxnState
	At       time.Time
	Reason   string
}

// PlanRequest creates a transaction.
type PlanRequest struct {
	ID           string
	Account      string
	CredlistPath string // credlist path, never the display name
	Hosts        []string
	OldPass      vault.Secret
	NewPass      vault.Secret
}

// Txn is a password-rotation transaction for one scored account.
type Txn struct {
	PlanRequest
	State           TxnState
	PlannedAt       time.Time
	HostChangedAt   time.Time
	Deadline        time.Time // the quiet window's end when the host changed: PCR must land before it
	SubmittedAt     time.Time
	SubmitBurstSeq  int  // last burst at submission; only later bursts count as evidence
	Race            bool // PCR landed in/near a burst, or after the deadline: possible mixed snapshot
	Tolerated       bool // the one failed round a race can explain was forgiven
	PCRApplied      bool
	PCRUnknown      bool // submission outcome unclear: assume applied for rollback
	HostReverted    bool
	KaliOK          bool
	ScorerOK        bool
	NoticedOverdue  bool
	NoticedDeadline bool
	Reason          string
	History         []Transition
}

func (t *Txn) needPCRRollback() bool { return t.PCRApplied || t.PCRUnknown }

// Submission is one CSV block to be pasted (or submitted) for a credlist path.
type Submission struct {
	ID       string
	Path     string
	TxnIDs   []string
	Rollback bool // carries the old values
	Block    CSVBlock
	Done     bool
}

// Notice is advice for the operator or UI.
type Notice struct {
	Txn    string
	Kind   string // pcr_deadline_missed, verify_overdue
	Detail string
}

// Engine runs PCR transactions. Calls serialize on one mutex (including calls
// to the interfaces) so a transaction never has two steps in flight.
type Engine struct {
	mu   sync.Mutex
	cfg  PCRConfig
	win  WindowSource
	host HostChanger
	sub  PCRSubmitter
	ver  Verifier
	txns map[string]*Txn
	subs map[string]*Submission
	n    int
}

// NewEngine creates an engine. sub and ver may be nil.
func NewEngine(cfg PCRConfig, win WindowSource, host HostChanger, sub PCRSubmitter, ver Verifier) *Engine {
	cfg.defaults()
	cfg.Policy = cfg.Policy.withDefaults()
	return &Engine{cfg: cfg, win: win, host: host, sub: sub, ver: ver, txns: map[string]*Txn{}, subs: map[string]*Submission{}}
}

func (e *Engine) gate(now time.Time) (Window, error) {
	w := e.win.SafeFor(now, e.cfg.MinWindow)
	if !w.Safe {
		return w, NotInWindowError{w}
	}
	if w.Confidence < e.cfg.MinConfidence && !e.cfg.AllowLowConfidence {
		return w, LowConfidenceError{w.Confidence, e.cfg.MinConfidence}
	}
	return w, nil
}

func (e *Engine) move(t *Txn, to TxnState, at time.Time, reason string) {
	ok := false
	for _, s := range allowed[t.State] {
		if s == to {
			ok = true
		}
	}
	if !ok {
		panic(fmt.Sprintf("scorer: illegal PCR transition %s -> %s", t.State, to))
	}
	t.History = append(t.History, Transition{From: t.State, To: to, At: at, Reason: reason})
	t.State, t.Reason = to, reason
}

func (e *Engine) get(id string) (*Txn, error) {
	t := e.txns[id]
	if t == nil {
		return nil, ErrUnknownTxn
	}
	return t, nil
}

func (e *Engine) activeFor(account string) *Txn {
	for _, t := range e.txns {
		if t.Account == account && !t.State.Terminal() {
			return t
		}
	}
	return nil
}

// Pending reports whether the account has an unfinished transaction.
func (e *Engine) Pending(account string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.activeFor(account) != nil
}

// CanRotate is the guard every rotation path calls first.
func (e *Engine) CanRotate(account string) error {
	if e.Pending(account) {
		return ErrPCRPending
	}
	return nil
}

// Plan creates a transaction in the planned state.
func (e *Engine) Plan(req PlanRequest, now time.Time) (Txn, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if req.CredlistPath == "" {
		return Txn{}, ErrNoCredlist
	}
	if err := e.cfg.Policy.ValidateEntry(CSVEntry{req.CredlistPath, req.Account, req.NewPass.Reveal()}); err != nil {
		return Txn{}, err
	}
	if len(req.Hosts) == 0 {
		return Txn{}, errors.New("no hosts")
	}
	if e.activeFor(req.Account) != nil {
		return Txn{}, ErrPCRPending
	}
	if req.ID == "" {
		e.n++
		req.ID = fmt.Sprintf("pcr-%d", e.n)
	}
	if _, dup := e.txns[req.ID]; dup {
		return Txn{}, fmt.Errorf("duplicate transaction id %q", req.ID)
	}
	t := &Txn{PlanRequest: req, State: StatePlanned, PlannedAt: now}
	e.txns[req.ID] = t
	return *t, nil
}

// Get returns a copy of a transaction.
func (e *Engine) Get(id string) (Txn, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if t := e.txns[id]; t != nil {
		c := *t
		c.History = append([]Transition(nil), t.History...)
		return c, true
	}
	return Txn{}, false
}

// ApplyHost changes the password on the hosts. It runs only inside the safe
// window; on failure the change is reverted and the transaction rolled back.
func (e *Engine) ApplyHost(ctx context.Context, id string, now time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	t, err := e.get(id)
	if err != nil {
		return err
	}
	if t.State != StatePlanned {
		return fmt.Errorf("%w: %s", ErrBadState, t.State)
	}
	w, err := e.gate(now)
	if err != nil {
		return err
	}
	if err := e.host.Change(ctx, t.Account, t.Hosts, t.NewPass); err != nil {
		rerr := e.host.Revert(ctx, t.Account, t.Hosts, t.OldPass)
		reason := "host change failed: " + err.Error()
		if rerr != nil {
			reason += "; revert also failed: " + rerr.Error()
		}
		e.move(t, StateRolledBack, now, reason)
		return errors.New(reason)
	}
	t.HostChangedAt, t.Deadline = now, w.End
	e.move(t, StateHostChanged, now, "host password changed")
	return nil
}

// Prepare builds the CSV for the given transactions (all must have the same
// credlist path and be planned or host_changed). The operator pastes Text;
// then ConfirmSubmission is called with the portal's reply.
func (e *Engine) Prepare(ids []string) (Submission, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.prepare(ids, false)
}

func (e *Engine) prepare(ids []string, rollback bool) (Submission, error) {
	var entries []CSVEntry
	for _, id := range ids {
		t, err := e.get(id)
		if err != nil {
			return Submission{}, err
		}
		okState := t.State == StatePlanned || t.State == StateHostChanged
		if rollback {
			okState = t.State == StateFailed || t.State == StatePCRSubmitted
		}
		if !okState {
			return Submission{}, fmt.Errorf("%w: %s is %s", ErrBadState, id, t.State)
		}
		pw := t.NewPass
		if rollback {
			pw = t.OldPass
		}
		entries = append(entries, CSVEntry{t.CredlistPath, t.Account, pw.Reveal()})
	}
	blocks, err := e.cfg.Policy.GenerateCSV(entries)
	if err != nil {
		return Submission{}, err
	}
	if len(blocks) != 1 {
		return Submission{}, errors.New("one submission per credlist path: group transactions by path")
	}
	e.n++
	s := &Submission{ID: fmt.Sprintf("sub-%d", e.n), Path: blocks[0].Path, TxnIDs: append([]string(nil), ids...), Rollback: rollback, Block: blocks[0]}
	e.subs[s.ID] = s
	return *s, nil
}

// Submit sends a prepared submission through the scripted path (switch off by
// default) inside the safe window.
func (e *Engine) Submit(ctx context.Context, subID string, now time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.cfg.Scripted {
		return ErrScriptedDisabled
	}
	if e.sub == nil {
		return ErrNoSubmitter
	}
	return e.submitLocked(ctx, subID, now)
}

func (e *Engine) submitLocked(ctx context.Context, subID string, now time.Time) error {
	s := e.subs[subID]
	if s == nil || s.Done {
		return fmt.Errorf("%w: submission %s", ErrBadState, subID)
	}
	if _, err := e.gate(now); err != nil {
		return err
	}
	reply, err := e.sub.Submit(ctx, s.Path, s.Block.Text)
	if err != nil {
		// Unknown whether the portal applied it: assume it might have.
		e.markUnknown(s, now, "PCR submission error: "+err.Error())
		return err
	}
	return e.confirm(s, reply, now)
}

func (e *Engine) markUnknown(s *Submission, now time.Time, reason string) {
	for _, id := range s.TxnIDs {
		t := e.txns[id]
		if t == nil || t.State.Terminal() {
			continue
		}
		t.PCRUnknown = true
		if t.State == StateHostChanged || t.State == StatePCRSubmitted {
			e.move(t, StateFailed, now, reason)
		}
	}
}

// ConfirmSubmission records the portal's reply for a prepared submission that
// the operator pasted at time at. A mismatch (count or skipped) is an error and
// fails the affected transactions; the engine never continues past it.
func (e *Engine) ConfirmSubmission(subID string, reply PCRReply, at time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.subs[subID]
	if s == nil || s.Done {
		return fmt.Errorf("%w: submission %s", ErrBadState, subID)
	}
	return e.confirm(s, reply, at)
}

func (e *Engine) confirm(s *Submission, reply PCRReply, at time.Time) error {
	s.Done = true
	skipped := map[string]bool{}
	for _, u := range reply.Skipped {
		skipped[u] = true
	}
	ambiguous := reply.Count != s.Block.Count-len(reply.Skipped)
	verr := s.Block.VerifyReply(reply)
	for _, id := range s.TxnIDs {
		t := e.txns[id]
		if t == nil {
			continue
		}
		if s.Rollback {
			if verr == nil && t.State == StateFailed {
				e.move(t, StateRolledBack, at, "host reverted and old value resubmitted")
			}
			continue
		}
		if t.State != StateHostChanged {
			continue
		}
		switch {
		case ambiguous:
			t.PCRUnknown = true
			e.move(t, StateFailed, at, "PCR reply count mismatch: "+verr.Error())
		case skipped[t.Account]:
			e.move(t, StateFailed, at, "PCR skipped this user (unknown or wrong-case name): "+verr.Error())
		default:
			t.PCRApplied = true
			t.SubmittedAt = at
			t.SubmitBurstSeq = e.win.BurstSeqAt(at)
			t.Race = e.win.Hazard(at) || (!t.Deadline.IsZero() && at.After(t.Deadline))
			e.move(t, StatePCRSubmitted, at, "PCR accepted by the portal")
		}
	}
	return verr
}

// Verify logs in with the new credential through the public path. Once a
// Verifier is configured, verification needs both this and a passing scorer login.
func (e *Engine) Verify(ctx context.Context, id string, now time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	t, err := e.get(id)
	if err != nil {
		return err
	}
	if t.State != StatePCRSubmitted {
		return fmt.Errorf("%w: %s", ErrBadState, t.State)
	}
	if e.ver == nil {
		return errors.New("no verifier configured")
	}
	if err := e.ver.Login(ctx, t.Account, t.NewPass); err != nil {
		e.move(t, StateFailed, now, "login with the new credential failed: "+err.Error())
		return err
	}
	t.KaliOK = true
	e.maybeVerified(t, now)
	return nil
}

func (e *Engine) maybeVerified(t *Txn, now time.Time) {
	if t.State == StatePCRSubmitted && t.ScorerOK && (e.ver == nil || t.KaliOK) {
		e.move(t, StateVerified, now, "passing scorer login observed")
	}
}

// ObserveScorerLogin feeds a scorer login by account from burst burstSeq. Only
// authentication outcomes belong here (a refused connection is not a bad
// password). Returns the IDs whose state changed. A failure is forgiven once
// when the PCR landed in a race and it is the first burst after submission.
func (e *Engine) ObserveScorerLogin(account string, ok bool, burstSeq int, at time.Time) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var changed []string
	for _, id := range e.sortedTxnIDs() {
		t := e.txns[id]
		if t.Account != account || t.State != StatePCRSubmitted || burstSeq <= t.SubmitBurstSeq {
			continue
		}
		switch {
		case ok:
			t.ScorerOK = true
			before := t.State
			e.maybeVerified(t, at)
			if t.State != before {
				changed = append(changed, id)
			}
		case t.Race && !t.Tolerated && burstSeq == t.SubmitBurstSeq+1:
			t.Tolerated = true
		default:
			e.move(t, StateFailed, at, fmt.Sprintf("scorer login failed in burst %d after the PCR", burstSeq))
			changed = append(changed, id)
		}
	}
	return changed
}

func (e *Engine) sortedTxnIDs() []string {
	ids := make([]string, 0, len(e.txns))
	for id := range e.txns {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Rollback reverts the host to the old password and, if the PCR may have been
// applied, resubmits the old value (never "Reset to Defaults"). It needs the
// safe window like any other step. With the scripted path off, the returned
// Submission is the CSV the operator pastes; confirm it with ConfirmSubmission.
func (e *Engine) Rollback(ctx context.Context, id string, now time.Time) (*Submission, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	t, err := e.get(id)
	if err != nil {
		return nil, err
	}
	switch t.State {
	case StatePlanned:
		e.move(t, StateRolledBack, now, "cancelled before any change")
		return nil, nil
	case StateHostChanged, StatePCRSubmitted, StateFailed:
	default:
		return nil, fmt.Errorf("%w: %s", ErrBadState, t.State)
	}
	if _, err := e.gate(now); err != nil {
		return nil, err
	}
	if !t.HostReverted {
		if err := e.host.Revert(ctx, t.Account, t.Hosts, t.OldPass); err != nil {
			return nil, fmt.Errorf("host revert: %w", err)
		}
		t.HostReverted = true
	}
	if t.State == StatePCRSubmitted {
		e.move(t, StateFailed, now, "operator rollback")
	}
	if !t.needPCRRollback() {
		if t.State == StateHostChanged {
			e.move(t, StateFailed, now, "rollback before PCR")
		}
		e.move(t, StateRolledBack, now, "host reverted; PCR was never applied")
		return nil, nil
	}
	if t.State == StateHostChanged {
		e.move(t, StateFailed, now, "rollback with PCR in unknown state")
	}
	s, err := e.prepare([]string{id}, true)
	if err != nil {
		return nil, err
	}
	if e.cfg.Scripted && e.sub != nil {
		if err := e.submitLocked(ctx, s.ID, now); err != nil {
			return &s, err
		}
	}
	return &s, nil
}

// Tick returns operator notices. It never changes state: silence is not failure.
func (e *Engine) Tick(now time.Time) []Notice {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Notice
	for _, id := range e.sortedTxnIDs() {
		t := e.txns[id]
		switch {
		case t.State == StateHostChanged && !t.Deadline.IsZero() && now.After(t.Deadline) && !t.NoticedDeadline:
			t.NoticedDeadline = true
			out = append(out, Notice{id, "pcr_deadline_missed",
				"host changed but the PCR is not confirmed before the next round: that user's draws will fail until it lands"})
		case t.State == StatePCRSubmitted && now.Sub(t.SubmittedAt) > e.cfg.VerifyTimeout && !t.NoticedOverdue:
			t.NoticedOverdue = true
			out = append(out, Notice{id, "verify_overdue",
				"no passing scorer login for this account yet (it is drawn at random, or the check stopped); not rolling back on silence"})
		}
	}
	return out
}

// CredsState maps the transaction state onto the design's PCR state names
// stored in creds.Record.
func (t Txn) CredsState() creds.PCRState {
	switch t.State {
	case StatePlanned:
		return creds.PCRPlanned
	case StateHostChanged:
		return creds.PCRApplying
	case StatePCRSubmitted:
		if t.KaliOK || t.ScorerOK {
			return creds.PCRVerifying
		}
		return creds.PCRPending
	case StateVerified:
		return creds.PCRConfirmed
	case StateFailed:
		return creds.PCRFailed
	case StateRolledBack:
		return creds.PCRStable
	}
	return creds.PCRNone
}

// PlanForRecord plans a rotation for a scored creds.Record. The new password
// should come from Generate and be stored in the vault under rec.VaultKey() by
// the caller (as a new version) once the transaction is verified.
func (e *Engine) PlanForRecord(rec creds.Record, hosts []string, oldPass, newPass vault.Secret, now time.Time) (Txn, error) {
	if !rec.Scored {
		return Txn{}, errors.New("not a scored account: rotate directly, no PCR")
	}
	if err := rec.Validate(); err != nil {
		return Txn{}, err
	}
	return e.Plan(PlanRequest{ID: rec.VaultKey() + "@" + now.UTC().Format("20060102T150405Z"), Account: rec.Account,
		CredlistPath: rec.Credlist, Hosts: hosts, OldPass: oldPass, NewPass: newPass}, now)
}

// SyncRecord writes the transaction's state and reference into the record.
func (e *Engine) SyncRecord(id string, rec *creds.Record) error {
	t, ok := e.Get(id)
	if !ok {
		return ErrUnknownTxn
	}
	rec.PCRState, rec.PCRRef = t.CredsState(), t.ID
	return nil
}
