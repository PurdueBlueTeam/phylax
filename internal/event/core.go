package event

import "time"

// ControllerFact is the controller's signed control: fact payload and the
// controller.fact event payload.
type ControllerFact struct {
	ID   string         `json:"id"`
	Fact string         `json:"fact"` // subtype
	TS   time.Time      `json:"ts"`   // controller clock, display only
	TTL  time.Duration  `json:"ttl"`  // counted from the agent's receipt
	Data map[string]any `json:"data,omitempty"`
}

type AgentStart struct {
	Version string   `json:"version,omitempty"`
	OS      string   `json:"os,omitempty"`
	Arch    string   `json:"arch,omitempty"`
	Roles   []string `json:"roles,omitempty"`
}

type AgentHealth struct {
	Spool   map[string]any `json:"spool,omitempty"`
	Modules map[string]any `json:"modules,omitempty"`
	Link    map[string]any `json:"link,omitempty"`
}

type AgentStep struct {
	Plan   string `json:"plan"`
	Node   string `json:"node"`
	Phase  string `json:"phase"`
	Action string `json:"action,omitempty"`
	Epoch  uint64 `json:"epoch,omitempty"`
	Seq    uint64 `json:"seq,omitempty"`
}

type AgentStepResult struct {
	Plan    string `json:"plan"`
	Node    string `json:"node"`
	Host    string `json:"host,omitempty"`
	Phase   string `json:"phase"`
	Outcome string `json:"outcome"`
	Error   string `json:"error,omitempty"`
	Class   string `json:"class,omitempty"`
}

type AgentStepRefused struct {
	Plan   string `json:"plan"`
	Node   string `json:"node"`
	Phase  string `json:"phase"`
	Reason string `json:"reason"`
}

type EvidenceBlob struct {
	Alert  string `json:"alert"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Name   string `json:"name,omitempty"`
	Chunks int    `json:"chunks,omitempty"`
}

type AgentConfigApplied struct {
	Epoch   uint64            `json:"epoch"`
	Version uint64            `json:"version"`
	State   string            `json:"state"`
	Modules map[string]string `json:"modules,omitempty"`
}

type AgentConfigRejected struct {
	Version uint64 `json:"version,omitempty"`
	Epoch   uint64 `json:"epoch,omitempty"`
	Reason  string `json:"reason"`
}

type AgentControlRefused struct {
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
	Epoch  uint64 `json:"epoch,omitempty"`
	Seq    uint64 `json:"seq,omitempty"`
}

type AgentModuleCrash struct {
	Module      string `json:"module"`
	Error       string `json:"error"`
	RestartInMS int64  `json:"restart_in_ms,omitempty"`
}

type AgentDeadmanRecovered struct {
	ID    string `json:"id"`
	Node  string `json:"node"`
	State string `json:"state"`
	Error string `json:"error,omitempty"`
}

type AgentDeadmanRecoveryError struct {
	Error string `json:"error"`
}

type AgentEnrolled struct {
	Host     string `json:"host"`
	KeyHash  string `json:"key_hash"`
	Manifest string `json:"manifest,omitempty"`
}

type AgentReenrolled struct {
	Host     string `json:"host"`
	KeyHash  string `json:"key_hash"`
	Manifest string `json:"manifest,omitempty"`
}

type AgentSilent struct {
	Host   string `json:"host"`
	Detail string `json:"detail,omitempty"`
}

type AgentResumed struct {
	Host   string `json:"host"`
	Detail string `json:"detail,omitempty"`
}

type SpoolGap struct {
	From  uint64 `json:"from"`
	To    uint64 `json:"to"`
	Count uint64 `json:"count"`
	Class string `json:"class"`
}

// The one plan-failure kind and the one enrollment-alert kind carry a reason;
// the design's kind table makes each event's priority decide the alert row.
// A locked controller after a restart (R8) and the controller disk quota (R9)
// keep their own kinds.
const (
	KindPlanFailed           = "plan.failed"
	KindEnrollAlert          = "enroll.alert"
	KindOperatorEdit         = "operator.edit"
	KindInventorySnapshot    = "inventory.snapshot"
	KindInventoryRow         = "inventory.row"
	KindInventoryProbeResult = "inventory.probe_result"
	KindControllerLocked     = "controller.locked"
	KindStoreQuota           = "store.quota"
)

// The reason values of plan.failed and enroll.alert (design: Event kinds).
const (
	ReasonDeadmanFired   = "deadman_fired"
	ReasonAutoHalted     = "auto_halted"
	ReasonRollbackFailed = "rollback_failed"
	ReasonRestoreFailed  = "restore_failed"
	ReasonConfirmFailed  = "confirm_failed"
	ReasonStepTimeout    = "step_timeout"
	ReasonBadResult      = "bad_result"

	ReasonRefused      = "refused"
	ReasonHashMismatch = "hash_mismatch"
	ReasonNoShow       = "no_show"
	ReasonKeyMismatch  = "key_mismatch"
	ReasonKeyReuse     = "key_reuse"
)

// PlanFailed is the one failure kind of a plan node or an automatic action
// (design: Event kinds). Reason says which failure it was.
type PlanFailed struct {
	Reason   string `json:"reason"`
	Host     string `json:"host"`
	Detail   string `json:"detail,omitempty"`
	Plan     string `json:"plan,omitempty"`
	Node     string `json:"node,omitempty"`
	Module   string `json:"module,omitempty"`
	Template string `json:"template,omitempty"`
	Count    int    `json:"count,omitempty"`
}

// EnrollAlert is the one enrollment-alert kind (design: Event kinds). Reason
// is refused, hash_mismatch, no_show, key_mismatch or key_reuse; the served
// and reported hashes belong to hash_mismatch, the window to no_show.
type EnrollAlert struct {
	Reason    string `json:"reason"`
	Host      string `json:"host"`
	Detail    string `json:"detail,omitempty"`
	Served    string `json:"served,omitempty"`     // sha256 hex of the served binary
	Reported  string `json:"reported,omitempty"`   // sha256 hex the agent reported
	WindowSec int    `json:"window_sec,omitempty"` // no_show: the enrollment window
	Since     string `json:"since,omitempty"`      // RFC 3339, UTC: when the bundle was written
}

// OperatorEdit is the one command-event kind (design: Event kinds): an
// operator action that changes what a module's table holds. Record is the
// full new value, never a diff.
type OperatorEdit struct {
	Module  string `json:"module"`
	Op      string `json:"op"`
	Subject string `json:"subject,omitempty"`
	Record  any    `json:"record,omitempty"`
	By      string `json:"by"`
	At      string `json:"at"`
}

// The core inventory kinds (design: Event kinds).
type InventorySnapshot struct {
	Table       string           `json:"table"`
	Schema      int              `json:"schema"`
	Epoch       uint64           `json:"epoch"`
	Reason      string           `json:"reason"` // baseline | epoch_change | periodic | requested
	Rows        []map[string]any `json:"rows,omitempty"`
	Part        int              `json:"part,omitempty"`
	Parts       int              `json:"parts,omitempty"`
	Count       int              `json:"count,omitempty"`
	CollectedAt string           `json:"collected_at"`
}

type InventoryRow struct {
	Table       string         `json:"table"`
	Epoch       uint64         `json:"epoch"`
	Op          string         `json:"op"` // added | removed | changed | overflow
	Key         string         `json:"key"`
	Row         map[string]any `json:"row,omitempty"`
	Old         map[string]any `json:"old,omitempty"`
	ChangedCols []string       `json:"changed_cols,omitempty"`
	Count       int            `json:"count,omitempty"` // overflow
	CollectedAt string         `json:"collected_at"`
}

type InventoryProbeResult struct {
	Probe       string           `json:"probe"`
	Params      map[string]any   `json:"params,omitempty"`
	Host        string           `json:"host"`
	Columns     []string         `json:"columns,omitempty"`
	Rows        []map[string]any `json:"rows,omitempty"`
	Truncated   bool             `json:"truncated,omitempty"`
	CollectedAt string           `json:"collected_at"`
	Live        bool             `json:"live,omitempty"`
}

// ControllerLocked is raised while plan signing is locked after a restart.
type ControllerLocked struct {
	Since   string   `json:"since"`             // RFC 3339, UTC
	Stopped []string `json:"stopped,omitempty"` // what is not running
}

// StoreQuota is raised when the controller disk crosses a quota level.
type StoreQuota struct {
	Level   string   `json:"level"` // "ok", "bulk", "evidence", "critical"
	UsedPct int      `json:"used_pct"`
	Shed    []string `json:"shed,omitempty"` // classes now refused
}

// The core kinds: what the agent, the spool and the controller emit about
// themselves rather than about the host. A module that emits core kinds is a
// core module (health, exec). Alert is a rule's verdict for the common kinds;
// for these the design's kind table marks the failures a human must see.
func init() {
	Declare(Type{Kind: "agent.start", Schema: 1, Priority: PriorityHigh, Fields: AgentStart{}})
	Declare(Type{Kind: "agent.health", Schema: 1, Priority: PriorityNormal, Fields: AgentHealth{}})
	Declare(Type{Kind: "agent.step", Schema: 1, Priority: PriorityHigh, Fields: AgentStep{}})
	Declare(Type{Kind: "agent.step_result", Schema: 1, Priority: PriorityHigh, Fields: AgentStepResult{}})
	Declare(Type{Kind: "agent.step_refused", Schema: 1, Priority: PriorityHigh, Fields: AgentStepRefused{}})
	Declare(Type{Kind: "evidence.blob", Schema: 1, Priority: PriorityHigh, Fields: EvidenceBlob{}})
	Declare(Type{Kind: "agent.config_applied", Schema: 1, Priority: PriorityHigh, Fields: AgentConfigApplied{}})
	Declare(Type{Kind: "agent.config_rejected", Schema: 1, Priority: PriorityHigh, Fields: AgentConfigRejected{}})
	Declare(Type{Kind: "agent.control_refused", Schema: 1, Priority: PriorityHigh, Fields: AgentControlRefused{}})
	Declare(Type{Kind: "agent.module_crash", Schema: 1, Priority: PriorityHigh, Fields: AgentModuleCrash{}})
	Declare(Type{Kind: "controller.fact", Schema: 1, Priority: PriorityHigh, Fields: ControllerFact{}})
	Declare(Type{Kind: "agent.deadman_recovered", Schema: 1, Priority: PriorityHigh, Fields: AgentDeadmanRecovered{}})
	Declare(Type{Kind: "agent.deadman_recovery_error", Schema: 1, Priority: PriorityHigh, Fields: AgentDeadmanRecoveryError{}})
	Declare(Type{Kind: "agent.enrolled", Schema: 1, Priority: PriorityHigh, Fields: AgentEnrolled{}})
	Declare(Type{Kind: "agent.reenrolled", Schema: 1, Priority: PriorityHigh, Fields: AgentReenrolled{}})
	Declare(Type{Kind: "agent.silent", Schema: 1, Priority: PriorityHigh, Alert: true, Fields: AgentSilent{}})
	Declare(Type{Kind: "agent.resumed", Schema: 1, Priority: PriorityHigh, Fields: AgentResumed{}})
	Declare(Type{Kind: "spool.gap", Schema: 1, Priority: PriorityHigh, Fields: SpoolGap{}})
	Declare(Type{Kind: KindPlanFailed, Schema: 1, Priority: PriorityCritical, Alert: true, Fields: PlanFailed{}})
	Declare(Type{Kind: KindEnrollAlert, Schema: 1, Priority: PriorityHigh, Alert: true, Fields: EnrollAlert{}})
	Declare(Type{Kind: KindOperatorEdit, Schema: 1, Priority: PriorityNormal, Fields: OperatorEdit{}})
	Declare(Type{Kind: KindInventorySnapshot, Schema: 1, Priority: PriorityBulk, Fields: InventorySnapshot{}})
	Declare(Type{Kind: KindInventoryRow, Schema: 1, Priority: PriorityNormal, Fields: InventoryRow{}})
	Declare(Type{Kind: KindInventoryProbeResult, Schema: 1, Priority: PriorityNormal, Fields: InventoryProbeResult{}})
	Declare(Type{Kind: KindControllerLocked, Schema: 1, Priority: PriorityCritical, Alert: true, Fields: ControllerLocked{}})
	Declare(Type{Kind: KindStoreQuota, Schema: 1, Priority: PriorityHigh, Alert: true, Fields: StoreQuota{}})
}
