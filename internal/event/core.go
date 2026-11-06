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

type AgentDeadmanFired struct {
	ID    string `json:"id"`
	Node  string `json:"node"`
	State string `json:"state"`
	Error string `json:"error,omitempty"`
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

type EnrollRefused struct {
	Host   string `json:"host"`
	Detail string `json:"detail,omitempty"`
}

type EnrollKeyMismatch struct {
	Host   string `json:"host"`
	Detail string `json:"detail,omitempty"`
}

type EnrollKeyReuse struct {
	Host   string `json:"host"`
	Detail string `json:"detail,omitempty"`
}

// The console-script enrollment checks (R1), a locked controller after a
// restart (R8) and the controller disk quota (R9).
const (
	KindEnrollHashMismatch = "enroll.hash_mismatch"
	KindEnrollNoShow       = "enroll.no_show"
	KindControllerLocked   = "controller.locked"
	KindStoreQuota         = "store.quota"
)

// EnrollHashMismatch is raised when the agent's hello binary_sha256 differs
// from the hash of the binary the controller served.
type EnrollHashMismatch struct {
	Host     string `json:"host"`
	Served   string `json:"served"`   // sha256 hex of the served binary
	Reported string `json:"reported"` // sha256 hex the agent reported
}

// EnrollNoShow is raised when a host with a served bundle did not connect
// inside the enrollment window.
type EnrollNoShow struct {
	Host      string `json:"host"`
	WindowSec int    `json:"window_sec"`
	Since     string `json:"since"` // RFC 3339, UTC: when the bundle was written
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

type PlanStepTimeout struct {
	Host   string `json:"host"`
	Detail string `json:"detail,omitempty"`
}

type PlanBadResult struct {
	Host   string `json:"host"`
	Detail string `json:"detail,omitempty"`
}

type PlanDeadmanFired struct {
	Host   string `json:"host"`
	Detail string `json:"detail,omitempty"`
}

type PlanRollbackFailed struct {
	Host   string `json:"host"`
	Detail string `json:"detail,omitempty"`
}

type PlanRestoreFailed struct {
	Host   string `json:"host"`
	Detail string `json:"detail,omitempty"`
}

type PlanConfirmFailed struct {
	Host   string `json:"host"`
	Detail string `json:"detail,omitempty"`
}

type PlanAutoHalted struct {
	Module    string `json:"module"`
	Template  string `json:"template"`
	Host      string `json:"host"`
	Rollbacks int    `json:"rollbacks,omitempty"`
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
	Declare(Type{Kind: "agent.deadman_fired", Schema: 1, Priority: PriorityCritical, Alert: true, Fields: AgentDeadmanFired{}})
	Declare(Type{Kind: "agent.deadman_recovered", Schema: 1, Priority: PriorityHigh, Fields: AgentDeadmanRecovered{}})
	Declare(Type{Kind: "agent.deadman_recovery_error", Schema: 1, Priority: PriorityHigh, Fields: AgentDeadmanRecoveryError{}})
	Declare(Type{Kind: "agent.enrolled", Schema: 1, Priority: PriorityHigh, Fields: AgentEnrolled{}})
	Declare(Type{Kind: "agent.reenrolled", Schema: 1, Priority: PriorityHigh, Fields: AgentReenrolled{}})
	Declare(Type{Kind: "agent.silent", Schema: 1, Priority: PriorityHigh, Alert: true, Fields: AgentSilent{}})
	Declare(Type{Kind: "agent.resumed", Schema: 1, Priority: PriorityHigh, Fields: AgentResumed{}})
	Declare(Type{Kind: "spool.gap", Schema: 1, Priority: PriorityHigh, Fields: SpoolGap{}})
	Declare(Type{Kind: "enroll.refused", Schema: 1, Priority: PriorityHigh, Alert: true, Fields: EnrollRefused{}})
	Declare(Type{Kind: "enroll.key_mismatch", Schema: 1, Priority: PriorityHigh, Alert: true, Fields: EnrollKeyMismatch{}})
	Declare(Type{Kind: "enroll.key_reuse", Schema: 1, Priority: PriorityHigh, Alert: true, Fields: EnrollKeyReuse{}})
	Declare(Type{Kind: "plan.step_timeout", Schema: 1, Priority: PriorityHigh, Fields: PlanStepTimeout{}})
	Declare(Type{Kind: "plan.bad_result", Schema: 1, Priority: PriorityHigh, Fields: PlanBadResult{}})
	Declare(Type{Kind: "plan.deadman_fired", Schema: 1, Priority: PriorityCritical, Alert: true, Fields: PlanDeadmanFired{}})
	Declare(Type{Kind: "plan.rollback_failed", Schema: 1, Priority: PriorityCritical, Alert: true, Fields: PlanRollbackFailed{}})
	Declare(Type{Kind: "plan.restore_failed", Schema: 1, Priority: PriorityCritical, Alert: true, Fields: PlanRestoreFailed{}})
	Declare(Type{Kind: "plan.confirm_failed", Schema: 1, Priority: PriorityCritical, Alert: true, Fields: PlanConfirmFailed{}})
	Declare(Type{Kind: "plan.auto_halted", Schema: 1, Priority: PriorityCritical, Alert: true, Fields: PlanAutoHalted{}})
	Declare(Type{Kind: KindEnrollHashMismatch, Schema: 1, Priority: PriorityCritical, Alert: true, Fields: EnrollHashMismatch{}})
	Declare(Type{Kind: KindEnrollNoShow, Schema: 1, Priority: PriorityHigh, Alert: true, Fields: EnrollNoShow{}})
	Declare(Type{Kind: KindControllerLocked, Schema: 1, Priority: PriorityCritical, Alert: true, Fields: ControllerLocked{}})
	Declare(Type{Kind: KindStoreQuota, Schema: 1, Priority: PriorityHigh, Alert: true, Fields: StoreQuota{}})
}
