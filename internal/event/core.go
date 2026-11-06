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
