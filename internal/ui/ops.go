package ui

import (
	"context"
	"errors"
	"time"
)

// The operator pages are built on Ops, implemented by the controller. All
// string fields may be attacker controlled (host names, alert text, process
// names); templates escape them.

// Errors an Ops implementation returns for operator mistakes; handlers show
// them as such instead of a 500.
var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict") // wrong state for that action
	ErrInvalid  = errors.New("invalid")  // bad input
)

// Ops is everything the operator pages read and do. Actions take the
// operator name (already authenticated) so the controller can record who
// approved what.
type Ops interface {
	Overview(ctx context.Context) (OpsDashboard, error)

	// Modules lists every module's health for the Platform page: each agent's
	// modules from their heartbeats and the controller's own modules, with the
	// modules not yet on the contract marked.
	Modules(ctx context.Context) []ModuleRow

	AgentDetail(ctx context.Context, host string) (AgentDetail, error)
	SetSafeMode(ctx context.Context, host string, on bool, by string) error
	// ReenableAuto clears the attempt ledger's breaker for one key.
	ReenableAuto(ctx context.Context, host, object, kind, by string) error

	Alerts(ctx context.Context, state string) ([]AlertRow, error)
	Alert(ctx context.Context, id int64) (AlertDetail, error)
	// TraceAlert builds (or finds) the attack chain for the alert and returns
	// its id.
	TraceAlert(ctx context.Context, id int64, by string) (chainID int64, err error)
	SetAlertState(ctx context.Context, id int64, state, by string) error

	Chains(ctx context.Context) ([]CampaignView, error)
	Chain(ctx context.Context, id int64) (ChainView, error)

	Templates(ctx context.Context) ([]TemplateInfo, error)
	CreatePlan(ctx context.Context, template, planID, by string) (string, error)
	Proposals(ctx context.Context) ([]ProposalRow, error)
	AcceptProposal(ctx context.Context, id int64, by string) (string, error)
	DismissProposal(ctx context.Context, id int64, by string) error
	Plans(ctx context.Context) ([]PlanBrief, error)
	Plan(ctx context.Context, id string) (PlanView, error)
	DryRun(ctx context.Context, id string) error
	ApprovePlan(ctx context.Context, id, by string) error
	ApproveNode(ctx context.Context, id, node, by, note string) error
	Apply(ctx context.Context, id, by string) error
	Rollback(ctx context.Context, id, by string) error
}

// OpsDashboard is the data of the one-screen dashboard.
type OpsDashboard struct {
	Agents      AgentSummary
	OpenAlerts  int
	AlertsBySev []SevCount
	Awaiting    []PlanBrief // plans waiting for an approval
	Scorer      *ScorerView // nil: no scorer data
	Chains      []ChainBrief
	Campaigns   []CampaignBrief
	Health      []string
}

// AgentSummary counts agents and lists them for the dashboard.
type AgentSummary struct {
	Total, Connected, Silent int
	SafeMode                 int
	Rows                     []AgentRow
}

// AgentRow is one agent line.
type AgentRow struct {
	Host       string
	State      string // connected, silent, disconnected
	Config     string // config state reported by the agent
	ConfigVer  uint64
	SpoolDepth uint64
	SafeMode   bool
	LastSeen   time.Time
}

// SevCount is the number of open alerts of a severity.
type SevCount struct {
	Severity string
	Count    int
}

// ScorerView is the round clock and SLA streaks.
type ScorerView struct {
	Round      string // e.g. "round 41, next burst in 3m10s"
	Confidence string
	Lines      []string
	Services   []SLARow
}

// SLARow is one service's SLA state.
type SLARow struct {
	Service   string
	Streak    int
	Penalties int
	Level     string // ok, warn, critical
}

// ChainBrief is one chain in a summary.
type ChainBrief struct {
	ID         int64
	Hosts      string
	Hops       int
	Confidence string
	Created    time.Time
}

// CampaignBrief summarises a campaign.
type CampaignBrief struct {
	ID     int64
	Name   string
	Chains int
	Last   time.Time
}

// AgentDetail is the per-host page.
type AgentDetail struct {
	Host          string
	Known         bool
	State         string
	Connected     bool
	Silent        bool
	LastSeen      time.Time
	ClockSkew     time.Duration
	SkewAt        time.Time
	ConfigState   string
	ConfigEpoch   uint64
	ConfigVersion uint64
	SafeMode      bool
	SpoolDepth    uint64
	Congestion    string
	Drops         uint64
	Acked         uint64
	Modules       []KV
	Gaps          []GapRow
	LastEvents    int64
}

// KV is a name/value pair.
type KV struct{ Key, Value string }

// GapRow is a telemetry gap.
type GapRow struct {
	From, To uint64
	Reason   string
	Class    string
	Count    uint64
	Time     time.Time
}

// AlertRow is one queue row.
type AlertRow struct {
	ID       int64
	Time     time.Time
	Severity string
	Rule     string
	Title    string
	Host     string
	State    string
	ChainID  int64
}

// AlertDetail is the evidence view of one alert.
type AlertDetail struct {
	AlertRow
	Message  string
	Entities []KV
	Evidence []EvidenceRow
	// Keys is the raw JSON key document.
	Keys string
}

// EvidenceRow is one referenced event.
type EvidenceRow struct {
	Agent string
	Seq   uint64
	Time  time.Time
	Kind  string
	Body  string // compact JSON of the event fields
}

// CampaignView groups chains for the Chains page.
type CampaignView struct {
	ID                int64
	Name              string
	First             time.Time
	Last              time.Time
	Chains            []ChainBrief
	Sources, Accounts []string
}

// ChainView is the timeline of one chain (a table, not a graph).
type ChainView struct {
	ID         int64
	CampaignID int64
	Confidence string
	Truncated  bool
	Notes      []string
	Rows       []TimelineRow
}

// TimelineRow is one hop.
type TimelineRow struct {
	Ord       int
	Cause     int
	Local     string
	UTC       string
	Host      string
	Kind      string
	What      string
	Technique string
	Method    string
	Level     string
	Guess     bool
	Notes     []string
	Evidence  []string // "agent#seq"
	Items     []ItemRow
}

// ItemRow is a remediation item.
type ItemRow struct {
	Text     string
	State    string
	Verified bool
}

// TemplateInfo is a plan template file.
type TemplateInfo struct {
	Name, Title string
	Nodes       int
}

// ProposalRow is one open one-click plan suggestion.
type ProposalRow struct {
	ID       int64
	Module   string
	Title    string
	Template string
	Params   map[string]string
	Evidence []string // "agent:seq"
	Reason   string
	Created  time.Time
	State    string
	PlanID   string
	By       string
}

// PlanBrief is a plan list row.
type PlanBrief struct {
	ID      string
	Name    string
	State   string
	By      string
	Created time.Time
	// Pending lists nodes waiting for their own approval.
	Pending []string
	Waiting string // what the plan waits for, "" when nothing
}

// PlanView is the plan page: DAG as a table with live node states.
type PlanView struct {
	PlanBrief
	OnFailure                                    string
	Hash                                         string
	HasDryRun                                    bool
	Approvable                                   bool
	Counts                                       []KV
	Nodes                                        []PlanNodeView
	Done                                         bool
	CanDryRun, CanApprove, CanApply, CanRollback bool
}

// PlanNodeView is one node.
type PlanNodeView struct {
	ID, Host, Action, Risk string
	Needs                  []string
	Gate                   bool
	State                  string
	Reason                 string
	DryStatus              string
	Diff                   string
	DryReason              string
	NeedsOwnApproval       bool
	Approved               bool
	ApprovedBy             string
	CanApprove             bool
	Phases                 []string
}
