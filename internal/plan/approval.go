package plan

import "time"

// ApprovalClass is how a plan was authorised.
type ApprovalClass string

const (
	ClassClick        ApprovalClass = "click"
	ClassAutoReadOnly ApprovalClass = "auto_readonly"
	ClassStanding     ApprovalClass = "standing"
	ClassAuto         ApprovalClass = "auto"
)

// StandingApproval is an operator-granted, scoped, expiring approval.
type StandingApproval struct {
	ID       string    `json:"id"`
	Module   string    `json:"module"`
	Template string    `json:"template"`
	Targets  string    `json:"targets"` // label expression
	Actions  []string  `json:"actions"`
	Expires  time.Time `json:"expires"`
	Approver string    `json:"approver"`
	Created  string    `json:"created"` // operator login
	Revoked  bool      `json:"revoked,omitempty"`
}
