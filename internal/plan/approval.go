package plan

import "github.com/PurdueBlueTeam/phylax/internal/store"

// ApprovalClass is how a plan was authorised.
type ApprovalClass string

const (
	ClassClick        ApprovalClass = "click"
	ClassAutoReadOnly ApprovalClass = "auto_readonly"
	ClassStanding     ApprovalClass = "standing"
	ClassAuto         ApprovalClass = "auto"
)

// StandingApproval is an operator-granted, scoped, expiring approval. The
// type lives in store so the store can read and write it without importing
// plan; plan re-exports it so callers keep using plan.StandingApproval.
type StandingApproval = store.StandingApproval
