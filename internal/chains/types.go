// Package chains builds lightweight attack chains from stored events (design:
// "Attack chains", owner decision D-2). A chain is an ordered list of hops in
// a table, built by about a dozen linking rules over data the agents already
// send, grouped into campaigns and rendered as a timeline. It is deliberately
// not a graph engine: there is no graph store, no query language and no
// syscall-level provenance. Every hop records how it was linked and how sure
// that link is, and the timeline never presents a guess as fact.
package chains

import (
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/traceback"
)

// Kind is the hop kind.
type Kind string

const (
	Access Kind = "access" // a source reaches a host through a service and account
	Exec   Kind = "exec"   // a process runs on a host
	Change Kind = "change" // a file, config, account or persistence entry changes
	Move   Kind = "move"   // host A reaches host B
	Egress Kind = "egress" // a host reaches outside
)

// Link methods (how a hop was tied to its cause), strongest first.
const (
	MethodSeed        = "seed"         // the seeding event itself
	MethodSocket      = "socket"       // the process owned the connection's socket
	MethodLineage     = "lineage"      // an ancestor process owned it
	MethodCommunityID = "community_id" // exact Community ID match across hosts
	MethodTuple       = "tuple"        // exact 5-tuple match across hosts
	MethodAuth        = "auth"         // a login event with a source address
	MethodSameAccount = "same_account" // same account within N seconds on one host
	MethodSourceAddr  = "source_addr"  // source address belongs to a known host, no connection record
	MethodTimeWindow  = "time_window"  // closest-in-time guess
	MethodUnmatched   = "unmatched"    // one side of a connection with no partner record
	MethodNone        = "none"
)

// ProcRef identifies a process in a hop.
type ProcRef struct {
	Host    string `json:"host"`
	PID     int64  `json:"pid"`
	Exe     string `json:"exe,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
}

// Hop is one step of a chain.
type Hop struct {
	ID    int64 `json:"-"`
	Ord   int   `json:"-"`
	Kind  Kind  `json:"kind"`
	Cause int   `json:"cause"` // Ord of the hop this one follows from; -1 for a root
	Seed  bool  `json:"seed,omitempty"`

	SrcHost string `json:"src_host,omitempty"` // empty when outside
	SrcAddr string `json:"src_addr,omitempty"`
	DstHost string `json:"dst_host,omitempty"` // the host the hop happens on (exec, change) or reaches
	DstAddr string `json:"dst_addr,omitempty"`

	Account     string   `json:"account,omitempty"`
	Proc        *ProcRef `json:"proc,omitempty"`
	Proto       string   `json:"proto,omitempty"`
	SrcPort     int      `json:"src_port,omitempty"`
	DstPort     int      `json:"dst_port,omitempty"`
	Service     string   `json:"service,omitempty"`
	CommunityID string   `json:"community_id,omitempty"`
	Path        string   `json:"path,omitempty"` // changed file / service / task / group
	Persistence bool     `json:"persistence,omitempty"`

	Start time.Time `json:"start"`
	End   time.Time `json:"end"`

	Technique  string   `json:"technique,omitempty"` // ATT&CK id
	What       string   `json:"what"`
	Method     string   `json:"method"`
	Confidence float64  `json:"confidence"`
	Notes      []string `json:"notes,omitempty"`

	Evidence []traceback.Ref `json:"evidence,omitempty"`

	Items []Item `json:"-"`
}

// Host is the host a hop happens on (the destination).
func (h *Hop) Host() string { return h.DstHost }

// ItemKind is a remediation action kind.
type ItemKind string

const (
	CloseEntry        ItemKind = "close_entry"
	RemovePersistence ItemKind = "remove_persistence"
	RotateCredential  ItemKind = "rotate_credential"
	BlockSource       ItemKind = "block_source"
	RemoveArtifact    ItemKind = "remove_artifact"
)

// Item states.
const (
	StateOpen     = "open"
	StateApplied  = "applied"
	StateVerified = "verified"
)

// Item is one remediation item of a hop.
type Item struct {
	ID     int64    `json:"-"`
	Kind   ItemKind `json:"kind"`
	Host   string   `json:"host,omitempty"`
	Target string   `json:"target"` // account, path, address, service
	Text   string   `json:"text"`
	State  string   `json:"-"`
	// Verified is the checkbox state: true once automatic verification (or an
	// operator) confirmed the hole is closed.
	Note string `json:"note,omitempty"` // how it was verified
}

// Verified reports the verified flag.
func (i Item) Verified() bool { return i.State == StateVerified }

// SeedKind says why a chain was started.
type SeedKind string

const (
	SeedAlert         SeedKind = "alert"
	SeedServiceChange SeedKind = "service_change"
	SeedRedCheck      SeedKind = "red_check"
	SeedDecoy         SeedKind = "decoy"
	SeedHoneytoken    SeedKind = "honeytoken"
	SeedLedger        SeedKind = "ledger"
)

// Chain is an ordered list of hops with a confidence.
type Chain struct {
	ID         int64
	CampaignID int64
	IncidentID int64
	Seed       SeedKind
	Hops       []Hop // ordered by start time; Cause refers to Ord
	Confidence float64
	Created    time.Time
	// Truncated is set when the hop limit cut the chain; Notes explain gaps
	// and bounds.
	Truncated bool
	Notes     []string
}

// SeedHop returns the hop that seeded the chain.
func (c *Chain) SeedHop() *Hop {
	for i := range c.Hops {
		if c.Hops[i].Seed {
			return &c.Hops[i]
		}
	}
	return nil
}

// Keys are the values campaigns group on.
type Keys struct {
	Sources  []string
	Accounts []string
	Hashes   []string
	C2       []string
}
