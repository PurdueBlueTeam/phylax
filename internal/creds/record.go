package creds

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Role says what an account is for; it decides the rotation stage.
type Role int

const (
	RoleDeviceAdmin Role = iota // Palo, VyOS admin / API account
	RoleLocalAdmin              // root, Administrator, sysadmin, our own admin accounts
	RoleDomainAdmin             // domain administrator and other AD accounts
	RoleService                 // service and app accounts (MySQL, OpenCart, Splunk, SQL Server ...)
)

func (r Role) String() string {
	return [...]string{"device-admin", "local-admin", "domain-admin", "service"}[r]
}

// PCRState mirrors the design's PCR state machine; the transaction engine
// (internal/scorer) owns the transitions, this package only stores the value.
type PCRState string

const (
	PCRNone      PCRState = ""
	PCRStable    PCRState = "stable"
	PCRPlanned   PCRState = "planned"
	PCRApplying  PCRState = "applying"
	PCRPending   PCRState = "pending"
	PCRVerifying PCRState = "verifying"
	PCRConfirmed PCRState = "confirmed"
	PCRFailed    PCRState = "failed"
)

// Record is the non-secret metadata for one account on one host or device.
// Passwords themselves are in the vault under VaultKey().
type Record struct {
	Account  string // case-exact (PCR usernames are case-sensitive)
	Host     string // host or device name from the manifest
	Role     Role
	Domain   bool // account lives on the domain controller(s); needs the Zerologon gate
	Scored   bool
	Credlist string // PCR credlist PATH (never the display name); scored only

	CurrentVersion  string // vault version id in use
	PreviousVersion string // vault version id to roll back to
	LastRotated     time.Time

	PCRState PCRState
	PCRRef   string // opaque reference to the PCR transaction record (scorer package)
}

// VaultKey is the vault entry name for this account.
func (r Record) VaultKey() string { return VaultKey(r.Host, r.Account) }

// VaultKey builds the entry name. The host is lower-cased; the account is not.
func VaultKey(host, account string) string {
	return "cred/" + strings.ToLower(host) + "/" + account
}

// Class returns the generation class for a record.
func (r Record) Class() Class {
	switch {
	case r.Scored:
		return Scored
	case r.Role == RoleDeviceAdmin || r.Role == RoleDomainAdmin:
		return Admin
	default:
		return Unscored
	}
}

// Validate checks internal consistency.
func (r Record) Validate() error {
	switch {
	case r.Account == "" || r.Host == "":
		return errors.New("creds: record needs account and host")
	case r.Scored && r.Credlist == "":
		return fmt.Errorf("creds: scored account %s@%s has no credlist path", r.Account, r.Host)
	case !r.Scored && (r.PCRState != PCRNone || r.PCRRef != ""):
		return fmt.Errorf("creds: unscored account %s@%s carries PCR state", r.Account, r.Host)
	case strings.ContainsAny(r.Account, ",\r\n"):
		return fmt.Errorf("creds: account %q not CSV safe", r.Account)
	}
	return nil
}

// MarkRotated records a successful rotation: new becomes current, the old
// current becomes the rollback target.
func (r *Record) MarkRotated(newVersion string, at time.Time) {
	r.PreviousVersion = r.CurrentVersion
	r.CurrentVersion = newVersion
	r.LastRotated = at
}

// MarkRolledBack swaps back to the previous version.
func (r *Record) MarkRolledBack() error {
	if r.PreviousVersion == "" {
		return errors.New("creds: no previous version")
	}
	r.CurrentVersion, r.PreviousVersion = r.PreviousVersion, r.CurrentVersion
	return nil
}

// ---- rotation ordering ----

// Stage is a rotation phase, in execution order.
type Stage int

const (
	StageZerologon   Stage = iota // 0: enforce secure channel / patch / filter RPC on each DC
	StageDeviceAdmin              // 1: Palo and VyOS admin accounts
	StageLocalAdmin               // 2: root, Administrator, domain admin, our admin accounts
	StageUnscored                 // 3: unscored service and app accounts
	StageScored                   // 4: scored accounts, PCR transactions only
)

func (s Stage) String() string {
	return [...]string{"zerologon-mitigation", "device-admin", "admin", "unscored", "scored-pcr"}[s]
}

// Method says how a step is executed.
type Method int

const (
	MethodDirect     Method = iota // rotate on the host/device and update the vault
	MethodPCR                      // host change plus Quotient PCR, human step in the middle
	MethodMitigation               // Zerologon check/mitigation, no credential change
)

// Step is one unit of the plan.
type Step struct {
	Stage  Stage
	Method Method
	Host   string
	Record *Record // nil for mitigation steps
	// After lists hosts whose Zerologon mitigation step must complete first.
	After []string
}

// Held is a record deliberately left out of the ordered steps.
type Held struct {
	Record Record
	Reason string
}

// Plan is the ordered result.
type Plan struct {
	Steps []Step
	Held  []Held
}

// PlanOptions parameterises ordering.
type PlanOptions struct {
	// DCs are the domain controller hosts (case-insensitive). Each gets a
	// mitigation step, and every Domain account on it depends on it.
	DCs []string
	// PCRListChecked says the PCR credlist has been compared with the host
	// accounts. Until it is true, an account named sysadmin that is not
	// already known to be unscored is held (the default account may be scored).
	PCRListChecked bool
}

// PlanRotation orders records per the design: Zerologon mitigation on DCs
// first, then device admins, then local/domain admins, then unscored
// service accounts, with scored accounts last and only as PCR transactions.
// Within a stage the order is deterministic (host, then account).
func PlanRotation(records []Record, opt PlanOptions) (Plan, error) {
	var p Plan
	dcs := map[string]string{}
	for _, d := range opt.DCs {
		dcs[strings.ToLower(d)] = d
	}
	var dcNames []string
	for k := range dcs {
		dcNames = append(dcNames, k)
	}
	sort.Strings(dcNames)
	for _, k := range dcNames {
		p.Steps = append(p.Steps, Step{Stage: StageZerologon, Method: MethodMitigation, Host: dcs[k]})
	}

	seen := map[string]bool{}
	var rest []Step
	for i := range records {
		r := records[i]
		if err := r.Validate(); err != nil {
			return Plan{}, err
		}
		if k := r.VaultKey(); seen[k] {
			return Plan{}, fmt.Errorf("creds: duplicate record %s", k)
		} else {
			seen[k] = true
		}
		if strings.EqualFold(r.Account, "sysadmin") && !r.Scored && !opt.PCRListChecked {
			p.Held = append(p.Held, Held{r, "sysadmin may be scored: check the PCR list first"})
			continue
		}
		st := Step{Host: r.Host, Record: &r}
		switch {
		case r.Scored:
			st.Stage, st.Method = StageScored, MethodPCR
		case r.Role == RoleDeviceAdmin:
			st.Stage = StageDeviceAdmin
		case r.Role == RoleLocalAdmin || r.Role == RoleDomainAdmin:
			st.Stage = StageLocalAdmin
		default:
			st.Stage = StageUnscored
		}
		if r.Domain {
			for _, k := range dcNames {
				st.After = append(st.After, dcs[k])
			}
			if len(dcNames) == 0 {
				return Plan{}, fmt.Errorf("creds: domain account %s@%s but no DC declared for the Zerologon gate", r.Account, r.Host)
			}
		}
		rest = append(rest, st)
	}
	sort.SliceStable(rest, func(i, j int) bool {
		a, b := rest[i], rest[j]
		if a.Stage != b.Stage {
			return a.Stage < b.Stage
		}
		if a.Host != b.Host {
			return strings.ToLower(a.Host) < strings.ToLower(b.Host)
		}
		return a.Record.Account < b.Record.Account
	})
	p.Steps = append(p.Steps, rest...)
	return p, nil
}
