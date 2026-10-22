package actions

import (
	"context"
	"sort"
	"strings"
	"time"
)

// ADObject is a directory object as the AD actions see it.
type ADObject struct {
	DN         string
	SAM        string // sAMAccountName
	Class      string // user | group | computer | other
	Enabled    bool
	AdminCount int
	Members    []string // group: member DNs (direct)
	PwdLastSet time.Time
	SID        string
}

// ADBackend is the domain-aware access the DC's agent has. The Windows
// implementation uses ADSI (the agent runs as SYSTEM on the DC); tests use a
// fake directory. Typed queries keep LDAP filters inside the implementation.
type ADBackend interface {
	DomainDN(ctx context.Context) (string, error)
	// Find resolves a sAMAccountName (user, group or computer).
	Find(ctx context.Context, sam string) (ADObject, bool, error)
	Get(ctx context.Context, dn string) (ADObject, bool, error)
	// AdminCountSet returns every object with adminCount=1.
	AdminCountSet(ctx context.Context) ([]ADObject, error)
	SetEnabled(ctx context.Context, dn string, enabled bool) error
	SetAdminCount(ctx context.Context, dn string, n int) error
	SetPassword(ctx context.Context, dn, password string, mustChange bool) error
	AddMember(ctx context.Context, groupDN, memberDN string) error
	RemoveMember(ctx context.Context, groupDN, memberDN string) error
}

func adOrErr(env *Env) (ADBackend, error) {
	if env.Win.AD == nil {
		return nil, unsupported("active directory")
	}
	return env.Win.AD, nil
}

// PrivilegedGroups are the groups audited by default (design: Active
// Directory hunt; red-team-ttps IA-2).
var PrivilegedGroups = []string{
	"Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
	"Account Operators", "Backup Operators", "Server Operators", "Print Operators",
	"DnsAdmins", "Group Policy Creator Owners", "Key Admins", "Enterprise Key Admins",
}

// maxNestDepth bounds recursive group resolution (cycles are also detected).
const maxNestDepth = 16

// Member is one effective member of a group with how it got there.
type Member struct {
	DN   string
	SAM  string
	Path string // "Domain Admins > Helpdesk > alice"
	Obj  ADObject
}

// ResolveMembers expands a group recursively. Nested groups are reported with
// their members; the result lists leaf (non-group) objects once, with the
// shortest nesting path, and the groups that were traversed.
func ResolveMembers(ctx context.Context, ad ADBackend, group ADObject) (leaves []Member, groups []string, err error) {
	type item struct {
		g    ADObject
		path string
		d    int
	}
	seenGroup := map[string]bool{strings.ToLower(group.DN): true}
	seenLeaf := map[string]bool{}
	q := []item{{group, group.SAM, 0}}
	for len(q) > 0 {
		it := q[0]
		q = q[1:]
		groups = append(groups, it.g.SAM)
		members := append([]string(nil), it.g.Members...)
		sort.Strings(members)
		for _, dn := range members {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
			o, ok, err := ad.Get(ctx, dn)
			if err != nil {
				return nil, nil, err
			}
			name := o.SAM
			if !ok {
				name = dn // foreign security principal or deleted object: report by DN
				o = ADObject{DN: dn, Class: "other"}
			}
			path := it.path + " > " + name
			if o.Class == "group" {
				if seenGroup[strings.ToLower(o.DN)] || it.d+1 > maxNestDepth {
					continue
				}
				seenGroup[strings.ToLower(o.DN)] = true
				q = append(q, item{o, path, it.d + 1})
				continue
			}
			if seenLeaf[strings.ToLower(o.DN)] {
				continue
			}
			seenLeaf[strings.ToLower(o.DN)] = true
			leaves = append(leaves, Member{DN: o.DN, SAM: name, Path: path, Obj: o})
		}
	}
	return leaves, groups, nil
}
