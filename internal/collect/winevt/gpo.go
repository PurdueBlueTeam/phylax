package winevt

import (
	"regexp"
	"strings"
)

// Group Policy fields. GPO changes arrive three ways: directory events
// (5136/5137/5141 on groupPolicyContainer objects), file events under
// SYSVOL\<domain>\Policies (Sysmon 11/23/26), and share access (5145 on the
// SYSVOL share). These helpers add the same derived fields to all three so a
// rule can be written against the shape (a policy item changed) instead of one
// producer's literals. They only add fields.

var (
	sysvolPolicyRE = regexp.MustCompile(`(?i)\\sysvol\\[^\\]+\\policies\\(\{[0-9a-f-]{36}\})(?:\\(machine|user))?(?:\\(.*))?$`)
	gpoDNRE        = regexp.MustCompile(`(?i)cn=(\{[0-9a-f-]{36}\}),cn=policies,cn=system`)
)

// gpoItemKind classifies the part of a policy a path (relative to Machine or
// User) belongs to.
func gpoItemKind(item string) string {
	l := strings.ToLower(item)
	switch {
	case strings.HasPrefix(l, "preferences\\scheduledtasks"):
		return "gpp_scheduledtasks"
	case strings.HasPrefix(l, "preferences\\groups"):
		return "gpp_groups"
	case strings.HasPrefix(l, "preferences\\"):
		return "gpp_other"
	case strings.HasPrefix(l, "scripts\\"):
		return "scripts"
	case strings.HasSuffix(l, "registry.pol"):
		return "registry_pol"
	case strings.HasSuffix(l, "gpttmpl.inf") || strings.HasPrefix(l, "microsoft\\windows nt\\secedit"):
		return "security_template"
	}
	return "other"
}

// sysvolPolicyFields marks path (a local or UNC path) as a Group Policy file
// when it lies under a SYSVOL policy folder.
func sysvolPolicyFields(f map[string]any, path string) {
	if path == "" {
		return
	}
	m := sysvolPolicyRE.FindStringSubmatch(path)
	if m == nil {
		return
	}
	f["sysvol_policy"] = true
	f["gpo_guid"] = strings.ToUpper(m[1])
	if m[2] != "" {
		f["gpo_section"] = strings.ToLower(m[2])
	}
	f["gpo_item"] = gpoItemKind(m[3])
}

// gpoObjectFields marks a directory change as touching a Group Policy object.
func gpoObjectFields(f map[string]any, dn, class string) {
	m := gpoDNRE.FindStringSubmatch(dn)
	if m == nil && !strings.EqualFold(class, "groupPolicyContainer") {
		return
	}
	f["gpo"] = true
	if m != nil {
		f["gpo_guid"] = strings.ToUpper(m[1])
	}
}
