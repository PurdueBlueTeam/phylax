package actions

import (
	"sort"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

// DefaultAccessGroups are the groups whose membership scored accounts rely on
// to log in; removing a protected account from one is refused.
var DefaultAccessGroups = []string{"Remote Desktop Users", "Remote Management Users", "sudo", "wheel", "ssh", "sshusers"}

// GuardFromManifest builds the scoring guard for one host from the manifest
// (the PCR rule): protected accounts (scored, or "protected" = unknown) on the
// host are never locked, deleted or renamed and change password only by PCR
// transaction; scored services on the host are never stopped, disabled or
// masked; scored content roots are never modified. A StaticGuard is plain
// data, so agents can carry the same rules in their configuration.
func GuardFromManifest(m *manifest.Manifest, host string) StaticGuard {
	g := StaticGuard{Groups: append([]string(nil), DefaultAccessGroups...)}
	if m == nil {
		return g
	}
	for id, a := range m.Accounts {
		if !a.Protected() {
			continue
		}
		if a.Scope != "domain" && len(a.Hosts) > 0 && !containsFold(a.Hosts, host) {
			continue
		}
		name := a.Username
		if name == "" {
			name, _, _ = strings.Cut(id, "@")
		}
		g.Accounts = append(g.Accounts, name)
	}
	for _, s := range m.Services {
		if !s.Scored || s.Host != host {
			continue
		}
		if s.Process != nil {
			if s.Process.Unit != "" {
				g.Services = append(g.Services, s.Process.Unit)
			}
			g.Services = append(g.Services, s.Process.Units...)
		}
		if s.Content != nil {
			g.Paths = append(g.Paths, s.Content.Roots...)
			g.Paths = append(g.Paths, s.Content.UploadDirs...)
		}
	}
	g.Accounts, g.Services, g.Paths = uniq(g.Accounts), uniq(g.Services), uniq(g.Paths)
	return g
}

func containsFold(l []string, s string) bool {
	for _, e := range l {
		if strings.EqualFold(e, s) {
			return true
		}
	}
	return false
}

func uniq(l []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range l {
		if e != "" && !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.Strings(out)
	return out
}
