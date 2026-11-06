package plan

import (
	"path"
	"sort"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

// ScoredTouch returns the manifest-scored services on the node's target host
// that the node's Touches hits. A service is scored when services.yml says
// scored: true; until discovery has learned the live set the services named by
// the manifest health: block are the scored set (no learned-set argument exists
// on purpose).
func ScoredTouch(m *manifest.Manifest, n Node, touches []actions.Touch) []string {
	if m == nil || n.Gate || len(touches) == 0 {
		return nil
	}
	scored := scoredServices(m, n.Target)
	if len(scored) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for id, s := range scored {
		if !serviceTouched(s, id, touches) {
			continue
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// scoredServices returns the scored services on host. The health: block decides
// the set until discovery has learned the live set; a host with no health block
// falls back to every service marked scored: true.
func scoredServices(m *manifest.Manifest, host string) map[string]manifest.Service {
	withHealth := map[string]manifest.Service{}
	scored := map[string]manifest.Service{}
	for id, s := range m.Services {
		if s.Host != host || !s.Scored {
			continue
		}
		scored[id] = s
		if len(s.Health) > 0 {
			withHealth[id] = s
		}
	}
	if len(withHealth) > 0 {
		return withHealth
	}
	return scored
}

func serviceTouched(s manifest.Service, id string, touches []actions.Touch) bool {
	for _, t := range touches {
		switch t.Kind {
		case actions.TouchService:
			if serviceNameMatches(s, id, t.Name) {
				return true
			}
		case actions.TouchPath:
			if pathTouchesService(s, t.Name) {
				return true
			}
		}
	}
	return false
}

func serviceNameMatches(s manifest.Service, id, name string) bool {
	n := normServiceName(name)
	if n == normServiceName(id) || n == normServiceName(s.Kind) {
		return true
	}
	if s.Process == nil {
		return false
	}
	if normServiceName(s.Process.Unit) == n {
		return true
	}
	for _, u := range s.Process.Units {
		if normServiceName(u) == n {
			return true
		}
	}
	return false
}

func normServiceName(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".service"))
}

// pathTouchesService reports whether a path touch hits the service's declared
// content. A scored service that declares no content is treated as touched by
// any path change: until discovery has learned what the service owns, the safe
// answer is that it might.
func pathTouchesService(s manifest.Service, p string) bool {
	if p == "" {
		return false
	}
	if s.Content == nil {
		return true
	}
	roots := append(append([]string(nil), s.Content.Roots...), s.Content.UploadDirs...)
	if len(roots) == 0 {
		return true
	}
	for _, root := range roots {
		if pathUnder(p, root) {
			return true
		}
	}
	return false
}

func pathUnder(p, root string) bool {
	if root == "" {
		return false
	}
	p = path.Clean(strings.ReplaceAll(p, `\`, "/"))
	root = path.Clean(strings.ReplaceAll(root, `\`, "/"))
	return p == root || strings.HasPrefix(p, root+"/")
}
