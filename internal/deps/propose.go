package deps

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

// Proposal is a set of depends_on entries to add to one manifest service.
type Proposal struct {
	Host     string                `json:"host"`
	Service  string                `json:"service"`
	Add      []manifest.Dependency `json:"add"`
	Evidence []string              `json:"evidence"` // one line per added entry
}

// ProposeOptions tunes Propose.
type ProposeOptions struct {
	// MinLevel is the lowest confidence proposed (default ConfMedium).
	MinLevel string
	// BaselineOnly proposes only edges seen in the learning window, so a
	// dependency that appears later (possibly an intruder's) is never
	// proposed for approval by default.
	BaselineOnly bool
}

func levelRank(l string) int {
	switch l {
	case ConfHigh:
		return 3
	case ConfMedium:
		return 2
	}
	return 1
}

// Propose turns the observed graph into depends_on additions: for each
// manifest service that scores or runs on a known host, every observed,
// resolved, cross-host dependency that the egress policy does not already
// allow. Entries are grouped per destination host and protocol. Nothing is
// applied; the operator reviews Diff and edits the manifest.
func Propose(g *Graph, m *manifest.Manifest, opt ProposeOptions) []Proposal {
	if opt.MinLevel == "" {
		opt.MinLevel = ConfMedium
	}
	type gk struct{ svc, to, proto string }
	groups := map[gk][]Edge{}
	for _, e := range g.Edges() {
		if e.Gone || e.To.Host == "" || levelRank(e.Level) < levelRank(opt.MinLevel) {
			continue
		}
		if opt.BaselineOnly && !e.Baseline {
			continue
		}
		s, ok := m.Services[e.From.Service]
		if !ok || s.Host != e.From.Host {
			continue
		}
		if ok, _ := Covered(m, e); ok {
			continue
		}
		proto := e.To.Proto
		if proto == "" {
			proto = "tcp"
		}
		k := gk{e.From.Service, e.To.Host, proto}
		groups[k] = append(groups[k], e)
	}
	bySvc := map[string]*Proposal{}
	var keys []gk
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.svc != b.svc {
			return a.svc < b.svc
		}
		if a.to != b.to {
			return a.to < b.to
		}
		return a.proto < b.proto
	})
	for _, k := range keys {
		es := groups[k]
		p := bySvc[k.svc]
		if p == nil {
			p = &Proposal{Host: m.Services[k.svc].Host, Service: k.svc}
			bySvc[k.svc] = p
		}
		var ports []uint16
		var low []uint16
		targetSvc := ""
		var ev []string
		for _, e := range es {
			if e.To.Port >= 49152 {
				low = append(low, e.To.Port)
			} else {
				ports = append(ports, e.To.Port)
			}
			if targetSvc == "" {
				if _, ok := m.Services[e.To.Service]; ok {
					targetSvc = e.To.Service
				}
			}
			ev = append(ev, fmt.Sprintf("%d/%s %s (%s, %d conns)", e.To.Port, e.To.Proto, e.Strength, e.Level, e.Count))
		}
		sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
		d := manifest.Dependency{To: k.to, Ports: dedupPorts(ports), Service: targetSvc}
		if k.proto != "tcp" {
			d.Proto = k.proto
		}
		if len(low) > 0 { // dynamic range (RPC and the like): one range
			sort.Slice(low, func(i, j int) bool { return low[i] < low[j] })
			d.PortRanges = []string{fmt.Sprintf("%d-%d", low[0], low[len(low)-1])}
		}
		d.Egress = uniqueLabel(m.Services[k.svc], p, labelFor(targetSvc, k.to, d))
		p.Add = append(p.Add, d)
		p.Evidence = append(p.Evidence, fmt.Sprintf("%s -> %s %s: %s", k.svc, k.to, k.proto, strings.Join(ev, "; ")))
	}
	out := make([]Proposal, 0, len(bySvc))
	for _, p := range bySvc {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Service < out[j].Service })
	return out
}

func dedupPorts(p []uint16) []uint16 {
	var out []uint16
	for i, v := range p {
		if i == 0 || v != p[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func labelFor(targetSvc, to string, d manifest.Dependency) string {
	switch {
	case targetSvc != "":
		return targetSvc
	case len(d.Ports) > 0:
		return to + "-" + strconv.Itoa(int(d.Ports[0]))
	}
	return to
}

func uniqueLabel(s manifest.Service, p *Proposal, want string) string {
	used := map[string]bool{}
	for _, d := range s.DependsOn {
		used[d.Egress] = true
	}
	for _, d := range p.Add {
		used[d.Egress] = true
	}
	l := want
	for i := 2; used[l]; i++ {
		l = want + "-" + strconv.Itoa(i)
	}
	return l
}

// Diff renders the proposals as a reviewable diff of services.yml.
func Diff(ps []Proposal) string {
	if len(ps) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("--- services.yml\n+++ services.yml (proposed depends_on from observed traffic)\n")
	for i, p := range ps {
		fmt.Fprintf(&b, "@@ service %s (host %s) @@\n", p.Service, p.Host)
		b.WriteString("+    depends_on:   # append to the existing list\n")
		for j, d := range p.Add {
			fmt.Fprintf(&b, "+      - %s\n", yamlDep(d))
			fmt.Fprintf(&b, "+        # evidence: %s\n", p.Evidence[min(j, len(p.Evidence)-1)])
		}
		_ = i
	}
	return b.String()
}

func yamlDep(d manifest.Dependency) string {
	parts := []string{"egress: " + d.Egress, "to: " + d.To}
	if len(d.Ports) > 0 {
		var ps []string
		for _, p := range d.Ports {
			ps = append(ps, strconv.Itoa(int(p)))
		}
		parts = append(parts, "ports: ["+strings.Join(ps, ", ")+"]")
	}
	if len(d.PortRanges) > 0 {
		parts = append(parts, `port_ranges: ["`+strings.Join(d.PortRanges, `", "`)+`"]`)
	}
	if d.Proto != "" {
		parts = append(parts, "proto: "+d.Proto)
	}
	if d.Service != "" {
		parts = append(parts, "service: "+d.Service)
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

// Apply returns a copy of m with the proposals added; m is not modified.
// Callers validate and lint the result before offering it for approval.
func Apply(m *manifest.Manifest, ps []Proposal) *manifest.Manifest {
	n := *m
	n.Services = make(map[string]manifest.Service, len(m.Services))
	for id, s := range m.Services {
		n.Services[id] = s
	}
	for _, p := range ps {
		s := n.Services[p.Service]
		s.DependsOn = append(append([]manifest.Dependency(nil), s.DependsOn...), p.Add...)
		n.Services[p.Service] = s
	}
	return &n
}
