package palo

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/devices"
	"github.com/PurdueBlueTeam/phylax/internal/devices/palo/xmlapi"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
)

// Translation is the typed intent as device changes.
type Translation struct {
	// Policy: objects, services, NAT and security rules, all tagged phylax-managed.
	Policy     devices.ChangeSet
	PolicyRisk devices.Risk
	// Mgmt: the additive half of the management lockdown (permit the controller).
	// It is its own commit; removing old entries comes later via MgmtRemovals.
	Mgmt     devices.ChangeSet
	MgmtRisk devices.Risk
	// Warnings are items that could not be expressed (unresolved addresses).
	Warnings []string

	permitted []string
}

// fit makes a PAN-OS object name (31 characters at most).
func fit(name string) string {
	name = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '-'
	}, name)
	if len(name) <= 31 {
		return name
	}
	h := sha1.Sum([]byte(name))
	return name[:22] + "-" + hex.EncodeToString(h[:])[:8]
}

func member(vals ...string) string {
	var b strings.Builder
	for _, v := range vals {
		b.WriteString("<member>" + esc(v) + "</member>")
	}
	return b.String()
}

func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

const tagXML = "<tag><member>" + ManagedTag + "</member></tag>"

func entry(name, inner string) string {
	return `<entry name="` + esc(name) + `">` + inner + `</entry>`
}

func normAddr(v string) string {
	if _, err := netip.ParsePrefix(v); err == nil {
		return v
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return a.String()
	}
	return v
}

func portList(s render.ServiceSpec) string {
	var parts []string
	for _, p := range s.Ports {
		parts = append(parts, strconv.Itoa(int(p)))
	}
	for _, r := range s.Ranges {
		if r.Lo == r.Hi {
			parts = append(parts, strconv.Itoa(int(r.Lo)))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", r.Lo, r.Hi))
		}
	}
	return strings.Join(parts, ",")
}

type builder struct {
	a        *Adapter
	t        *Translation
	svcDone  map[string]bool
	addrDone map[string]bool
}

func (b *builder) vsys() string { return b.a.vsysPath() }

func (b *builder) op(kind, key, xpath, el string) {
	b.t.Policy.Ops = append(b.t.Policy.Ops, MakeOp(kind, key, xpath, el))
}

// service returns the service object name for a tcp/udp spec, queueing its creation.
func (b *builder) service(s render.ServiceSpec) (string, bool) {
	if s.Proto != "tcp" && s.Proto != "udp" {
		return "", false
	}
	ports := portList(s)
	if ports == "" {
		ports = "1-65535"
	}
	name := fit("phylax-" + s.Proto + "-" + strings.ReplaceAll(ports, ",", "_"))
	if !b.svcDone[name] {
		b.svcDone[name] = true
		b.op("object.upsert", name, xmlapi.EntryXPath(b.vsys()+"/service", name),
			entry(name, "<protocol><"+s.Proto+"><port>"+ports+"</port></"+s.Proto+"></protocol>"+tagXML))
	}
	return name, true
}

func (b *builder) endpoints(eps []render.Endpoint, what, rule string) (members []string, skip bool) {
	if len(eps) == 0 {
		return []string{"any"}, false
	}
	for _, e := range eps {
		if e.Value == "" {
			b.t.Warnings = append(b.t.Warnings, fmt.Sprintf("rule %s skipped: %s %q has no address yet (fill in by hand)", rule, what, e.Host))
			return nil, true
		}
		members = append(members, normAddr(e.Value))
	}
	return members, false
}

// Translate turns the typed Palo intent into ChangeSets. Everything it
// creates carries the phylax-managed tag.
func (a *Adapter) Translate(in *render.PaloIntent) (*Translation, error) {
	t := &Translation{PolicyRisk: devices.RiskNone, MgmtRisk: devices.RiskLockout}
	b := &builder{a: a, t: t, svcDone: map[string]bool{}, addrDone: map[string]bool{}}
	risk := func(r string) {
		switch r {
		case render.RiskLockout:
			t.PolicyRisk = devices.RiskLockout
		case render.RiskService:
			if t.PolicyRisk == devices.RiskNone {
				t.PolicyRisk = devices.RiskService
			}
		}
	}

	b.op("object.upsert", ManagedTag, xmlapi.EntryXPath(b.vsys()+"/tag", ManagedTag),
		entry(ManagedTag, "<comments>objects and rules created by phylax</comments>"))
	// The tag object itself is not subject to the managed check (it is how we mark things).
	t.Policy.Ops[0].Kind = "tag.upsert"

	for _, ad := range in.Addresses {
		name := fit(ad.Name)
		b.op("object.upsert", name, xmlapi.EntryXPath(b.vsys()+"/address", name),
			entry(name, "<ip-netmask>"+esc(normAddr(ad.Value))+"</ip-netmask>"+tagXML))
	}

	// Static 1:1 NAT: the inside host leaves as its public address and is reached at it.
	for _, n := range in.StaticNAT {
		if n.Original.Value == "" || n.Translated.Value == "" {
			t.Warnings = append(t.Warnings, fmt.Sprintf("nat %s skipped: translated address of %s unresolved (DHCP), fix by hand", n.Name, n.Translated.Host))
			continue
		}
		name := fit(n.Name)
		inner := "<from>" + member(in.InsideZone) + "</from><to>" + member(in.OutsideZone) + "</to>" +
			"<source>" + member(normAddr(n.Translated.Value)) + "</source><destination>" + member("any") + "</destination>" +
			"<service>any</service><source-translation><static-ip><translated-address>" + esc(normAddr(n.Original.Value)) +
			"</translated-address><bi-directional>yes</bi-directional></static-ip></source-translation>"
		if n.Comment != "" {
			inner += "<description>" + esc(n.Comment) + "</description>"
		}
		b.op("nat.upsert", name, xmlapi.EntryXPath(b.vsys()+"/rulebase/nat/rules", name), entry(name, inner+tagXML))
	}

	for _, r := range in.Rules {
		src, skip := b.endpoints(r.Sources, "source", r.Name)
		if skip {
			continue
		}
		dst, skip := b.endpoints(r.Destinations, "destination", r.Name)
		if skip {
			continue
		}
		app, svc := []string{"any"}, []string{"any"}
		var tcpudp []render.ServiceSpec
		hasICMP, hasAny := false, len(r.Services) == 0
		for _, s := range r.Services {
			switch s.Proto {
			case "icmp":
				hasICMP = true
			case "any":
				hasAny = true
			default:
				tcpudp = append(tcpudp, s)
			}
		}
		switch {
		case hasICMP && len(tcpudp) == 0:
			app, svc = []string{"icmp", "ping"}, []string{"application-default"}
		case hasICMP:
			t.Warnings = append(t.Warnings, fmt.Sprintf("rule %s skipped: mixes icmp with tcp/udp services", r.Name))
			continue
		case !hasAny:
			svc = nil
			for _, s := range tcpudp {
				n, ok := b.service(s)
				if !ok {
					t.Warnings = append(t.Warnings, fmt.Sprintf("rule %s: unsupported protocol %q", r.Name, s.Proto))
					continue
				}
				svc = append(svc, n)
			}
			if len(svc) == 0 {
				continue
			}
		}
		action := "allow"
		if r.Action == "deny" {
			action = "deny"
		}
		name := fit(r.Name)
		inner := "<from>" + member(r.FromZone) + "</from><to>" + member(r.ToZone) + "</to>" +
			"<source>" + member(src...) + "</source><destination>" + member(dst...) + "</destination>" +
			"<source-user>" + member("any") + "</source-user><application>" + member(app...) + "</application>" +
			"<service>" + member(svc...) + "</service><action>" + action + "</action>"
		if r.LogEnd {
			inner += "<log-end>yes</log-end>"
		}
		if r.Comment != "" {
			inner += "<description>" + esc(r.Comment) + "</description>"
		}
		b.op("rule.upsert", name, xmlapi.EntryXPath(b.vsys()+"/rulebase/security/rules", name), entry(name, inner+tagXML))
		risk(r.Risk)
	}

	if in.Mgmt != nil {
		for _, e := range in.Mgmt.PermittedFrom {
			if e.Value == "" {
				t.Warnings = append(t.Warnings, "mgmt lockdown: permitted-from address for "+e.Host+" is unresolved; not adding it")
				continue
			}
			v := normAddr(e.Value)
			if _, err := netip.ParsePrefix(v); err != nil {
				v += "/32"
			}
			t.permitted = append(t.permitted, v)
			t.Mgmt.Ops = append(t.Mgmt.Ops, MakeOp("mgmt.permit", v, xmlapi.EntryXPath(a.PermittedIPPath(), v), entry(v, "")))
		}
		if !in.Mgmt.Additive {
			t.Warnings = append(t.Warnings, "mgmt lockdown is not marked additive; the adapter always adds first and removes in a second commit")
		}
	}
	return t, nil
}

// MgmtRemovals reads the live management ACL and returns the delete ops for
// entries the intent does not permit. Run it only after the additive commit
// passed a fresh-connection probe. An empty ACL (allow all) yields nothing.
func (a *Adapter) MgmtRemovals(ctx context.Context, t *Translation) (devices.ChangeSet, error) {
	var cs devices.ChangeSet
	n, err := a.c.ConfigShow(ctx, a.PermittedIPPath())
	if err != nil || n == nil {
		return cs, err
	}
	want := map[string]bool{}
	for _, p := range t.permitted {
		want[p] = true
	}
	var names []string
	for _, e := range n.Children {
		if nm := e.Attr("name"); e.Name == "entry" && !want[nm] {
			names = append(names, nm)
		}
	}
	sort.Strings(names)
	for _, nm := range names {
		cs.Ops = append(cs.Ops, MakeOp("mgmt.remove", nm, xmlapi.EntryXPath(a.PermittedIPPath(), nm), ""))
	}
	return cs, nil
}

// Flow is a scored flow to prove against the running policy.
type Flow struct {
	From, To, Src, Dst string
	Port, Proto        int
	WantAction         string // default allow
}

// FlowsFromIntent derives one policy-match flow per scored-service rule.
func FlowsFromIntent(in *render.PaloIntent) []Flow {
	var out []Flow
	for _, r := range in.Rules {
		if r.Phase != "service" || len(r.Destinations) != 1 || r.Destinations[0].Value == "" {
			continue
		}
		for _, s := range r.Services {
			proto := map[string]int{"tcp": 6, "udp": 17}[s.Proto]
			if proto == 0 {
				continue
			}
			port := 0
			if len(s.Ports) > 0 {
				port = int(s.Ports[0])
			} else if len(s.Ranges) > 0 {
				port = int(s.Ranges[0].Lo)
			}
			out = append(out, Flow{From: r.FromZone, To: r.ToZone, Src: "198.51.100.10", Dst: r.Destinations[0].Value, Port: port, Proto: proto})
		}
	}
	return out
}

// HealthCheck builds the runner's health callback: each flow must hit an
// allow (or WantAction) in the running policy, a brand-new connection must
// work, and extra (scorer-mimic probes) must pass.
func (a *Adapter) HealthCheck(flows []Flow, extra func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		for _, f := range flows {
			rule, act, err := a.c.TestSecurityPolicyMatch(ctx, xmlapi.PolicyMatch{From: f.From, To: f.To, Source: f.Src, Destination: f.Dst, Port: f.Port, Protocol: f.Proto})
			if err != nil {
				return fmt.Errorf("policy match %s:%d: %w", f.Dst, f.Port, err)
			}
			want := f.WantAction
			if want == "" {
				want = "allow"
			}
			if act != want {
				return fmt.Errorf("policy match %s:%d hit rule %q with action %q, want %q", f.Dst, f.Port, rule, act, want)
			}
		}
		if err := a.Probe(ctx); err != nil {
			return err
		}
		if extra != nil {
			return extra(ctx)
		}
		return nil
	}
}
