package mods

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/detect"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// KindAlert is the event kind of a local detection. Alerts are ordinary events
// at Critical priority, so they ride the spool's highest class to the controller.
const KindAlert = "detect.alert"

const keptProfiles = "detect.profiles"

func init() {
	agent.RegisterFactory(agent.Factory{
		Name: "detect",
		Section: func(c *plan.AgentConfig) (string, bool) {
			if c.Modules.Detect == nil {
				return "", false
			}
			return fp(c.Modules.Detect), true
		},
		Build: func(env agent.Env, c *plan.AgentConfig) (agent.ModuleSpec, error) {
			s := c.Modules.Detect
			rs, err := detect.Parse("signed-config", s.RuleStream(), detect.LoadOptions{AllowUntested: true})
			if err != nil {
				return agent.ModuleSpec{}, fmt.Errorf("detect rules: %w", err)
			}
			return spec(&detectModule{env: env, rs: rs, s: s}, s.RatePerSec, s.Burst), nil
		},
	})
}

// detectModule runs the rule engine over the agent's own event stream.
type detectModule struct {
	env agent.Env
	rs  *detect.RuleSet
	s   *plan.DetectSettings
}

func (*detectModule) Name() string { return "detect" }

func (m *detectModule) Start(ctx context.Context, emit agent.Emit) error {
	eng := detect.NewEngine(m.rs, detect.Options{
		// Tier-0 responses stay disabled until a later task: every rule is
		// forced to alert unless the signed config explicitly enables acting.
		AlertOnly: !m.s.ActEnabled,
		MaxKeys:   m.s.MaxKeys,
	})
	if st, ok := m.env.Kept(keptProfiles).(map[string]map[string]detect.KeyState); ok {
		eng.ImportProfiles(st)
	}
	for _, sd := range m.s.Seeds {
		if err := eng.Seed(sd.Profile, append([]string(nil), sd.Key...), sd.Values...); err != nil {
			m.env.Logger.Warn("detect: seed skipped", "profile", sd.Profile, "err", err)
		}
	}
	ch, unsub := m.env.Subscribe(8192)
	defer unsub()
	defer func() { m.env.Keep(keptProfiles, eng.ExportProfiles()) }()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-ch:
			if strings.HasPrefix(ev.Kind, "detect.") { // never feed our own alerts back
				continue
			}
			for _, al := range eng.Process(ev) {
				_ = emit(AlertEvent(al))
			}
		}
	}
}

// AlertEvent converts a rule firing to the event that is spooled.
func AlertEvent(a detect.Alert) event.Event {
	strs := func(in []string) []any {
		out := make([]any, len(in))
		for i, s := range in {
			out[i] = s
		}
		return out
	}
	ents := make(map[string]any, len(a.Entities))
	for k, v := range a.Entities {
		ents[k] = v
	}
	f := map[string]any{
		"rule": a.RuleID, "title": a.Title, "severity": a.Severity, "tier": a.Tier, "mode": a.Mode,
		"message": a.Message, "attack": strs(a.Attack), "collect": strs(a.Collect), "entities": ents,
	}
	if a.IRTemplate != "" {
		f["ir_template"] = a.IRTemplate
	}
	if len(a.Source) > 0 {
		src := make(map[string]any, len(a.Source))
		for k, v := range a.Source {
			src[k] = v
		}
		f["source"] = src
	}
	ev := make([]any, 0, len(a.Evidence))
	for _, e := range a.Evidence {
		ev = append(ev, map[string]any{"kind": e.Kind, "time": e.Time.UTC().Format(time.RFC3339Nano), "fields": e.Fields})
	}
	f["evidence"] = ev
	t := a.Time
	if t.IsZero() {
		t = time.Now()
	}
	return event.Event{Time: t, Kind: KindAlert, Priority: event.PriorityCritical, Fields: f}
}
