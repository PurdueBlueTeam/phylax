package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// maxFactID bounds a fact id; a later fact with the same id replaces the
// earlier one on the agent.
const maxFactID = 128

// SendFact validates a control: fact and sends it, signed, to every target
// host. mod is the calling module: a fact subtype has exactly one owner, so a
// module cannot send another module's facts. An agent that is not connected is
// logged and skipped: it treats the fact as unknown, which is the safe side.
func (c *Controller) SendFact(ctx context.Context, mod string, m module.ControlMsg) error {
	if m.Type != "fact" {
		return fmt.Errorf("controller: control type %q is not a fact", m.Type)
	}
	owner, ok := plan.FactSender(m.Fact)
	if !ok {
		return fmt.Errorf("controller: unknown fact subtype %q", m.Fact)
	}
	if owner != mod {
		return fmt.Errorf("controller: module %q does not own fact subtype %q (owned by %s)", mod, m.Fact, owner)
	}
	if len(m.ID) == 0 || len(m.ID) > maxFactID {
		return fmt.Errorf("controller: fact id must be 1..%d bytes", maxFactID)
	}
	if m.TTL <= 0 || m.TTL > plan.MaxFactTTL {
		return fmt.Errorf("controller: fact ttl %v outside (0, %v]", m.TTL, plan.MaxFactTTL)
	}
	data, err := json.Marshal(m.Data)
	if err != nil {
		return fmt.Errorf("controller: fact data: %w", err)
	}
	if len(data) > plan.MaxFactData {
		return fmt.Errorf("controller: fact data is %d bytes, more than %d", len(data), plan.MaxFactData)
	}
	targets, err := c.factHosts(m.Hosts)
	if err != nil {
		return err
	}
	args, err := json.Marshal(event.ControllerFact{ID: m.ID, Fact: m.Fact, TS: c.now().UTC(), TTL: m.TTL, Data: m.Data})
	if err != nil {
		return fmt.Errorf("controller: fact args: %w", err)
	}
	for _, host := range targets {
		if c.sessionFor(host) == nil {
			c.log.Warn("fact: agent is not connected; skipped", "host", host, "fact", m.Fact, "id", m.ID)
			continue
		}
		if err := c.SendControl(ctx, host, plan.ControlFact, true, args); err != nil {
			return err
		}
	}
	return nil
}

// factHosts resolves every Hosts entry: a manifest host name, or a label
// expression (manifest.ParseLabels). At least one host must resolve.
func (c *Controller) factHosts(hosts []string) ([]string, error) {
	if len(hosts) == 0 {
		return nil, errors.New("controller: fact has no hosts")
	}
	man, err := c.currentManifest()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(hosts))
	out := make([]string, 0, len(hosts))
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for _, h := range hosts {
		if _, ok := man.Hosts[h]; ok {
			add(h)
			continue
		}
		e, err := manifest.ParseLabels(h)
		if err != nil {
			return nil, fmt.Errorf("controller: fact host %q: %w", h, err)
		}
		match := man.HostsMatching(e)
		if len(match) == 0 {
			return nil, fmt.Errorf("controller: fact host %q matches no host", h)
		}
		for _, name := range match {
			add(name)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("controller: fact resolved no host")
	}
	return out, nil
}
