package controller

import "github.com/PurdueBlueTeam/phylax/internal/module"

// AgentHealth returns per-module health reported by an agent, from its latest
// heartbeat. It is empty until the first heartbeat arrives.
func (c *Controller) AgentHealth(host string) map[string]module.Health {
	c.mu.Lock()
	s, ok := c.agents[host]
	c.mu.Unlock()
	if !ok {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]module.Health, len(s.hb.Health))
	for k, v := range s.hb.Health {
		out[k] = v
	}
	return out
}
