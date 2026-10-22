package mods

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/decoys"
	"github.com/PurdueBlueTeam/phylax/internal/decoys/sandbox"
	"github.com/PurdueBlueTeam/phylax/internal/honeytokens"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// DeceptionFile is the legacy per-host decoy/honeytoken configuration. The
// decoy settings now travel in the signed AgentConfig (Modules.Deception, built
// by the controller from decoys.yml and the honeytoken registry); this
// unsigned file is read only when the signed config has no deception section
// (migration path, removed once every deployment has a controller that sends
// the section).
const DeceptionFile = "deception.json"

func init() {
	// The decoy listeners run in a re-executed copy of this binary; take over
	// the process before the agent's main does anything.
	sandbox.MaybeRunChild()
}

// decoysSection fingerprints the signed section: the whole decoy
// configuration (listeners, tokens, ports) is in it, so any change restarts the
// listeners. Without a section the legacy file applies and cannot be
// fingerprinted here, so every config version restarts them.
func decoysSection(c *plan.AgentConfig) (string, bool) {
	if !hasDecoyRole(c) {
		return "", false
	}
	if c.Modules.Deception != nil {
		return fp(c.Modules.Deception), true
	}
	return fp([]any{c.Version, c.Epoch}), true
}

func hasDecoyRole(c *plan.AgentConfig) bool { return slices.Contains(c.Roles, "decoys") }

// declaredPorts are the ports of every service the host declares (the net
// module's service map, "proto/port"): a decoy never sits on any of them, a
// superset of the scored ports.
func declaredPorts(c *plan.AgentConfig) []uint16 {
	var out []uint16
	if c.Modules.Net == nil {
		return nil
	}
	for k, name := range c.Modules.Net.Services {
		if strings.HasPrefix(name, "decoy-") {
			continue // the controller names the decoys' own ports in the same map
		}
		if _, p, ok := strings.Cut(k, "/"); ok {
			if n, err := strconv.ParseUint(p, 10, 16); err == nil {
				out = append(out, uint16(n))
			}
		}
	}
	return out
}

func init() {
	agent.RegisterFactory(agent.Factory{
		Name:    "decoys",
		Section: decoysSection,
		Build:   buildDecoys,
	})
	agent.RegisterFactory(agent.Factory{
		Name: "honeywatch",
		Section: func(c *plan.AgentConfig) (string, bool) {
			if !hasDecoyRole(c) || runtime.GOOS != "linux" {
				return "", false
			}
			return decoysSection(c)
		},
		Build: buildHoneywatch,
	})
	agent.RegisterFactory(agent.Factory{
		Name: "akiascan",
		Section: func(c *plan.AgentConfig) (string, bool) {
			return "v1", c.Modules.Detect != nil
		},
		Build: func(env agent.Env, _ *plan.AgentConfig) (agent.ModuleSpec, error) {
			return spec(&honeytokens.AKIAScanner{Subscribe: env.Subscribe}, 20, 50), nil
		},
	})
}

// deceptionSettings returns the effective decoy configuration: the signed
// section when present, else the legacy deception.json.
func deceptionSettings(env agent.Env, c *plan.AgentConfig) (*plan.DeceptionSettings, error) {
	if d := c.Modules.Deception; d != nil {
		return d, nil
	}
	lc, err := decoys.LoadLocalConfig(filepath.Join(env.StateDir, DeceptionFile))
	if err != nil {
		return nil, unavailable("no decoy configuration (neither a signed deception section nor " + DeceptionFile + "): " + err.Error())
	}
	if env.Logger != nil {
		env.Logger.Warn("decoys: using the unsigned " + DeceptionFile + "; have the controller send a deception section")
	}
	d := &plan.DeceptionSettings{Bind: lc.Bind, ScoredPorts: lc.ScoredPorts, WatchPaths: lc.WatchPaths, InProcess: true}
	for _, l := range lc.Listeners {
		d.Listeners = append(d.Listeners, plan.DecoyListenerSettings{Kind: l.Kind, Port: l.Port})
	}
	for _, t := range lc.Tokens {
		d.Tokens = append(d.Tokens, plan.HoneyToken{ID: t.ID, Host: t.Host, Kind: string(t.Kind), Path: t.Path,
			User: t.User, Secret: t.Secret, Fingerprint: t.Fingerprint, SPN: t.SPN})
	}
	return d, nil
}

func tokensOf(d *plan.DeceptionSettings) []honeytokens.Token {
	out := make([]honeytokens.Token, 0, len(d.Tokens))
	for _, t := range d.Tokens {
		out = append(out, honeytokens.Token{ID: t.ID, Host: t.Host, Kind: honeytokens.Kind(t.Kind), Path: t.Path,
			User: t.User, Secret: t.Secret, Fingerprint: t.Fingerprint, SPN: t.SPN})
	}
	return out
}

func registryOf(d *plan.DeceptionSettings) (*honeytokens.Registry, error) {
	r := honeytokens.NewRegistry()
	for _, t := range tokensOf(d) {
		if err := r.Add(t); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func buildDecoys(env agent.Env, c *plan.AgentConfig) (agent.ModuleSpec, error) {
	d, err := deceptionSettings(env, c)
	if err != nil {
		return agent.ModuleSpec{}, err
	}
	scored := append(append([]uint16(nil), d.ScoredPorts...), declaredPorts(c)...)
	var ls []decoys.Listener
	for _, l := range d.Listeners {
		ls = append(ls, decoys.Listener{Kind: l.Kind, Port: l.Port})
	}
	// Persistent SSH host key in the state dir (also validates the listeners
	// before anything binds).
	var keyPEM []byte
	if env.StateDir != "" && slices.ContainsFunc(ls, func(l decoys.Listener) bool { return l.Kind == decoys.KindSSH }) {
		if keyPEM, err = sandbox.LoadOrCreateHostKey(filepath.Join(env.StateDir, sandbox.HostKeyFile)); err != nil {
			return agent.ModuleSpec{}, err
		}
	}
	if runtime.GOOS == "linux" && !d.InProcess {
		m, err := sandbox.New(sandbox.Options{User: d.SandboxUser, Logger: env.Logger, Spec: sandbox.Spec{
			Host: env.Host, Bind: d.Bind, Listeners: ls, ScoredPorts: scored, Tokens: tokensOf(d), HostKeyPEM: string(keyPEM)}})
		if err != nil {
			return agent.ModuleSpec{}, err // refuses a scored or declared port
		}
		return spec(m, 20, 50), nil
	}
	reg, err := registryOf(d)
	if err != nil {
		return agent.ModuleSpec{}, err
	}
	cfg := decoys.Config{Host: env.Host, Bind: d.Bind, Tokens: reg, Logger: env.Logger, ScoredPorts: scored, Listeners: ls}
	if keyPEM != nil {
		if cfg.HostKey, err = sandbox.Signer(keyPEM); err != nil {
			return agent.ModuleSpec{}, fmt.Errorf("decoy host key: %w", err)
		}
	}
	m, err := decoys.New(cfg) // refuses a scored or declared port
	if err != nil {
		return agent.ModuleSpec{}, err
	}
	return spec(m, 20, 50), nil
}

func buildHoneywatch(env agent.Env, c *plan.AgentConfig) (agent.ModuleSpec, error) {
	d, err := deceptionSettings(env, c)
	if err != nil || len(d.WatchPaths) == 0 {
		return agent.ModuleSpec{}, unavailable("no honey files to watch")
	}
	reg, err := registryOf(d)
	if err != nil {
		return agent.ModuleSpec{}, err
	}
	w, err := honeytokens.NewFanotify()
	if err != nil {
		return agent.ModuleSpec{}, unavailable(err.Error())
	}
	return spec(&honeytokens.WatchModule{W: w, Paths: d.WatchPaths, Reg: reg, Host: env.Host,
		IgnorePID: os.Getpid()}, 10, 20), nil
}
