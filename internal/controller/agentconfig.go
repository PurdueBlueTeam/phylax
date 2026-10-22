package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/detect"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// Agent configuration: the controller derives every host's AgentConfig from
// the manifest (BuildAgentConfig), signs it with the plan key, sends it in
// `welcome` on connect and as a `config` message when the inputs change.
//
// Versions are per host and only move when the content (or the epoch) does,
// so a reconnect re-sends the identical signed message (Ed25519 is
// deterministic and IssuedAt is kept) and the agent sees "already applied".

const (
	configVersFile = "agentconfigs.json"
	// repushAfter is how long a stale config report waits before the controller
	// sends the config again (a push may have been dropped by a full queue).
	repushAfter = 15 * time.Second
)

type cfgRec struct {
	Epoch    uint64 `json:"epoch"`
	Version  uint64 `json:"version"`
	Digest   string `json:"digest"`
	IssuedAt int64  `json:"issued_at"`
}

type cfgState struct {
	mu    sync.Mutex
	in    *ConfigInputs
	gen   uint64
	recs  map[string]cfgRec
	cache map[string]cfgCached
}

type cfgCached struct {
	gen   uint64
	epoch uint64
	msg   *link.Config
}

func (c *Controller) loadConfigRecs() error {
	c.cfgs.recs, c.cfgs.cache = map[string]cfgRec{}, map[string]cfgCached{}
	b, err := os.ReadFile(filepath.Join(c.cfg.DataDir, configVersFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err == nil {
		err = json.Unmarshal(b, &c.cfgs.recs)
	}
	if err != nil {
		// Fail closed: forgetting versions could re-issue a number an agent
		// already holds with different content.
		return fmt.Errorf("controller: %s: %w", configVersFile, err)
	}
	return nil
}

// SetConfigInputs installs new config inputs (manifest, rules, ledger
// reference), validating the rules strictly, and pushes every connected
// agent whose config changed. Invalid rules are refused and the previous
// inputs stay in force.
func (c *Controller) SetConfigInputs(ctx context.Context, in ConfigInputs) error {
	if in.Manifest == nil {
		return errors.New("config inputs: manifest is required")
	}
	if len(in.Rules) > 0 {
		d := &plan.DetectSettings{Rules: in.Rules}
		if _, err := detect.Parse("config", d.RuleStream(), detect.LoadOptions{}); err != nil {
			return fmt.Errorf("config inputs: rules: %w", err)
		}
	}
	c.cfgs.mu.Lock()
	cp := in
	c.cfgs.in = &cp
	c.cfgs.gen++
	c.cfgs.mu.Unlock()
	c.pushAll(ctx)
	return nil
}

// HasConfigInputs reports whether agent configs are being generated.
func (c *Controller) HasConfigInputs() bool {
	c.cfgs.mu.Lock()
	defer c.cfgs.mu.Unlock()
	return c.cfgs.in != nil
}

// AgentConfigFor returns the signed config for host (nil, nil when there are
// no inputs or the manifest does not know the host).
func (c *Controller) AgentConfigFor(ctx context.Context, host string) (*link.Config, error) {
	c.cfgs.mu.Lock()
	defer c.cfgs.mu.Unlock()
	if c.cfgs.in == nil {
		return nil, nil
	}
	if _, ok := c.cfgs.in.Manifest.Hosts[host]; !ok {
		return nil, nil
	}
	epoch, err := c.st.Epoch(ctx)
	if err != nil {
		return nil, err
	}
	if ca, ok := c.cfgs.cache[host]; ok && ca.gen == c.cfgs.gen && ca.epoch == epoch {
		return ca.msg, nil
	}
	in := *c.cfgs.in
	in.Tokens = c.honeyTokens()
	cfg, warns, err := BuildAgentConfig(in, host)
	if err != nil {
		return nil, err
	}
	for _, w := range warns {
		c.log.Warn("agent config", "host", host, "warning", w)
	}
	cfg.Epoch = epoch
	digest, err := cfg.Digest() // Version and IssuedAt are still zero: the content digest
	if err != nil {
		return nil, err
	}
	rec := c.cfgs.recs[host]
	if rec.Digest != digest || rec.Epoch != epoch || rec.Version == 0 {
		rec = cfgRec{Epoch: epoch, Version: rec.Version + 1, Digest: digest, IssuedAt: c.now().Unix()}
		next := make(map[string]cfgRec, len(c.cfgs.recs)+1)
		for k, v := range c.cfgs.recs {
			next[k] = v
		}
		next[host] = rec
		b, _ := json.MarshalIndent(next, "", "  ")
		if err := atomicfile.WriteFile(filepath.Join(c.cfg.DataDir, configVersFile), b, 0o600); err != nil {
			return nil, fmt.Errorf("persist config versions: %w", err)
		}
		c.cfgs.recs = next
		c.log.Info("agent config changed", "host", host, "epoch", epoch, "version", rec.Version)
	}
	cfg.Version, cfg.IssuedAt = rec.Version, rec.IssuedAt
	msg, err := plan.SignConfig(c.planKey, cfg)
	if err != nil {
		return nil, err
	}
	c.cfgs.cache[host] = cfgCached{gen: c.cfgs.gen, epoch: epoch, msg: msg}
	return msg, nil
}

// pushAll sends the current config to every connected agent.
func (c *Controller) pushAll(ctx context.Context) {
	c.mu.Lock()
	states := make([]*agentState, 0, len(c.agents))
	for _, s := range c.agents {
		states = append(states, s)
	}
	c.mu.Unlock()
	for _, s := range states {
		c.pushConfig(ctx, s, false)
	}
}

// pushConfig sends s's agent its config if connected. Unless force, nothing is
// sent when the same message was already queued on this session.
func (c *Controller) pushConfig(ctx context.Context, s *agentState, force bool) {
	s.mu.Lock()
	ag := s.sess
	s.mu.Unlock()
	if ag == nil || !ag.isReady() {
		return
	}
	msg, err := c.AgentConfigFor(ctx, s.host)
	if err != nil {
		c.alert(s.host, "config.generate_failed", err.Error())
		return
	}
	if msg == nil {
		return
	}
	s.mu.Lock()
	same := s.cfgSess == ag && s.cfgSent != nil && s.cfgSent.Epoch == msg.Epoch && s.cfgSent.Version == msg.Version
	if same && !force {
		s.mu.Unlock()
		return
	}
	s.cfgSess, s.cfgSent, s.cfgPushed = ag, msg, c.now()
	s.mu.Unlock()
	if err := ag.sess.TrySend(link.PrioStep, msg); err != nil {
		c.log.Warn("config push not queued", "host", s.host, "err", err)
		s.mu.Lock()
		s.cfgSent = nil // retried on the next heartbeat that shows it stale
		s.mu.Unlock()
	}
}

// noteConfigStatus records the config status an agent reported in its
// heartbeat ("<state>/<epoch>.<version>" under module "config") and re-sends
// the config if the agent is behind.
func (c *Controller) noteConfigStatus(s *agentState, hb *link.Heartbeat) {
	v, ok := hb.Modules["config"]
	if !ok {
		return
	}
	state, epoch, ver := parseConfigStatus(v)
	s.mu.Lock()
	s.hb.ConfigState, s.hb.ConfigEpoch, s.hb.ConfigVersion = state, epoch, ver
	last := s.cfgPushed
	s.mu.Unlock()
	if !c.HasConfigInputs() || c.now().Sub(last) < repushAfter {
		return
	}
	msg, err := c.AgentConfigFor(context.Background(), s.host)
	if err != nil || msg == nil {
		return
	}
	if epoch < msg.Epoch || (epoch == msg.Epoch && ver < msg.Version) {
		c.pushConfig(context.Background(), s, true)
	}
}

func parseConfigStatus(v string) (state string, epoch, version uint64) {
	state, rest, _ := strings.Cut(v, "/")
	e, ver, _ := strings.Cut(rest, ".")
	epoch, _ = strconv.ParseUint(e, 10, 64)
	version, _ = strconv.ParseUint(ver, 10, 64)
	return state, epoch, version
}

// ---- loading and watching the inputs ----

// LoadConfigInputs reads the manifest, the rule files and the ledger reference
// named by cfg (ManifestPath is required; RulesPath and LedgerPath are optional).
func LoadConfigInputs(cfg Config) (ConfigInputs, error) {
	var in ConfigInputs
	if cfg.ManifestPath == "" {
		return in, errors.New("manifest_path is not set")
	}
	m, err := manifest.LoadDir(cfg.ManifestPath, manifest.Options{})
	if err != nil {
		return in, fmt.Errorf("manifest: %w", err)
	}
	in.Manifest = m
	if cfg.RulesPath != "" {
		files, _ := filepath.Glob(filepath.Join(cfg.RulesPath, "*.y*ml"))
		sort.Strings(files)
		for _, f := range files {
			if ext := filepath.Ext(f); ext != ".yml" && ext != ".yaml" {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				return in, err
			}
			in.Rules = append(in.Rules, plan.RuleFile{Name: filepath.Base(f), YAML: string(b)})
		}
		if len(in.Rules) == 0 {
			return in, fmt.Errorf("rules_path %s has no rule files", cfg.RulesPath)
		}
	}
	if cfg.LedgerPath != "" {
		b, err := os.ReadFile(cfg.LedgerPath)
		if err != nil {
			return in, fmt.Errorf("ledger: %w", err)
		}
		h := sha256.Sum256(b)
		in.Ledger = plan.LedgerRef{File: filepath.Base(cfg.LedgerPath), SHA256: hex.EncodeToString(h[:])}
	}
	return in, nil
}

// inputsFingerprint changes whenever a file feeding the config changes.
func inputsFingerprint(cfg Config) string {
	h := sha256.New()
	for _, root := range []string{cfg.ManifestPath, cfg.RulesPath} {
		if root == "" {
			continue
		}
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if fi, err := d.Info(); err == nil {
				fmt.Fprintf(h, "%s|%d|%d\n", p, fi.Size(), fi.ModTime().UnixNano())
			}
			return nil
		})
	}
	if cfg.LedgerPath != "" {
		if fi, err := os.Stat(cfg.LedgerPath); err == nil {
			fmt.Fprintf(h, "%s|%d|%d\n", cfg.LedgerPath, fi.Size(), fi.ModTime().UnixNano())
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// LoadAndSetConfigInputs loads the inputs named by the controller config and
// installs them (the initial load at start-up).
func (c *Controller) LoadAndSetConfigInputs(ctx context.Context) error {
	in, err := LoadConfigInputs(c.cfg)
	if err != nil {
		return err
	}
	return c.SetConfigInputs(ctx, in)
}

// WatchConfigInputs reloads the inputs whenever their files change (checked
// every interval; call LoadAndSetConfigInputs first), pushing new configs to
// connected agents. A change that does not load or validate is reported as an
// alert and the previous inputs stay in force. It blocks until ctx is cancelled.
func (c *Controller) WatchConfigInputs(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	last := inputsFingerprint(c.cfg)
	load := func() error {
		return c.LoadAndSetConfigInputs(ctx)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		fp := inputsFingerprint(c.cfg)
		if fp == last {
			continue
		}
		last = fp
		if err := load(); err != nil {
			c.alert("", "config.inputs_invalid", err.Error())
		}
	}
}

func (a *agentConn) isReady() bool {
	select {
	case <-a.ready:
		return true
	default:
		return false
	}
}
