package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/PurdueBlueTeam/phylax/internal/honeytokens"
	"github.com/PurdueBlueTeam/phylax/internal/store"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

// The honeytoken registry (design: Deception). The controller generates the
// tokens from decoys.yml, keeps them durably, and feeds them three ways:
//
//   - the signed AgentConfig carries the tokens to the decoy hosts (the decoys
//     compare what an attacker types against them) and the detection seeds
//     (honeytoken.accounts, .spns, .paths, .aws_keys) to every host with
//     rules, so D15c-g fire;
//   - the deploy plan plants them (file.plant, ad.honey_account), the secret
//     bait content travelling as step secrets resolved from the vault;
//   - Registry.Attribute names the looted host on alerts (alerts.go).
//
// Persistence: token metadata (everything but secret material) is one JSON
// record in the store's meta table; every secret value (the token's password
// or key, each planted file body, each AD password) is a vault entry
// honeytoken/<id>/<name>. A store dump therefore holds no secret, and without
// the vault the registry loads without secrets (alerting, not matching them).

// SecretVault is the part of *vault.Vault the controller uses.
type SecretVault interface {
	Put(name string, value vault.Secret, note string) (string, error)
	Get(name string) (vault.Secret, string, error)
}

const (
	honeyMetaKey     = "honeytokens"
	honeyVaultPrefix = "honeytoken/"
	honeyDocVersion  = 1
)

// HoneyStep is one planting step of a token: an action the deploy plan runs on
// the token's host. Secret parameters are vault references, never values.
type HoneyStep struct {
	Token string `json:"token"`
	Host  string `json:"host"`
	// Action is file.plant or ad.honey_account.
	Action       string            `json:"action"`
	Params       map[string]any    `json:"params"`
	SecretParams []string          `json:"secret_params,omitempty"`
	SecretRefs   map[string]string `json:"secret_refs,omitempty"`
	OnlyIfAbsent bool              `json:"only_if_absent,omitempty"`
	Risk         string            `json:"risk"`
	Note         string            `json:"note,omitempty"`
}

type honeyDoc struct {
	V      int                 `json:"v"`
	Tokens []honeytokens.Token `json:"tokens"`
	Steps  []HoneyStep         `json:"steps"`
}

type honeyState struct {
	mu    sync.RWMutex
	reg   *honeytokens.Registry
	steps []HoneyStep
	hosts map[string]bool // hosts with generated tokens
	// noSecrets: the registry was loaded without secret material (no vault, or
	// it is locked). Credential matching at decoys is blind until
	// ReloadHoneytokenSecrets.
	noSecrets bool
}

func (h *honeyState) init() {
	h.reg, h.hosts = honeytokens.NewRegistry(), map[string]bool{}
}

func vaultName(token, what string) string { return honeyVaultPrefix + token + "/" + what }

// loadHoneytokens reads the registry from the store and the vault.
func (c *Controller) loadHoneytokens(ctx context.Context) error {
	c.honey.init()
	raw, err := c.st.MetaGet(ctx, honeyMetaKey)
	if errors.Is(err, store.ErrNoMeta) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("controller: honeytokens: %w", err)
	}
	var d honeyDoc
	if err := json.Unmarshal([]byte(raw), &d); err != nil || d.V != honeyDocVersion {
		// Fail closed: starting with an empty registry would let the next
		// generation reuse (and so collide with) planted values.
		return fmt.Errorf("controller: honeytokens record unreadable (version %d): %v", d.V, err)
	}
	return c.installHoney(d, true)
}

// installHoney builds the in-memory registry from a record, filling secrets
// from the vault when possible.
func (c *Controller) installHoney(d honeyDoc, alert bool) error {
	reg := honeytokens.NewRegistry()
	missing := false
	hosts := map[string]bool{}
	for _, t := range d.Tokens {
		if t.Secret == "" && tokenHasSecret(t) {
			if s, ok := c.vaultGet(vaultName(t.ID, "secret")); ok {
				t.Secret = s
			} else {
				missing = true
			}
		}
		if err := reg.Add(t); err != nil {
			return fmt.Errorf("controller: honeytokens: %w", err)
		}
		hosts[t.Host] = true
	}
	c.honey.mu.Lock()
	c.honey.reg, c.honey.steps, c.honey.hosts, c.honey.noSecrets = reg, d.Steps, hosts, missing
	c.honey.mu.Unlock()
	if missing && alert {
		c.alert("", "honeytokens.secrets_unavailable",
			"honeytoken secrets could not be read from the vault (locked or not configured): decoys will not recognise honey passwords until it is unlocked")
	}
	return nil
}

// tokenHasSecret reports whether a token kind carries secret material at all
// (ssh keys and honey files are identified by fingerprint or path).
func tokenHasSecret(t honeytokens.Token) bool {
	switch t.Kind {
	case honeytokens.KindSSHKey, honeytokens.KindHoneyFile:
		return false
	}
	return true
}

func (c *Controller) vaultGet(name string) (string, bool) {
	if c.opt.Vault == nil {
		return "", false
	}
	s, _, err := c.opt.Vault.Get(name)
	if err != nil {
		return "", false
	}
	return s.Reveal(), true
}

// ReloadHoneytokenSecrets re-reads the registry after the vault was unlocked
// and pushes the configs that changed.
func (c *Controller) ReloadHoneytokenSecrets(ctx context.Context) error {
	d, err := c.honeyDoc(ctx)
	if err != nil {
		return err
	}
	if err := c.installHoney(d, false); err != nil {
		return err
	}
	c.honeyChanged(ctx)
	return nil
}

func (c *Controller) honeyDoc(ctx context.Context) (honeyDoc, error) {
	raw, err := c.st.MetaGet(ctx, honeyMetaKey)
	if errors.Is(err, store.ErrNoMeta) {
		return honeyDoc{V: honeyDocVersion}, nil
	}
	if err != nil {
		return honeyDoc{}, err
	}
	var d honeyDoc
	return d, json.Unmarshal([]byte(raw), &d)
}

// HoneytokenSteps returns the planting steps for the given hosts (all if none).
func (c *Controller) HoneytokenSteps(hosts ...string) []HoneyStep {
	c.honey.mu.RLock()
	defer c.honey.mu.RUnlock()
	var out []HoneyStep
	for _, s := range c.honey.steps {
		if len(hosts) == 0 || containsStr(hosts, s.Host) {
			out = append(out, s)
		}
	}
	return out
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// HoneytokenSeeds are the detection profiles for the rules in
// rules/deception.yml (Registry.Seeds).
func (c *Controller) HoneytokenSeeds() map[string][]string {
	c.honey.mu.RLock()
	defer c.honey.mu.RUnlock()
	return c.honey.reg.Seeds()
}

// honeyTokens snapshots every token, secrets included, for config generation.
func (c *Controller) honeyTokens() []honeytokens.Token {
	c.honey.mu.RLock()
	defer c.honey.mu.RUnlock()
	return c.honey.reg.Tokens()
}

// AttributeHoneytoken resolves event fields to the honeytoken involved and the
// host it was planted on.
func (c *Controller) AttributeHoneytoken(fields map[string]any) (honeytokens.Token, bool) {
	c.honey.mu.RLock()
	reg := c.honey.reg
	c.honey.mu.RUnlock()
	return reg.Attribute(fields)
}

// honeyChanged invalidates the generated configs and pushes the new ones.
func (c *Controller) honeyChanged(ctx context.Context) {
	c.pushAll(ctx)
}

// GenerateHoneytokens generates and persists the tokens of the named hosts
// (every host with a decoys.yml entry that has none yet if no host is named),
// then pushes the changed agent configs. Hosts that already have tokens are
// left alone, so calling it again is safe. It returns the hosts generated.
//
// All or nothing: the generator runs against a copy of the registry, the vault
// entries and the store record are written, and only then is the live registry
// replaced.
func (c *Controller) GenerateHoneytokens(ctx context.Context, hosts ...string) ([]string, error) {
	if c.opt.Vault == nil {
		return nil, errors.New("honeytokens: no vault is configured; secret bait cannot be stored")
	}
	c.cfgs.mu.Lock()
	in := c.cfgs.in
	c.cfgs.mu.Unlock()
	if in == nil || in.Manifest == nil {
		return nil, errors.New("honeytokens: no manifest loaded")
	}
	m := in.Manifest
	if len(hosts) == 0 {
		for h, d := range m.Decoys {
			if len(d.Honeytokens)+len(d.HoneyFiles) > 0 {
				hosts = append(hosts, h)
			}
		}
	}
	sort.Strings(hosts)

	c.honeyGen.Lock() // serialise generators; readers keep using the live registry
	defer c.honeyGen.Unlock()
	c.honey.mu.RLock()
	live := c.honey.reg
	oldSteps := append([]HoneyStep(nil), c.honey.steps...)
	have := map[string]bool{}
	for h := range c.honey.hosts {
		have[h] = true
	}
	c.honey.mu.RUnlock()

	work := honeytokens.NewRegistry()
	for _, t := range live.Tokens() {
		if err := work.Add(t); err != nil {
			return nil, err
		}
	}
	gen := honeytokens.NewGenerator(work)
	var done []string
	var newSteps []HoneyStep
	var newToks []honeytokens.Token
	vaultWrites := map[string]string{}
	for _, h := range hosts {
		if have[h] {
			continue
		}
		hm, ok := m.Hosts[h]
		d := m.Decoys[h]
		if !ok {
			return nil, fmt.Errorf("honeytokens: host %q is not in the manifest", h)
		}
		spec := honeytokens.HostSpec{Host: h, Windows: hm.IsWindows(), Domain: d.Domain, HoneyFiles: d.HoneyFiles}
		for _, t := range d.Honeytokens {
			spec.Tokens = append(spec.Tokens, honeytokens.TokenDef{Kind: t.Kind, At: t.At})
		}
		hp, err := gen.ForHost(spec)
		if err != nil {
			return nil, err
		}
		if len(hp.Tokens) == 0 {
			continue
		}
		newToks = append(newToks, hp.Tokens...)
		for _, a := range hp.Actions {
			st := HoneyStep{Token: a.Token, Host: a.Host, Action: a.Action, Risk: a.Risk, Note: a.Note,
				OnlyIfAbsent: a.OnlyIfAbsent, Params: map[string]any{}}
			secret := map[string]bool{}
			for _, n := range a.SecretParams {
				secret[n] = true
			}
			for k, v := range a.Params {
				if !secret[k] {
					st.Params[k] = v
					continue
				}
				s, _ := v.(string)
				name := vaultName(a.Token, k)
				vaultWrites[name] = s
				if st.SecretRefs == nil {
					st.SecretRefs = map[string]string{}
				}
				st.SecretRefs[k] = name
				st.SecretParams = append(st.SecretParams, k)
			}
			sort.Strings(st.SecretParams)
			newSteps = append(newSteps, st)
		}
		done = append(done, h)
	}
	if len(done) == 0 {
		return nil, nil
	}
	for _, t := range newToks {
		if t.Secret != "" {
			vaultWrites[vaultName(t.ID, "secret")] = t.Secret
		}
	}
	names := make([]string, 0, len(vaultWrites))
	for n := range vaultWrites {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if _, err := c.opt.Vault.Put(n, vault.NewSecretString(vaultWrites[n]), "honeytoken"); err != nil {
			return nil, fmt.Errorf("honeytokens: vault: %w", err)
		}
	}
	// Persist metadata without secret material.
	doc := honeyDoc{V: honeyDocVersion, Steps: append(oldSteps, newSteps...)}
	for _, t := range work.Tokens() {
		t.Secret = ""
		doc.Tokens = append(doc.Tokens, t)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	if err := c.st.MetaSet(ctx, honeyMetaKey, string(raw)); err != nil {
		return nil, fmt.Errorf("honeytokens: persist: %w", err)
	}
	c.honey.mu.Lock()
	c.honey.reg, c.honey.steps = work, doc.Steps
	for _, h := range done {
		c.honey.hosts[h] = true
	}
	c.honey.mu.Unlock()
	c.log.Info("honeytokens generated", "hosts", strings.Join(done, ","), "tokens", len(newToks))
	c.honeyChanged(ctx)
	return done, nil
}
