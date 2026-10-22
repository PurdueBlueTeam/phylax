package plan

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/link"
)

func cfgFixture(t *testing.T) (ed25519.PrivateKey, *ConfigVerifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, &ConfigVerifier{Key: pub, HostID: "h1", Store: FileSeqStore{Path: filepath.Join(t.TempDir(), "configseq.json")}}
}

func mkCfg(host string, epoch, ver uint64) *AgentConfig {
	return &AgentConfig{Host: host, Epoch: epoch, Version: ver, IssuedAt: 100, Roles: []string{"capture"},
		Modules: ModuleSettings{Net: &NetSettings{Services: map[string]string{"tcp/80": "web"}}, Health: &HealthSettings{IntervalSec: 60}}}
}

func wantCfgErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
}

func TestConfigSignVerify(t *testing.T) {
	priv, v := cfgFixture(t)
	w, err := SignConfig(priv, mkCfg("h1", 1, 1))
	if err != nil {
		t.Fatal(err)
	}
	c, err := v.Verify(w)
	if err != nil || c.Modules.Net.Services["tcp/80"] != "web" || c.Version != 1 {
		t.Fatalf("verify: %+v %v", c, err)
	}
	// Signing is deterministic: the same content re-sent is byte-identical.
	w2, _ := SignConfig(priv, mkCfg("h1", 1, 1))
	if w.Sig != w2.Sig || string(w.Body) != string(w2.Body) {
		t.Fatal("signature not deterministic")
	}
}

func TestConfigRefusals(t *testing.T) {
	priv, v := cfgFixture(t)
	good, _ := SignConfig(priv, mkCfg("h1", 1, 5))

	tamper := func(f func(*AgentConfig)) *link.Config {
		var c AgentConfig
		if err := json.Unmarshal(good.Body, &c); err != nil {
			t.Fatal(err)
		}
		f(&c)
		b, _ := json.Marshal(c)
		return &link.Config{Version: c.Version, Epoch: c.Epoch, Body: b, Sig: good.Sig}
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	foreign, _ := SignConfig(other, mkCfg("h1", 1, 6))
	wrongHost, _ := SignConfig(priv, mkCfg("h2", 1, 6))
	envMismatch := *good
	envMismatch.Version = 6

	for name, tc := range map[string]struct {
		w    *link.Config
		want error
	}{
		"tampered setting":  {tamper(func(c *AgentConfig) { c.Modules.Net.Services["tcp/80"] = "evil" }), ErrBadSignature},
		"tampered host":     {tamper(func(c *AgentConfig) { c.Host = "h2" }), ErrBadSignature},
		"foreign signer":    {foreign, ErrBadSignature},
		"other host":        {wrongHost, ErrWrongHost},
		"envelope mismatch": {&envMismatch, ErrMalformed},
		"no signature":      {&link.Config{Version: 5, Epoch: 1, Body: good.Body}, ErrBadSignature},
		"garbage body":      {&link.Config{Version: 5, Epoch: 1, Body: json.RawMessage(`{"a":1.5}`), Sig: good.Sig}, ErrMalformed},
		"oversized body":    {&link.Config{Version: 5, Epoch: 1, Body: json.RawMessage(strings.Repeat(" ", MaxConfigBody+1)), Sig: good.Sig}, ErrMalformed},
		"nil":               {nil, ErrMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(tc.w)
			wantCfgErr(t, err, tc.want)
		})
	}
	// None of the refusals moved the mark.
	if m, _ := v.Store.Load(); m != (Mark{}) {
		t.Fatalf("mark moved to %+v by refused configs", m)
	}
}

func TestConfigReplayAndEpoch(t *testing.T) {
	priv, v := cfgFixture(t)
	sign := func(epoch, ver uint64) *link.Config {
		w, err := SignConfig(priv, mkCfg("h1", epoch, ver))
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	v5 := sign(2, 5)
	c, err := v.Verify(v5)
	if err != nil {
		t.Fatal(err)
	}
	// Accepted but not yet applied (crash before persisting): may be presented again.
	if _, err := v.Verify(v5); err != nil {
		t.Fatalf("retry of an unapplied config: %v", err)
	}
	dg, _ := c.Digest()
	v.MarkApplied(2, 5, dg)
	_, err = v.Verify(v5)
	wantCfgErr(t, err, ErrConfigCurrent)
	// A different body under the same (epoch, version) is a replay, not "current".
	other := mkCfg("h1", 2, 5)
	other.Roles = []string{"scanner"}
	w, _ := SignConfig(priv, other)
	_, err = v.Verify(w)
	wantCfgErr(t, err, ErrReplay)
	// Older version, same epoch.
	_, err = v.Verify(sign(2, 4))
	wantCfgErr(t, err, ErrReplay)
	// Older epoch, even with a huge version.
	_, err = v.Verify(sign(1, 900))
	wantCfgErr(t, err, ErrStaleEpoch)
	// Newer version and a newer epoch with a lower version are fine.
	if _, err := v.Verify(sign(2, 6)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(sign(3, 1)); err != nil {
		t.Fatalf("restore bumps the epoch and resets versions: %v", err)
	}
	// The mark is durable: a fresh verifier on the same store still refuses.
	v2 := &ConfigVerifier{Key: v.Key, HostID: "h1", Store: v.Store}
	_, err = v2.Verify(sign(2, 6))
	wantCfgErr(t, err, ErrStaleEpoch)
}

func TestRuleStream(t *testing.T) {
	d := &DetectSettings{Rules: []RuleFile{
		{Name: "a\nb.yml", YAML: "---\n# c\nid: x\n---\n"},
		{Name: "empty.yml", YAML: "  \n"},
		{Name: "b.yml", YAML: "id: y"},
	}}
	got := string(d.RuleStream())
	if strings.Count(got, "---\n") != 2 || strings.Contains(got, "a\nb") || !strings.Contains(got, "id: y") {
		t.Fatalf("stream:\n%s", got)
	}
}
