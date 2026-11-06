package plan

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/module"
)

func TestModuleLimitsCarriesCommon(t *testing.T) {
	b, _ := json.Marshal(NetSettings{ModuleLimits: ModuleLimits{Common: module.Common{Enabled: true}}})
	if !bytes.Contains(b, []byte(`"enabled":true`)) || !bytes.Contains(b, []byte(`"act_enabled":false`)) {
		t.Fatalf("%s", b)
	}
}

func TestConfigParseRejectsUnknownField(t *testing.T) {
	priv, v := cfgFixture(t)
	good, err := SignConfig(priv, mkCfg("h1", 1, 1))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(good.Body, &doc); err != nil {
		t.Fatal(err)
	}
	net, ok := doc["modules"].(map[string]any)["net"].(map[string]any)
	if !ok {
		t.Fatalf("no modules.net in %s", good.Body)
	}
	net["x_typo"] = 1
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, configSigningBytes(canon))
	w := &link.Config{Version: 1, Epoch: 1, Body: canon, Sig: hex.EncodeToString(sig)}
	_, err = v.Parse(w)
	if err == nil || !strings.Contains(err.Error(), "x_typo") {
		t.Fatalf("got %v", err)
	}
}

func TestBlockFor(t *testing.T) {
	cfg := &AgentConfig{Modules: ModuleSettings{Net: &NetSettings{}}}
	if b, ok := BlockFor(cfg, "net"); !ok || b.(*NetSettings) == nil {
		t.Fatal("net")
	}
	if b, ok := BlockFor(cfg, "audit"); !ok || b.(*AuditSettings) != nil {
		t.Fatal("absent block must be a typed nil")
	}
	if _, ok := BlockFor(cfg, "nope"); ok {
		t.Fatal("unknown module")
	}
}
