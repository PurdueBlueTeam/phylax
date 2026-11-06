package controller

import (
	"errors"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

func TestHostManifestNotNil(t *testing.T) {
	c := newTestControllerWithManifest(t, nil)
	m := c.hostFor(testMod()).Manifest()
	if m == nil || len(m.Hosts) == 0 {
		t.Fatalf("%+v", m)
	}
}

func TestHostUpdateOverridesReloads(t *testing.T) {
	c := newTestControllerWithManifest(t, map[string]string{"modules/ctltest.yml": "enabled: true\n"})
	h := c.hostFor(testMod())
	err := h.UpdateOverrides(func(o *manifest.Overrides) error {
		o.LearnedListeners = append(o.LearnedListeners, manifest.LearnedListener{Host: "h1", Proto: "tcp", Port: 8081, Reason: "scorer seen", Observed: "2027-02-06T15:04:05Z"})
		return nil
	})
	if err != nil || len(h.Manifest().Overrides.LearnedListeners) != 1 {
		t.Fatalf("%v %+v", err, h.Manifest().Overrides)
	}
	if h2 := c.hostFor(testMod()); len(h2.Manifest().Overrides.LearnedListeners) != 1 {
		t.Fatal("a second host handle does not see the change")
	}
	bad := h.UpdateOverrides(func(o *manifest.Overrides) error {
		o.LearnedListeners = append(o.LearnedListeners, manifest.LearnedListener{Host: "h1"})
		return nil
	})
	if bad == nil || len(h.Manifest().Overrides.LearnedListeners) != 1 {
		t.Fatal("invalid entry accepted or manifest changed")
	}
}

func TestHostSecretsPrefixGrant(t *testing.T) {
	v := newVault(t)
	for _, name := range []string{"cred/palo1/phylax", "cred/vyos/phylax", "other"} {
		if _, err := v.Put(name, vault.NewSecretString("value"), "test"); err != nil {
			t.Fatal(err)
		}
	}
	c := newTestControllerWithManifest(t, map[string]string{"modules/ctltest.yml": "enabled: true\nsecrets: [cred/*]\n"})
	c.opt.Vault = v
	h := c.hostFor(testMod())
	r, err := h.Secrets("cred/*")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cred/palo1/phylax", "cred/vyos/phylax"} {
		if _, err := r.Get(name); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := r.Get("other"); !errors.Is(err, vault.ErrNotAllowed) {
		t.Fatalf("prefix reader served another name: %v", err)
	}
	if _, err := h.Secrets("cred/palo1/phylax"); err != nil {
		t.Fatalf("covered exact name refused: %v", err)
	}
	if _, err := h.Secrets("other"); !errors.Is(err, vault.ErrNotAllowed) {
		t.Fatalf("got %v", err)
	}
}
