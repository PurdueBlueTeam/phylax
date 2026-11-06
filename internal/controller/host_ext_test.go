package controller

import (
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

func TestHostManifestNotNil(t *testing.T) {
	t.Skip("unimplemented: W1 Task 17a")
	c := newTestControllerWithManifest(t, nil)
	m := c.hostFor(testMod()).Manifest()
	if m == nil || len(m.Hosts) == 0 {
		t.Fatalf("%+v", m)
	}
}

func TestHostUpdateOverridesReloads(t *testing.T) {
	t.Skip("unimplemented: W1 Task 17a")
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
	t.Skip("unimplemented: W1 Task 17a")
	// block "enabled: true\nsecrets: [cred/*]\n"; unlocked test vault holds "cred/palo1/phylax", "cred/vyos/phylax", "other"
	// h.Secrets("cred/*") -> reader; Get("cred/palo1/phylax") and Get("cred/vyos/phylax") ok; Get("other") -> vault.ErrNotAllowed
	// h.Secrets("cred/palo1/phylax") -> ok (covered by the grant); h.Secrets("other") -> vault.ErrNotAllowed
}
