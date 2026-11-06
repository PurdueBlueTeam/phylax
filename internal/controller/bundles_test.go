package controller

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	phyagent "github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/link"
)

func bundleDir(t *testing.T) string { return filepath.Join(t.TempDir(), "bundles") }

func readBundle(t *testing.T, dir, host string) (*phyagent.Bundle, os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, host+".json")
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := phyagent.ParseBundle(data)
	if err != nil {
		t.Fatalf("ParseBundle(%s): %v", host, err)
	}
	return b, fi.Mode().Perm()
}

func TestWriteBundles_ParseAndEnroll(t *testing.T) {
	x := newCtl(t)
	dir := bundleDir(t)
	opts := BundleOptions{Controllers: []string{"10.0.0.5:7443"}, TTL: time.Hour, Safe: true}
	if err := x.c.WriteBundles(dir, []string{"h1", "h2"}, opts); err != nil {
		t.Fatal(err)
	}
	wantKey := hex.EncodeToString(x.c.PlanPublicKey())
	tokens := map[string]string{}
	for _, host := range []string{"h1", "h2"} {
		b, mode := readBundle(t, dir, host)
		if mode != 0o600 {
			t.Errorf("%s: mode %o, want 600", host, mode)
		}
		if b.Host != host {
			t.Errorf("%s: Host %q", host, b.Host)
		}
		if b.Token == "" {
			t.Errorf("%s: empty token", host)
		}
		if !b.Safe {
			t.Errorf("%s: Safe is false", host)
		}
		if len(b.Controllers) != 1 || b.Controllers[0] != "10.0.0.5:7443" {
			t.Errorf("%s: Controllers %v", host, b.Controllers)
		}
		pin, err := link.ParsePin(b.ControllerPin)
		if err != nil {
			t.Errorf("%s: ControllerPin: %v", host, err)
		} else if pin != x.c.Pin() {
			t.Errorf("%s: ControllerPin %s, want %s", host, pin, x.c.Pin())
		}
		if b.PlanKey != wantKey {
			t.Errorf("%s: PlanKey %q, want %q", host, b.PlanKey, wantKey)
		}
		if prev, ok := tokens[b.Token]; ok {
			t.Errorf("%s: token equals %s's token", host, prev)
		}
		tokens[b.Token] = host
	}
	if fi, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %o, want 700", fi.Mode().Perm())
	}
}

func TestWriteBundles_UnknownHostWritesNothing(t *testing.T) {
	x := newCtl(t)
	dir := bundleDir(t)
	err := x.c.WriteBundles(dir, []string{"h1", "ghost"}, BundleOptions{Controllers: []string{"10.0.0.5:7443"}})
	if !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("err %v, want ErrUnknownHost", err)
	}
	ents, rerr := os.ReadDir(dir)
	if rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		t.Fatal(rerr)
	}
	if len(ents) != 0 {
		t.Fatalf("dir has %d entries, want none", len(ents))
	}
	// A token minted after the refused call must still work: nothing was spent.
	if _, err := x.c.MintToken("h1", 0); err != nil {
		t.Fatalf("MintToken after refusal: %v", err)
	}
}

func TestWriteBundles_RequiresController(t *testing.T) {
	x := newCtl(t)
	dir := bundleDir(t)
	if err := x.c.WriteBundles(dir, []string{"h1"}, BundleOptions{}); err == nil {
		t.Fatal("empty Controllers: no error")
	}
	ents, rerr := os.ReadDir(dir)
	if rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		t.Fatal(rerr)
	}
	if len(ents) != 0 {
		t.Fatalf("dir has %d entries, want none", len(ents))
	}
}
