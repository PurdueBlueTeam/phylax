package vault

import (
	"errors"
	"testing"
)

func TestScoped(t *testing.T) {
	v, _ := newVault(t)
	if _, err := v.Put("a", NewSecretString("one"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put("b", NewSecretString("two"), ""); err != nil {
		t.Fatal(err)
	}
	r := Scoped(v, []string{"a"})
	if s, err := r.Get("a"); err != nil || s.Reveal() == "" {
		t.Fatalf("a: %v", err)
	}
	if _, err := r.Get("b"); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("b: %v", err)
	}
	v.Lock()
	if _, err := r.Get("a"); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked: %v", err)
	}
}

func TestScopedPrefixGrant(t *testing.T) {
	v, _ := newVault(t)
	for _, n := range []string{"cred/palo1/phylax", "cred/vyos/phylax", "credx/a", "pcr/h1"} {
		if _, err := v.Put(n, NewSecretString("x"), ""); err != nil {
			t.Fatal(err)
		}
	}
	r := Scoped(v, []string{"cred/*"})
	if _, err := r.Get("cred/palo1/phylax"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get("cred/vyos/phylax"); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"credx/a", "pcr/h1"} {
		if _, err := r.Get(n); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s: %v", n, err)
		}
	}
}

func TestCovers(t *testing.T) {
	g := []string{"cred/*", "notify.webhook"}
	for name, want := range map[string]bool{"cred/h1/admin": true, "cred/": true, "cred": false, "credx/a": false, "notify.webhook": true, "notify.webhook2": false, "cred/*": true} {
		if Covers(g, name) != want {
			t.Errorf("%q: want %v", name, want)
		}
	}
}
