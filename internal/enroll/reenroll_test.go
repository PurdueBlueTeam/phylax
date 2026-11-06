package enroll

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

func TestReenrollOrder(t *testing.T) {
	m, err := manifest.LoadDir("../../manifest/2027", manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	order := ReenrollOrder(m)
	if len(order) != len(m.Hosts) {
		t.Fatalf("order has %d hosts, manifest has %d", len(order), len(m.Hosts))
	}
	if order[0] != "ad" {
		t.Fatalf("first host = %q, want the domain controller ad", order[0])
	}
	seenMember := false
	for _, name := range order {
		h := m.Hosts[name]
		if h.HasRole(manifest.RoleDomainController) {
			continue
		}
		if h.DomainMember == "" {
			if seenMember {
				t.Fatalf("%s (not a domain member) comes after a member: %v", name, order)
			}
			continue
		}
		seenMember = true
	}
	if again := ReenrollOrder(m); !reflect.DeepEqual(order, again) {
		t.Fatalf("order is not stable: %v then %v", order, again)
	}
}

// enrolledHosts puts three hosts in the store with different keys.
func enrolledHosts(t *testing.T, f *enrFixture) map[string]link.Pin {
	t.Helper()
	pins := map[string]link.Pin{"h1": {1}, "h2": {2}, "h3": {3}}
	for host, pin := range pins {
		if err := f.st.EnrollAgent(context.Background(), host, pin[:]); err != nil {
			t.Fatal(err)
		}
	}
	return pins
}

func TestReenrollAllRevokesInOrderAndReportsFailures(t *testing.T) {
	f := newEnroller(t)
	pins := enrolledHosts(t, f)
	var mu sync.Mutex
	var pushed []string
	var disconnected []string
	f.e.opt.Disconnect = func(host string) {
		mu.Lock()
		defer mu.Unlock()
		disconnected = append(disconnected, host)
	}
	pushErr := errors.New("boom")
	results := f.e.ReenrollAll(context.Background(), []string{"h1", "h2", "h3"},
		func(string) string { return "ssh" },
		func(_ context.Context, host string) error {
			if !f.e.Revoked(host) {
				t.Errorf("%s was pushed before it was revoked", host)
			}
			mu.Lock()
			pushed = append(pushed, host)
			mu.Unlock()
			if host == "h2" {
				return pushErr
			}
			return nil
		})
	if len(results) != 3 {
		t.Fatalf("results = %d, want 3", len(results))
	}
	for i, want := range []string{"h1", "h2", "h3"} {
		if results[i].Target.Host != want {
			t.Fatalf("result %d = %q, want %q", i, results[i].Target.Host, want)
		}
	}
	if !errors.Is(results[1].Err, pushErr) || results[0].Err != nil || results[2].Err != nil {
		t.Fatalf("results errors = %v, %v, %v; want only h2 to fail", results[0].Err, results[1].Err, results[2].Err)
	}
	if want := []string{"h1", "h2", "h3"}; !reflect.DeepEqual(pushed, want) {
		t.Fatalf("push order = %v, want %v", pushed, want)
	}
	if want := []string{"h1", "h2", "h3"}; !reflect.DeepEqual(disconnected, want) {
		t.Fatalf("disconnect order = %v, want %v", disconnected, want)
	}
	for _, host := range []string{"h1", "h2", "h3"} {
		if !f.e.Revoked(host) {
			t.Fatalf("%s is not revoked after ReenrollAll", host)
		}
	}

	// A failed push leaves the host revoked, so a fresh token still finishes it.
	tok, err := f.e.MintToken("h2", 0)
	if err != nil {
		t.Fatal(err)
	}
	newPin := link.Pin{22}
	res, err := f.e.Authorize(context.Background(), &link.Hello{Proto: 1, Host: "h2", Token: tok}, newPin)
	if err != nil {
		t.Fatalf("Authorize after the failed push: %v", err)
	}
	if !res.Reenrolled {
		t.Fatalf("Result = %+v, want Reenrolled", res)
	}
	if f.e.Revoked("h2") {
		t.Fatal("a fresh token did not clear h2's revoke flag")
	}
	if ag, err := f.st.Agent(context.Background(), "h2"); err != nil || string(ag.PubKey) != string(newPin[:]) {
		t.Fatalf("h2 key = %x, %v; want the new key", ag.PubKey, err)
	}
	old := pins["h2"]
	if string(old[:]) == string(newPin[:]) {
		t.Fatal("test bug: the new key equals the old one")
	}
}

func TestReenrollAllGroupBarrier(t *testing.T) {
	f := newEnroller(t)
	var dcStart, dcEnd, memberStart time.Time
	results := f.e.ReenrollAll(context.Background(), []string{"dc", "member"},
		func(string) string { return "ssh" },
		func(_ context.Context, host string) error {
			switch host {
			case "dc":
				dcStart = time.Now()
				time.Sleep(50 * time.Millisecond)
				dcEnd = time.Now()
			case "member":
				memberStart = time.Now()
			}
			return nil
		})
	if len(results) != 2 || results[0].Err != nil || results[1].Err != nil {
		t.Fatalf("results = %+v", results)
	}
	if dcStart.IsZero() || memberStart.IsZero() {
		t.Fatalf("push calls missing: dc=%v member=%v", dcStart, memberStart)
	}
	if memberStart.Before(dcEnd) {
		t.Fatalf("the member push started at %v, before the DC push finished at %v", memberStart, dcEnd)
	}
}
