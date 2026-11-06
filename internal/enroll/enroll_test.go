package enroll

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// enrFixture is a real Enroller over a temporary data dir, store and identity.
type enrFixture struct {
	t   *testing.T
	e   *Enroller
	dir string
	id  *link.Identity
	st  *store.Store
}

func newEnroller(t *testing.T) *enrFixture { return newEnrollerWith(t, nil) }

func newEnrollerWith(t *testing.T, mod func(*Options)) *enrFixture {
	return newEnrollerAt(t, t.TempDir(), mod)
}

func newEnrollerAt(t *testing.T, dir string, mod func(*Options)) *enrFixture {
	t.Helper()
	ctx := context.Background()
	id, err := link.GenerateIdentity("phylax-controller")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(dir, "phylax.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	o := Options{
		DataDir: dir, Store: st, Identity: id,
		PlanKey:   priv.Public().(ed25519.PublicKey),
		HostKnown: func(h string) bool { return h != "ghost" },
	}
	if mod != nil {
		mod(&o)
	}
	e, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return &enrFixture{t: t, e: e, dir: dir, id: id, st: st}
}

func (f *enrFixture) planKeyHex() string { return hex.EncodeToString(f.e.opt.PlanKey) }

func readFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	return string(b), err
}

func TestMintTokenUnknownHost(t *testing.T) {
	f := newEnroller(t)
	if _, err := f.e.MintToken("ghost", 0); !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("MintToken(ghost) err = %v, want ErrUnknownHost", err)
	}
	tok, err := f.e.MintToken("h1", 0)
	if err != nil {
		t.Fatal(err)
	}
	host, err := f.e.Tokens().Peek(tok)
	if err != nil || host != "h1" {
		t.Fatalf("Peek = %q, %v; want h1, nil", host, err)
	}
}

func TestPeekDoesNotConsume(t *testing.T) {
	now := time.Now()
	f := newEnrollerWith(t, func(o *Options) { o.Now = func() time.Time { return now } })
	tok, err := f.e.MintToken("h1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if host, err := f.e.Tokens().Peek(tok); err != nil || host != "h1" {
			t.Fatalf("Peek #%d = %q, %v; want h1, nil", i+1, host, err)
		}
	}
	if err := f.e.Tokens().Consume(tok, "h1", link.Pin{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.e.Tokens().Peek(tok); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("Peek after Consume err = %v, want ErrTokenUsed", err)
	}
	expiring, err := f.e.MintToken("h1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := f.e.Tokens().Peek(expiring); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("Peek expired err = %v, want ErrTokenExpired", err)
	}
}

func TestBundleCarriesPinPlanKeyAndSafe(t *testing.T) {
	f := newEnroller(t)
	b, err := f.e.Bundle("h1", BundleOptions{Controllers: []string{"10.0.0.5:7443"}, Safe: true})
	if err != nil {
		t.Fatal(err)
	}
	if b.Host != "h1" {
		t.Errorf("Host = %q, want h1", b.Host)
	}
	if b.Token == "" {
		t.Error("Token is empty")
	}
	if !b.Safe {
		t.Error("Safe is false")
	}
	if b.ControllerPin != f.id.Pin.String() {
		t.Errorf("ControllerPin = %q, want %q", b.ControllerPin, f.id.Pin.String())
	}
	if b.PlanKey != f.planKeyHex() {
		t.Errorf("PlanKey = %q, want %q", b.PlanKey, f.planKeyHex())
	}
}
