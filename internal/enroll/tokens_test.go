package enroll

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/link"
)

func TestTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	tk, err := OpenTokens(path, 2)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tk.now = func() time.Time { return now }
	tok, err := tk.Mint("h1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	pinA, pinB := link.Pin{1}, link.Pin{2}
	if err := tk.Consume(tok, "h9", pinA); !errors.Is(err, ErrTokenHost) {
		t.Fatalf("wrong host: %v", err)
	}
	if err := tk.Consume(tok, "h1", pinA); err != nil {
		t.Fatal(err)
	}
	if err := tk.Consume(tok, "h1", pinA); err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	if err := tk.Consume(tok, "h1", pinB); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("reuse: %v", err)
	}
	if err := tk.Consume("nope", "h1", pinA); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("invalid: %v", err)
	}
	// The plaintext is never stored.
	raw, _ := readFile(path)
	if strings.Contains(raw, tok) {
		t.Fatal("token stored in plaintext")
	}
	// Reload keeps the used state.
	tk2, _ := OpenTokens(path, 2)
	if err := tk2.Consume(tok, "h1", pinB); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("after reload: %v", err)
	}
	// Expiry.
	t2, _ := tk.Mint("h2", time.Minute)
	now = now.Add(2 * time.Minute)
	if err := tk.Consume(t2, "h2", pinA); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired: %v", err)
	}
	// Live-token cap.
	for i := 0; i < 2; i++ {
		if _, err := tk.Mint("h3", time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tk.Mint("h3", time.Minute); !errors.Is(err, ErrTooManyTokens) {
		t.Fatalf("cap: %v", err)
	}
}
