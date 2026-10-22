//go:build !windows

package winevt

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func TestStubModuleIsIdleOffWindows(t *testing.T) {
	m, err := New(Config{BookmarkPath: filepath.Join(t.TempDir(), "b.json")})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	// Must return nil immediately (finished, not restarted) and emit nothing.
	if err := m.Start(context.Background(), func(event.Event) error { called = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("stub emitted an event")
	}
	if _, err := platformOpen(context.Background(), Channel{Name: ChSecurity}, "", false); err == nil {
		t.Fatal("platformOpen must fail off Windows")
	}
	if i, err := platformProbe(nil); err != nil || i.Present {
		t.Fatal("probe")
	}
}
