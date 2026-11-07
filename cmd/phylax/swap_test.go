package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/svcinstall"
)

// fakeInstaller records the service calls a swap plan makes and, when started
// is set, writes the started.json a freshly started agent would write.
type fakeInstaller struct {
	dir     string
	started bool
	calls   []string
}

func (f *fakeInstaller) record(s string) { f.calls = append(f.calls, s) }

func (f *fakeInstaller) Install(_ context.Context, s svcinstall.Spec) error {
	f.record("install " + s.Name)
	return f.writeStarted()
}

func (f *fakeInstaller) Uninstall(_ context.Context, name string) error {
	f.record("uninstall " + name)
	return nil
}

func (f *fakeInstaller) Stop(_ context.Context, name string) error {
	f.record("stop " + name)
	return nil
}

func (f *fakeInstaller) Restart(_ context.Context, name string) error {
	f.record("restart " + name)
	return f.writeStarted()
}

// writeStarted writes what a freshly started agent would: started.json with a
// time later than the swap (when started is set).
func (f *fakeInstaller) writeStarted() error {
	if !f.started {
		return nil
	}
	raw, err := json.Marshal(svcinstall.Started{PID: os.Getpid(), Time: time.Now().UTC()})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(f.dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(f.dir, "started.json"), raw, 0o600)
}

func indexOf(calls []string, want string) int {
	for i, c := range calls {
		if c == want {
			return i
		}
	}
	return -1
}

func countOf(calls []string, want string) int {
	n := 0
	for _, c := range calls {
		if c == want {
			n++
		}
	}
	return n
}

func writeBin(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestSwapReplaceBinarySuccess(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "phylax")
	newer := filepath.Join(dir, "phylax.new")
	writeBin(t, old, "A")
	writeBin(t, newer, "B")
	inst := &fakeInstaller{dir: dir, started: true}
	p := svcinstall.SwapPlan{Kind: "replace_binary", Service: "svc", OldBinary: old, NewBinary: newer, StateDir: dir, WaitSec: 2}
	if err := runSwap(context.Background(), p, inst); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(old); err != nil || string(raw) != "B" {
		t.Fatalf("binary is %q (%v), want the new one", raw, err)
	}
	if _, err := os.Stat(old + ".old"); !os.IsNotExist(err) {
		t.Fatal(".old left behind after a successful swap")
	}
	if _, err := os.Stat(newer); !os.IsNotExist(err) {
		t.Fatal("the new binary was not moved into place")
	}
	if got := countOf(inst.calls, "restart svc"); got != 1 {
		t.Fatalf("restarts %d, want 1: %v", got, inst.calls)
	}
}

func TestSwapReplaceBinaryRollsBackWithoutHeartbeat(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "phylax")
	newer := filepath.Join(dir, "phylax.new")
	writeBin(t, old, "A")
	writeBin(t, newer, "B")
	inst := &fakeInstaller{dir: dir} // Restart never writes started.json
	p := svcinstall.SwapPlan{Kind: "replace_binary", Service: "svc", OldBinary: old, NewBinary: newer, StateDir: dir, WaitSec: 1}
	if err := runSwap(context.Background(), p, inst); err == nil {
		t.Fatal("a swap without a controller ack succeeded")
	}
	if raw, err := os.ReadFile(old); err != nil || string(raw) != "A" {
		t.Fatalf("binary is %q (%v), want the old one back", raw, err)
	}
	if got := countOf(inst.calls, "restart svc"); got != 2 {
		t.Fatalf("restarts %d, want 2 (start, revert): %v", got, inst.calls)
	}
}

func TestSwapRenameInstallsNewThenRemovesOld(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "phylax2")
	writeBin(t, bin, "B")
	inst := &fakeInstaller{dir: dir, started: true}
	p := svcinstall.SwapPlan{Kind: "rename", Service: "old-svc", NewService: "new-svc", NewBinary: bin,
		StateDir: dir, WaitSec: 2, Args: []string{"agent", "run", "--service-name", "new-svc"}}
	if err := runSwap(context.Background(), p, inst); err != nil {
		t.Fatal(err)
	}
	i, u := indexOf(inst.calls, "install new-svc"), indexOf(inst.calls, "uninstall old-svc")
	if i < 0 || u < 0 || i > u {
		t.Fatalf("want install(new) before uninstall(old): %v", inst.calls)
	}
	if got := countOf(inst.calls, "uninstall new-svc"); got != 0 {
		t.Fatalf("removed the new service: %v", inst.calls)
	}
}

func TestSwapRenameRevertsWithoutHeartbeat(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "phylax2")
	writeBin(t, bin, "B")
	inst := &fakeInstaller{dir: dir} // no started.json
	p := svcinstall.SwapPlan{Kind: "rename", Service: "old-svc", NewService: "new-svc", NewBinary: bin, StateDir: dir, WaitSec: 1}
	if err := runSwap(context.Background(), p, inst); err == nil {
		t.Fatal("a rename without a controller ack succeeded")
	}
	if strings.Join(inst.calls, "|") != "stop old-svc|install new-svc|uninstall new-svc|restart old-svc" {
		t.Fatalf("calls %v", inst.calls)
	}
}
