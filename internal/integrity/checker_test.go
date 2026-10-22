//go:build linux

package integrity

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

type sink struct {
	mu sync.Mutex
	ev []event.Event
}

func (s *sink) emit(e event.Event) { s.mu.Lock(); s.ev = append(s.ev, e); s.mu.Unlock() }
func (s *sink) all() []event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]event.Event(nil), s.ev...)
}

func copyFile(t *testing.T, src, dst string, mode os.FileMode) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

func fileSum(t *testing.T, p string) Sum {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return sumOf(string(b))
}

func newChecker(t *testing.T, l *Ledger, s *sink, mod func(*Config)) *Checker {
	t.Helper()
	cfg := Config{Agent: "a1", Judge: l, Emit: s.emit}
	if mod != nil {
		mod(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func startSleep(t *testing.T, path string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(path, "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	// wait until exec happened (exe link points at the new image)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if l, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", cmd.Process.Pid)); err == nil && l == path {
			return cmd
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("child did not exec")
	return nil
}

func sleepBin(t *testing.T) string {
	p, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	return p
}

func TestExecModifiedBinaryDetected(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "postfix")
	copyFile(t, sleepBin(t), good, 0o755)
	l := NewLedger(Meta{})
	l.Add(Entry{Path: good, SHA256: fileSum(t, good), Package: "postfix", Version: "3.6", Source: SourceVendorPackage, OS: "debian12"})
	var s sink
	c := newChecker(t, l, &s, nil)
	ctx := context.Background()

	r, err := c.CheckExec(ctx, ExecInfo{Path: good, UID: 1000})
	if err != nil || r.Verdict != Match || len(s.all()) != 0 {
		t.Fatalf("good binary: %v %+v events=%d", err, r, len(s.all()))
	}

	// Red team swaps in a proxy build (different bytes at the same path).
	trojan := filepath.Join(dir, "t")
	copyFile(t, sleepBin(t), trojan, 0o755)
	f, _ := os.OpenFile(trojan, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("PROXY-TO-KALI")
	f.Close()
	if err := os.Rename(trojan, good); err != nil {
		t.Fatal(err)
	}
	r, err = c.CheckExec(ctx, ExecInfo{Path: good, UID: 0, PPID: 1, Process: "proc:a1:42", Service: "smtp"})
	if err != nil || r.Verdict != Mismatch {
		t.Fatalf("trojaned binary: %v %+v", err, r)
	}
	evs := s.all()
	if len(evs) != 1 || evs[0].Kind != "integrity.verdict" || evs[0].Priority != event.PriorityCritical {
		t.Fatalf("events: %+v", evs)
	}
	f2 := evs[0].Fields
	for k, want := range map[string]any{
		"verdict": "mismatch", "package": "postfix", "source": "vendor_package", "process": "proc:a1:42",
		"expected_sha256": fileSum(t, good).String()[:0] + l.ByPath(good)[0].SHA256.String(), "trigger": "exec", "escalate": true, "service": "smtp",
	} {
		if f2[k] != want {
			t.Errorf("field %s = %v, want %v", k, f2[k], want)
		}
	}
	if f2["sha256"] != fileSum(t, good).String() {
		t.Errorf("sha256 field wrong: %v", f2["sha256"])
	}
	// Event must be sealable (canonical encodable).
	e := evs[0]
	if err := e.Seal(0, event.GenesisHash); err != nil {
		t.Fatal(err)
	}
	// Identical finding is suppressed on repeat.
	c.CheckExec(ctx, ExecInfo{Path: good, UID: 0, PPID: 1, Process: "proc:a1:42", Service: "smtp"})
	if len(s.all()) != 1 {
		t.Fatal("repeat finding not suppressed")
	}
}

func TestHandleProcessStartUsesRunningImage(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "sleep")
	copyFile(t, sleepBin(t), bin, 0o755)
	cmd := startSleep(t, bin)
	l := NewLedger(Meta{})
	l.Add(Entry{Path: bin, SHA256: fileSum(t, bin), Source: SourceReference})
	var s sink
	c := newChecker(t, l, &s, nil)
	ev := event.Event{Agent: "a1", Seq: 7, Kind: "process_start", Fields: map[string]any{"pid": float64(cmd.Process.Pid), "exe": bin, "uid": float64(0)}}
	if r, err := c.HandleProcessStart(context.Background(), ev); err != nil || r.Verdict != Match {
		t.Fatalf("%v %+v", err, r)
	}
	// Delete the file: the event path is gone but the running image is still judged.
	os.Remove(bin)
	r, err := c.CheckExec(context.Background(), ExecInfo{PID: cmd.Process.Pid, Path: bin, UID: -1})
	if err != nil || r.Verdict != Match {
		t.Fatalf("deleted but running: %v %+v", err, r)
	}
	evs := s.all()
	if len(evs) != 1 || evs[0].Fields["flags"].([]string)[0] != "deleted_exe" {
		t.Fatalf("expected a deleted_exe event, got %+v", evs)
	}
}

func TestPinReplacedInPlaceAndDeletedImage(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "sleep")
	copyFile(t, sleepBin(t), bin, 0o755)
	l := NewLedger(Meta{})
	l.Add(Entry{Path: bin, SHA256: fileSum(t, bin), Package: "postfix", Version: "3", Source: SourceReference})
	cmd := startSleep(t, bin)
	var s sink
	c := newChecker(t, l, &s, nil)
	ctx := context.Background()
	pin := Pin{Service: "smtp", PID: cmd.Process.Pid, Path: bin, Process: "proc:1"}

	res, err := c.CheckPin(ctx, pin)
	if err != nil || res.Verdict != Match || len(res.Flags) != 0 || len(s.all()) != 0 {
		t.Fatalf("clean pin: %v %+v events=%d", err, res, len(s.all()))
	}

	// Replace in place: new inode (a different binary) renamed over the path.
	evil := filepath.Join(dir, "evil")
	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no true")
	}
	copyFile(t, truePath, evil, 0o755)
	if err := os.Rename(evil, bin); err != nil {
		t.Fatal(err)
	}
	res, err = c.CheckPin(ctx, pin)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{FlagImageDeleted, FlagInodeReplaced, FlagDiskDiffers, "disk_mismatch"} {
		if !has(res.Flags, f) {
			t.Errorf("missing flag %s in %v", f, res.Flags)
		}
	}
	if res.Running.Verdict != Match || res.Disk == nil || res.Disk.Verdict != Mismatch || res.Verdict != Mismatch {
		t.Fatalf("verdicts: running=%s disk=%+v overall=%s", res.Running.Verdict, res.Disk, res.Verdict)
	}
	evs := s.all()
	if len(evs) != 1 || evs[0].Fields["trigger"] != "pin" || evs[0].Fields["disk_sha256"] != fileSum(t, bin).String() ||
		evs[0].Fields["running_sha256"] != l.ByPath(bin)[0].SHA256.String() || evs[0].Fields["service"] != "smtp" {
		t.Fatalf("pin event: %+v", evs)
	}

	// Now the file is removed outright: deleted running image, nothing on disk.
	os.Remove(bin)
	res, err = c.CheckPin(ctx, pin)
	if err != nil || !has(res.Flags, FlagImageDeleted) || !has(res.Flags, FlagDiskMissing) || res.Running.Verdict != Match {
		t.Fatalf("deleted: %v %+v", err, res)
	}

	// Dead process.
	cmd.Process.Kill()
	cmd.Wait()
	if _, err := c.CheckPin(ctx, pin); err == nil {
		t.Fatal("expected process-gone error")
	}
}

func TestPinStaleAfterLegitUpdateIsInformational(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "sleep")
	copyFile(t, sleepBin(t), bin, 0o755)
	oldSum := fileSum(t, bin)
	cmd := startSleep(t, bin)
	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Skip()
	}
	next := filepath.Join(dir, "next")
	copyFile(t, truePath, next, 0o755)
	l := NewLedger(Meta{})
	l.Add(Entry{Path: bin, SHA256: oldSum, Version: "1", Source: SourceReference})
	l.Add(Entry{Path: bin, SHA256: fileSum(t, next), Version: "2", Source: SourceReference})
	os.Rename(next, bin)
	var s sink
	c := newChecker(t, l, &s, nil)
	res, err := c.CheckPin(context.Background(), Pin{Service: "x", PID: cmd.Process.Pid, Path: bin})
	if err != nil || res.Verdict.Alerting() || !has(res.Flags, FlagStaleAfterUpdate) {
		t.Fatalf("%v %+v", err, res)
	}
	if evs := s.all(); len(evs) != 1 || evs[0].Priority != event.PriorityHigh && evs[0].Priority != event.PriorityNormal {
		t.Fatalf("%+v", evs)
	}
}

func TestCheckMapsFakeProc(t *testing.T) {
	dir := t.TempDir()
	libdir := filepath.Join(dir, "lib")
	os.MkdirAll(libdir, 0o755)
	good := filepath.Join(libdir, "libc.so.6")
	evil := filepath.Join(libdir, "libhook.so")
	rogue := filepath.Join(dir, "tmp", "mod_rogue.so")
	os.MkdirAll(filepath.Dir(rogue), 0o755)
	os.WriteFile(good, []byte("libc"), 0o644)
	os.WriteFile(evil, []byte("trojan libhook"), 0o644)
	os.WriteFile(rogue, []byte("php module"), 0o644)

	l := NewLedger(Meta{})
	l.Add(Entry{Path: good, SHA256: sumOf("libc"), Source: SourceReference})
	l.Add(Entry{Path: evil, SHA256: sumOf("genuine libhook"), Source: SourceReference})

	proc := t.TempDir()
	os.MkdirAll(filepath.Join(proc, "321"), 0o755)
	maps := "" +
		"55d0c8a00000-55d0c8a21000 r--p 00000000 08:01 100 " + good + "\n" +
		"7f0000000000-7f0000100000 r-xp 00000000 08:01 100 " + good + "\n" +
		"7f0000200000-7f0000300000 r-xp 00000000 08:01 101 " + evil + "\n" +
		"7f0000400000-7f0000500000 r-xp 00000000 08:01 102 " + rogue + "\n" +
		"7f0000600000-7f0000700000 r-xp 00000000 00:01 103 /memfd:payload (deleted)\n" +
		"7f0000800000-7f0000900000 rw-p 00000000 00:00 0 \n" +
		"7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0 [stack]\n" +
		"7f0000a00000-7f0000b00000 r-xp 00000000 08:01 104 /usr/lib/gone.so (deleted)\n"
	os.WriteFile(filepath.Join(proc, "321", "maps"), []byte(maps), 0o644)

	var s sink
	c := newChecker(t, l, &s, func(c *Config) { c.ProcRoot = proc })
	res, err := c.CheckMaps(context.Background(), 321, Context{UID: 33, Service: "apache", Pinned: true})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]LibResult{}
	for _, r := range res {
		got[r.Path] = r
	}
	if len(res) != 5 {
		t.Fatalf("expected 5 distinct exec mappings, got %d: %+v", len(res), res)
	}
	if got[good].Result.Verdict != Match || got[evil].Result.Verdict != Mismatch || got[rogue].Result.Verdict != Unknown {
		t.Fatalf("verdicts: %s %s %s", got[good].Result.Verdict, got[evil].Result.Verdict, got[rogue].Result.Verdict)
	}
	if !has(got[rogue].Flags, FlagWritableLibrary) { // t.TempDir lives under /tmp
		t.Fatal("writable_location not flagged")
	}
	if !has(got["/memfd:payload"].Flags, FlagMemfdLibrary) || !has(got["/usr/lib/gone.so"].Flags, FlagDeletedLibrary) {
		t.Fatalf("flags: %+v %+v", got["/memfd:payload"], got["/usr/lib/gone.so"])
	}
	evs := s.all()
	if len(evs) != 5 { // all four bad ones, plus libc itself because it is mapped from /tmp
		t.Fatalf("%d events: %v", len(evs), evs)
	}
	for _, e := range evs {
		if e.Fields["trigger"] != "library" || e.Fields["pid"] != 321 || e.Fields["library"] == nil {
			t.Fatalf("event %+v", e.Fields)
		}
	}
}

func TestCacheInvalidation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bin")
	os.WriteFile(p, []byte("AAAA"), 0o755)
	l := NewLedger(Meta{})
	c := newChecker(t, l, &sink{}, nil)
	ctx := context.Background()
	s1, _, _ := c.HashFile(ctx, p)
	s2, _, _ := c.HashFile(ctx, p)
	if h, hits := c.CacheStats(); h != 1 || hits != 1 || s1 != s2 {
		t.Fatalf("expected 1 hash + 1 hit, got %d %d", h, hits)
	}
	// Same size, same mtime, different content: ctime still moves, so the entry is invalid.
	st, _ := os.Stat(p)
	os.WriteFile(p, []byte("BBBB"), 0o755)
	os.Chtimes(p, st.ModTime(), st.ModTime())
	s3, _, _ := c.HashFile(ctx, p)
	if s3 == s1 || s3 != sumOf("BBBB") {
		t.Fatalf("forged-mtime rewrite not detected")
	}
	if h, _ := c.CacheStats(); h != 2 {
		t.Fatalf("expected re-hash, hashed=%d", h)
	}
	// Replaced inode (rename) with identical content size also re-hashes.
	q := filepath.Join(dir, "q")
	os.WriteFile(q, []byte("CCCC"), 0o755)
	os.Rename(q, p)
	s4, _, _ := c.HashFile(ctx, p)
	if s4 != sumOf("CCCC") {
		t.Fatal("replaced inode not detected")
	}
}

func TestSweepThrottleAndIncremental(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "usr/bin")
	os.MkdirAll(bin, 0o755)
	os.WriteFile(filepath.Join(bin, "ok"), []byte("ok"), 0o755)
	os.WriteFile(filepath.Join(bin, "bad"), []byte("bad"), 0o755)
	os.WriteFile(filepath.Join(bin, "data.txt"), []byte("not executable"), 0o644)
	os.WriteFile(filepath.Join(bin, "libx.so.1"), []byte("lib"), 0o644)
	l := NewLedger(Meta{})
	l.Add(Entry{Path: filepath.Join(bin, "ok"), SHA256: sumOf("ok"), Source: SourceReference})
	l.Add(Entry{Path: filepath.Join(bin, "bad"), SHA256: sumOf("good bad"), Source: SourceReference})
	l.Add(Entry{Path: filepath.Join(bin, "libx.so.1"), SHA256: sumOf("lib"), Source: SourceReference})
	var s sink
	c := newChecker(t, l, &s, nil)
	ctx := context.Background()
	st, err := c.Sweep(ctx, SweepOptions{Roots: []string{bin}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Files != 3 || st.Hashed != 3 || st.Verdicts[Match] != 2 || st.Verdicts[Mismatch] != 1 {
		t.Fatalf("%+v", st)
	}
	if len(s.all()) != 1 || s.all()[0].Fields["trigger"] != "sweep" {
		t.Fatalf("events %+v", s.all())
	}
	st, _ = c.Sweep(ctx, SweepOptions{Roots: []string{bin}})
	if st.Hashed != 0 || st.CacheHits != 3 {
		t.Fatalf("second sweep should be all cache hits: %+v", st)
	}
	st, _ = c.Sweep(ctx, SweepOptions{Roots: []string{bin}, FullRehash: true})
	if st.Hashed != 3 {
		t.Fatalf("full rehash: %+v", st)
	}
	// Throttle: 3 files of a few bytes at 100 B/s must take measurable time.
	os.WriteFile(filepath.Join(bin, "big"), make([]byte, 40), 0o755)
	c2 := newChecker(t, l, &sink{}, nil)
	t0 := time.Now()
	c2.Sweep(ctx, SweepOptions{Roots: []string{bin}, BytesPerSec: 100})
	if el := time.Since(t0); el < 300*time.Millisecond {
		t.Fatalf("sweep not throttled: %v", el)
	}
	// Cancellation.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := c.Sweep(cctx, SweepOptions{Roots: []string{bin}}); err == nil {
		t.Fatal("cancelled sweep returned nil")
	}
}

type fakeVerifier map[string]SignatureResult

func (f fakeVerifier) VerifyFile(_ context.Context, p string) (SignatureResult, error) {
	if r, ok := f[filepath.Base(p)]; ok {
		return r, nil
	}
	return SignatureResult{Status: SigUnsigned}, nil
}

func TestSignatureAllowlistAndSigInvalid(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"splunkd.exe", "dns.exe", "tool.exe", "other.exe"} {
		os.WriteFile(filepath.Join(dir, n), []byte(n), 0o755)
	}
	l := NewLedger(Meta{})
	var s sink
	c := newChecker(t, l, &s, func(c *Config) {
		c.Allowlist = SignerAllowlist{"Splunk Inc."}
		c.Verifier = fakeVerifier{
			"splunkd.exe": {Status: SigValid, Signer: "Splunk Inc."},
			"tool.exe":    {Status: SigValid, Signer: "Random Vendor"},
			"dns.exe":     {Status: SigBad, Detail: "hash mismatch"},
		}
	})
	want := map[string]Verdict{"splunkd.exe": Match, "tool.exe": Unknown, "dns.exe": SigInvalid, "other.exe": SigInvalid}
	for n, v := range want {
		r, err := c.CheckExec(context.Background(), ExecInfo{Path: filepath.Join(dir, n), UID: -1})
		if err != nil || r.Verdict != v {
			t.Errorf("%s: %v %s want %s", n, err, r.Verdict, v)
		}
	}
	if len(s.all()) != 3 {
		t.Fatalf("events=%d", len(s.all()))
	}
}

func TestWorseAndAlerting(t *testing.T) {
	if Worse(Unknown, Mismatch) != Mismatch || Worse(KnownBad, Mismatch) != KnownBad || Worse(Match, MatchOtherVersion) != MatchOtherVersion {
		t.Fatal("Worse ordering")
	}
	if Match.Alerting() || MatchOtherVersion.Alerting() || !Unknown.Alerting() {
		t.Fatal("Alerting")
	}
}
