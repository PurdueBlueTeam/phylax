package integrity

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// EventKind is the kind of every event this package emits.
const EventKind = "integrity.verdict"

// Trigger values for the "trigger" evidence field.
const (
	TriggerExec    = "exec"
	TriggerLibrary = "library"
	TriggerPin     = "pin"
	TriggerSweep   = "sweep"
)

// Config configures a Checker. Only Judge is required.
type Config struct {
	Agent string // agent id stamped on events
	Judge Judger // usually a *Ledger, or a controller-backed lookup
	Hints *HostHints
	// Emit receives integrity.verdict events (unsealed; the spool assigns
	// seq and hashes). May be nil.
	Emit func(event.Event)
	Now  func() time.Time
	// ProcRoot is the procfs mount ("/proc"); tests point it at a fake tree.
	ProcRoot string
	Verifier SignatureVerifier // Authenticode/catalog; nil on Linux
	// Allowlist lists acceptable third-party signers; a validly signed file
	// from an allowed signer that the ledger does not know is accepted.
	Allowlist SignerAllowlist
	CacheSize int
	// Suppress is how long an identical finding (path, hash, verdict, flags)
	// is not re-emitted (default 15 minutes). Pin checks every 60 s would
	// otherwise repeat forever.
	Suppress time.Duration
	// EmitMatches also emits events for good verdicts (off by default).
	EmitMatches bool
	// MaxHashBytes caps one file (default 2 GiB); larger files are skipped.
	MaxHashBytes int64
}

// Checker performs the agent-side checks. It never modifies files: every file
// is opened read-only and only hashed.
type Checker struct {
	cfg   Config
	cache *hashCache

	mu    sync.Mutex
	seen  map[string]time.Time
	stats struct{ hashed, hits int64 }
}

// New builds a Checker.
func New(cfg Config) (*Checker, error) {
	if cfg.Judge == nil {
		return nil, errors.New("integrity: Config.Judge is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = "/proc"
	}
	if cfg.Suppress == 0 {
		cfg.Suppress = 15 * time.Minute
	}
	if cfg.MaxHashBytes <= 0 {
		cfg.MaxHashBytes = 2 << 30
	}
	return &Checker{cfg: cfg, cache: newHashCache(cfg.CacheSize), seen: map[string]time.Time{}}, nil
}

// CacheStats reports hash computations and cache hits since creation.
func (c *Checker) CacheStats() (hashed, hits int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats.hashed, c.stats.hits
}

// hashed describes one hashed open file.
type hashed struct {
	Sum    Sum
	ID     fileID
	Size   int64
	Mode   os.FileMode
	UID    int
	Cached bool
}

// hashOpen hashes an already-open regular file, consulting the cache by the
// identity of the open handle (so /proc/<pid>/exe yields the running inode).
func (c *Checker) hashOpen(ctx context.Context, f *os.File, path string, force bool) (hashed, error) {
	fi, err := f.Stat()
	if err != nil {
		return hashed{}, err
	}
	if !fi.Mode().IsRegular() {
		return hashed{}, fmt.Errorf("integrity: %s is not a regular file", path)
	}
	if fi.Size() > c.cfg.MaxHashBytes {
		return hashed{}, fmt.Errorf("integrity: %s too large to hash (%d bytes)", path, fi.Size())
	}
	h := hashed{ID: idOf(fi, path), Size: fi.Size(), Mode: fi.Mode(), UID: fileOwner(fi)}
	if !force {
		if s, ok := c.cache.get(h.ID); ok {
			h.Sum, h.Cached = s, true
			c.mu.Lock()
			c.stats.hits++
			c.mu.Unlock()
			return h, nil
		}
	}
	hs := sha256.New()
	buf := make([]byte, 128<<10)
	var n int64
	for {
		if err := ctx.Err(); err != nil {
			return h, err
		}
		k, err := f.Read(buf)
		hs.Write(buf[:k])
		n += int64(k)
		if err == io.EOF {
			break
		}
		if err != nil {
			return h, err
		}
	}
	copy(h.Sum[:], hs.Sum(nil))
	// A file that changed while we read it is not cached.
	if fi2, err := f.Stat(); err == nil && idOf(fi2, path) == h.ID && n == h.Size {
		c.cache.put(h.ID, h.Sum)
	}
	c.mu.Lock()
	c.stats.hashed++
	c.mu.Unlock()
	return h, nil
}

// HashFile hashes path (cached by dev+inode+ctime+size).
func (c *Checker) HashFile(ctx context.Context, path string) (Sum, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return Sum{}, 0, err
	}
	defer f.Close()
	h, err := c.hashOpen(ctx, f, path, false)
	return h.Sum, h.Size, err
}

// judge combines the ledger verdict with host hints and signature checks.
func (c *Checker) judge(ctx context.Context, path string, h hashed) Result {
	claimed := c.cfg.Hints.ClaimedVersion(path)
	r := c.cfg.Judge.Judge(path, h.Sum, claimed)
	r.Size = h.Size
	if r.Verdict == Unknown && c.cfg.Hints != nil && !r.HintOnly {
		if hf, ok := c.cfg.Hints.Files[NormalizePath(path)]; ok && hf.MD5 != "" {
			if m, err := md5File(path); err == nil && m == hf.MD5 {
				r.HintOnly = true
				r.Note = "only the host package database vouches for this file (hint, not proof)"
			}
		}
	}
	if r.Verdict.Alerting() && r.Verdict != KnownBad && c.cfg.Verifier != nil {
		sr, err := c.cfg.Verifier.VerifyFile(ctx, path)
		if err == nil || sr.Status != SigUnsupported {
			r.Signer = sr.Signer
			switch {
			case sr.Status == SigValid && c.cfg.Allowlist.Allows(sr.Signer):
				r.Verdict, r.Note = Match, "accepted by signer allowlist: "+sr.Signer
			case sr.Status == SigValid:
				// Signed by someone unlisted: keep the ledger verdict, record the signer.
			default:
				r.Verdict = SigInvalid
				r.Note = "signature " + string(sr.Status) + ": " + sr.Detail
			}
		}
	}
	return r
}

func md5File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Context is the process context attached to a finding.
type Context struct {
	Trigger string
	PID     int
	PPID    int
	UID     int    // -1 or unset when unknown
	Process string // pointer to the process tree (process event id / ref)
	Service string // scored service name, "" if none
	Pinned  bool
}

// emit builds and sends an integrity.verdict event when warranted. It returns
// whether an event was sent.
func (c *Checker) emit(r Result, cx Context, flags []string, extra map[string]any) bool {
	alert := r.Verdict.Alerting() || len(flags) > 0
	if !alert && !c.cfg.EmitMatches {
		return false
	}
	now := c.cfg.Now()
	key := fmt.Sprintf("%s|%s|%s|%s|%s|%d", cx.Trigger, r.Path, r.SHA256, r.Verdict, strings.Join(flags, ","), cx.PID)
	c.mu.Lock()
	if t, ok := c.seen[key]; ok && now.Sub(t) < c.cfg.Suppress {
		c.mu.Unlock()
		return false
	}
	if len(c.seen) > 100000 {
		c.seen = map[string]time.Time{}
	}
	c.seen[key] = now
	c.mu.Unlock()
	if c.cfg.Emit == nil {
		return true
	}
	root := cx.UID == 0
	escalate := (r.Verdict == Unknown || r.Verdict == Mismatch || r.Verdict == KnownBad || r.Verdict == SigInvalid) &&
		(root || cx.Service != "" || cx.Pinned)
	f := map[string]any{
		"path": r.Path, "sha256": r.SHA256.String(), "size": r.Size,
		"verdict": string(r.Verdict), "trigger": cx.Trigger,
		"root": root, "escalate": escalate,
	}
	if cx.PID > 0 {
		f["pid"] = cx.PID
	}
	if cx.PPID > 0 {
		f["ppid"] = cx.PPID
	}
	if cx.UID >= 0 {
		f["uid"] = cx.UID
	}
	if cx.Process != "" {
		f["process"] = cx.Process
	}
	if cx.Service != "" {
		f["service"] = cx.Service
	}
	if len(flags) > 0 {
		f["flags"] = flags
	}
	if m := r.Matched; m != nil {
		f["matched"] = entryFields(*m)
	}
	if len(r.Expected) > 0 {
		exp := make([]any, 0, len(r.Expected))
		for _, e := range r.Expected {
			exp = append(exp, entryFields(e))
		}
		f["expected"] = exp
		// Flat fields for the common single-answer case.
		e0 := r.Expected[0]
		f["expected_sha256"], f["source"], f["package"] = e0.SHA256.String(), e0.Source.String(), e0.Package
		if e0.Version != "" {
			f["version"] = e0.Version
		}
		if e0.Signer != "" {
			f["expected_signer"] = e0.Signer
		}
	}
	if r.Signer != "" {
		f["signer"] = r.Signer
	}
	if r.BadLabel != "" {
		f["bad_label"] = r.BadLabel
	}
	if r.HintOnly {
		f["hint_only"] = true
	}
	if len(r.HashKnownAt) > 0 {
		f["hash_known_at"] = r.HashKnownAt
	}
	if r.Note != "" {
		f["note"] = r.Note
	}
	for k, v := range extra {
		f[k] = v
	}
	pr := event.PriorityHigh
	if r.Verdict == KnownBad || r.Verdict == Mismatch || escalate {
		pr = event.PriorityCritical
	}
	if !alert {
		pr = event.PriorityNormal
	}
	c.cfg.Emit(event.Event{Agent: c.cfg.Agent, Time: now.UTC(), Kind: EventKind, Priority: pr, Fields: f})
	return true
}

func entryFields(e Entry) map[string]any {
	m := map[string]any{"sha256": e.SHA256.String(), "path": e.Path, "source": e.Source.String(), "size": e.Size}
	if e.Package != "" {
		m["package"] = e.Package
	}
	if e.Version != "" {
		m["version"] = e.Version
	}
	if e.Signer != "" {
		m["signer"] = e.Signer
	}
	if e.OS != "" {
		m["os"] = e.OS
	}
	if e.Mode != 0 {
		m["mode"] = e.Mode
	}
	return m
}

// ExecInfo describes a process start.
type ExecInfo struct {
	PID     int
	PPID    int
	UID     int
	Path    string // path as reported by the exec event
	Process string // process-tree pointer
	Service string
	Pinned  bool
}

// CheckExec hashes the executable of a process start and judges it. When the
// process is still alive, /proc/<pid>/exe is opened so the hash is of the
// image actually running, not whatever is at Path now.
func (c *Checker) CheckExec(ctx context.Context, x ExecInfo) (Result, error) {
	var (
		f     *os.File
		path  = x.Path
		flags []string
		err   error
	)
	if x.PID > 0 {
		pe := c.procPath(x.PID, "exe")
		if tgt, lerr := os.Readlink(pe); lerr == nil {
			if strings.HasSuffix(tgt, " (deleted)") {
				flags = append(flags, "deleted_exe")
			}
			if strings.HasPrefix(tgt, "/memfd:") {
				flags = append(flags, "memfd_exe")
			}
			if path == "" {
				path = strings.TrimSuffix(tgt, " (deleted)")
			}
			f, err = os.Open(pe)
		}
	}
	if f == nil {
		if path == "" {
			return Result{}, errors.New("integrity: exec has no path")
		}
		if f, err = os.Open(path); err != nil {
			return Result{}, err
		}
	}
	defer f.Close()
	h, err := c.hashOpen(ctx, f, path, false)
	if err != nil {
		return Result{}, err
	}
	r := c.judge(ctx, path, h)
	c.emit(r, Context{Trigger: TriggerExec, PID: x.PID, PPID: x.PPID, UID: x.UID, Process: x.Process, Service: x.Service, Pinned: x.Pinned}, flags, nil)
	return r, nil
}

// HandleProcessStart is the event input: a process_start event whose fields
// carry pid, an executable path ("exe" or "path"), "uid", "ppid" and
// optionally "process" (tree pointer) and "service". Missing fields default
// sensibly. The event is not modified.
func (c *Checker) HandleProcessStart(ctx context.Context, ev event.Event) (Result, error) {
	fl := ev.Fields
	x := ExecInfo{PID: fieldInt(fl, "pid", 0), PPID: fieldInt(fl, "ppid", 0), UID: fieldInt(fl, "uid", -1)}
	for _, k := range []string{"exe", "path"} {
		if s, ok := fl[k].(string); ok && s != "" {
			x.Path = s
			break
		}
	}
	x.Process, _ = fl["process"].(string)
	if x.Process == "" {
		x.Process = fmt.Sprintf("%s#%d", ev.Agent, ev.Seq)
	}
	x.Service, _ = fl["service"].(string)
	return c.CheckExec(ctx, x)
}

func fieldInt(m map[string]any, k string, def int) int {
	switch v := m[k].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case uint32:
		return int(v)
	case uint64:
		return int(v)
	case float64:
		return int(v)
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func (c *Checker) procPath(pid int, name string) string {
	return c.cfg.ProcRoot + "/" + strconv.Itoa(pid) + "/" + name
}
