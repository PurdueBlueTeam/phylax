//go:build linux

package audit

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/elastic/go-libaudit/v2/auparse"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func (m *Module) handle(msgs []*auparse.AuditMessage) {
	switch r := Assemble(msgs, m.cfg.limits()).(type) {
	case *ExecEvent:
		m.onExec(r)
	case *FileEvent:
		m.onFile(r)
	case *NetEvent:
		m.onNet(r)
	}
}

func (m *Module) isOwnPath(p string) bool {
	for _, ex := range m.cfg.ExcludePaths {
		if hasPrefixPath(p, ex) {
			return true
		}
	}
	return false
}

func idFields(f map[string]any, c *Common) {
	f["pid"], f["ppid"] = c.PID, c.PPID
	f["uid"], f["gid"], f["euid"], f["egid"], f["auid"], f["ses"] = c.UID, c.GID, c.EUID, c.EGID, c.AUID, c.SES
	f["tty"], f["comm"], f["exe"] = c.TTY, c.Comm, c.Exe
	f["syscall"], f["success"], f["exit"] = c.Syscall, c.Success, c.Exit
	if c.Key != "" {
		f["key"] = c.Key
	}
	f["audit_serial"] = c.Serial
	f["source"] = "audit"
	if m := c.Cwd; m != "" {
		f["cwd"] = m
	}
}

// lineage fills the process-identity fields from /proc and the cache. child
// reports whether the audit event describes the process after exec (so a live
// /proc exe is comparable).
func (m *Module) liveInfo(c *Common) (ProcInfo, bool) {
	pi, ok := m.procs.Resolve(c.PID, c.Time)
	if !ok {
		return ProcInfo{}, false
	}
	if c.Exe != "" && pi.Exe != "" && pi.Exe != c.Exe && !strings.HasPrefix(pi.Exe, c.Exe) {
		// The pid now runs something else (exec'd again, or reused): keep the
		// identity ticks only if live, never the image fields.
		pi.Exe, pi.Cmdline, pi.Comm, pi.Cgroup = "", "", "", ""
	}
	return pi, true
}

func (m *Module) onExec(e *ExecEvent) {
	if e.PID == m.cfg.selfPID {
		m.ownDropped.Add(1)
		return
	}
	f := map[string]any{}
	idFields(f, &e.Common)
	f["image"] = e.Exe
	f["argv"] = e.Argv
	f["argc"] = e.Argc
	f["cmdline"] = strings.Join(e.Argv, " ")
	if e.ExecPath != "" {
		f["exec_path"] = e.ExecPath
	}
	if e.ArgvTruncated {
		f["argv_truncated"] = true
	}
	if e.ArgvIncomplete {
		f["argv_incomplete"] = true
		if e.Proctitle != "" {
			f["proctitle"] = e.Proctitle
		}
	}
	if m.bootID != "" {
		f["boot_id"] = m.bootID
	}
	child, haveChild := m.liveInfo(&e.Common)
	if haveChild {
		if child.Live {
			f["start_ticks"] = child.Start
		}
		if child.Cgroup != "" {
			f["cgroup"] = child.Cgroup
		}
	}
	// Parent: /proc at event time, else the cache of earlier exec events.
	if par, ok := m.procs.Resolve(e.PPID, e.Time); ok {
		p := map[string]any{"pid": par.PID, "exe": par.Exe, "comm": par.Comm, "live": par.Live}
		if par.Cmdline != "" {
			p["cmdline"] = par.Cmdline
		}
		if par.Start != 0 {
			p["start_ticks"] = par.Start
		}
		f["parent"] = p
		f["pexe"], f["pcomm"] = par.Exe, par.Comm
	} else {
		f["parent"] = map[string]any{"pid": e.PPID, "unresolved": true}
	}
	// Remember the new image so its children resolve it even after it exits.
	if e.Success {
		pi := ProcInfo{PID: e.PID, PPID: e.PPID, Exe: e.Exe, Comm: e.Comm, Cmdline: strings.Join(e.Argv, " ")}
		if haveChild && child.Live {
			pi.Start, pi.Cgroup = child.Start, child.Cgroup
		}
		m.procs.Remember(pi)
	}
	prio := event.PriorityHigh
	if !e.Success {
		prio = event.PriorityNormal
	}
	m.send(event.Event{Time: e.Time.UTC(), Kind: KindProcessStart, Priority: prio, Fields: f}, false)
}

func (m *Module) onFile(e *FileEvent) {
	if e.PID == m.cfg.selfPID {
		m.ownDropped.Add(1)
		return
	}
	var paths, dirs []string
	var path, oldPath string
	for _, p := range e.Paths {
		if p.Name == "" {
			continue
		}
		name := resolvePath(e.Cwd, p.Name)
		if p.Nametype == "PARENT" {
			dirs = append(dirs, name)
			continue
		}
		paths = append(paths, name)
		switch {
		case p.Nametype == "DELETE" && e.Op == "rename" && oldPath == "":
			oldPath = name
		case path == "" && !(p.Nametype == "DELETE" && e.Op == "rename"):
			path = name
		}
	}
	if path == "" && len(paths) > 0 {
		path = paths[0]
	}
	if path == "" && len(dirs) > 0 {
		path = dirs[0]
	}
	// Feedback-loop exclusion: drop only if everything touched is ours.
	all := append(append([]string(nil), paths...), dirs...)
	if len(all) > 0 {
		own := true
		for _, p := range all {
			if !m.isOwnPath(p) {
				own = false
				break
			}
		}
		if own {
			m.ownDropped.Add(1)
			return
		}
	}
	now := time.Now()
	for _, p := range paths {
		m.recent.Store(p, now)
	}
	f := map[string]any{"op": e.Op, "path": path, "paths": paths}
	if oldPath != "" {
		f["old_path"] = oldPath
	}
	if len(dirs) > 0 {
		f["dirs"] = dirs
	}
	if e.PathsTruncated {
		f["paths_truncated"] = true
	}
	if strings.HasPrefix(e.Key, KeySelf) {
		f["self_tamper"] = true
	}
	idFields(f, &e.Common)
	if w, ok := m.procs.Resolve(e.PID, e.Time); ok {
		if w.Cmdline != "" {
			f["writer_cmdline"] = w.Cmdline
		}
		if w.Live && w.Start != 0 {
			f["writer_start_ticks"] = w.Start
		}
	}
	m.send(event.Event{Time: e.Time.UTC(), Kind: KindFileChange, Priority: event.PriorityCritical, Fields: f}, false)
}

func resolvePath(cwd, p string) string {
	if strings.HasPrefix(p, "/") || cwd == "" {
		return p
	}
	return strings.TrimRight(cwd, "/") + "/" + p
}

func (m *Module) onNet(e *NetEvent) {
	if e.PID == m.cfg.selfPID {
		m.ownDropped.Add(1)
		return
	}
	f := map[string]any{"family": e.Family, "addr": e.Addr, "port": e.Port,
		"direction": map[bool]string{true: "inbound", false: "outbound"}[strings.HasPrefix(e.Syscall, "accept")]}
	idFields(f, &e.Common)
	m.send(event.Event{Time: e.Time.UTC(), Kind: KindNetConnect, Priority: event.PriorityNormal, Fields: f}, false)
}

// ---- sweep ----

func (m *Module) sweepRoots() []string {
	seen := map[string]bool{}
	var roots []string
	for _, p := range append(m.cfg.WatchPaths(), m.cfg.SelfPaths...) {
		if ok, _ := osExists(p); ok && !seen[p] {
			seen[p] = true
			roots = append(roots, p)
		}
	}
	return roots
}

const maxSweepEvents = 500

func (m *Module) sweepLoop(ctx context.Context) error {
	return m.runSweeps(ctx, m.sweepRoots, m.cfg.SweepInterval, m.cfg.SweepStartDelay)
}

func (m *Module) runSweeps(ctx context.Context, roots func() []string, every, delay time.Duration) error {
	opts := SweepOptions{Depth: m.cfg.SweepDepth, MaxEntries: m.cfg.SweepMaxEntries,
		HashMaxBytes: m.cfg.SweepHashMaxBytes, FilesPerSec: m.cfg.SweepFilesPerSec, Exclude: m.cfg.ExcludePaths}
	var prev Snapshot
	var prevStart time.Time
	wait := delay
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		wait = every
		start := time.Now()
		cur, err := TakeSnapshot(ctx, roots(), opts)
		if err != nil {
			return nil // cancelled
		}
		if prev != nil {
			m.emitSweepDiff(Diff(prev, cur), prevStart)
		}
		prev, prevStart = cur, start
		m.setStatus(func(s *Status) { s.SweepLast = time.Now() })
	}
}

// emitSweepDiff reports changes the audit stream did not already report since
// the previous sweep started.
func (m *Module) emitSweepDiff(changes []Change, since time.Time) {
	n, skipped := 0, 0
	for _, c := range changes {
		if v, ok := m.recent.Load(c.Path); ok && !v.(time.Time).Before(since.Add(-time.Second)) {
			skipped++
			continue
		}
		if c.New != nil && c.New.IsDir && c.Kind == Modified && !c.Content {
			continue
		}
		if n >= maxSweepEvents {
			m.gaps.add("sweep_overflow", uint64(len(changes)-n-skipped), time.Now(), true)
			break
		}
		n++
		f := map[string]any{"source": "sweep", "op": string(c.Kind), "path": c.Path,
			"content_changed": c.Content, "writer_known": false}
		if c.New != nil {
			f["size"], f["mode"] = c.New.Size, fmt.Sprintf("%o", c.New.Mode&0o7777)
			f["uid"], f["gid"] = c.New.UID, c.New.GID
			if c.New.Hash != "" {
				f["sha256"] = c.New.Hash
			}
			if c.New.Target != "" {
				f["target"] = c.New.Target
			}
			f["is_dir"] = c.New.IsDir
		}
		if c.Old != nil && c.Old.Hash != "" {
			f["old_sha256"] = c.Old.Hash
		}
		m.send(event.Event{Time: time.Now().UTC(), Kind: KindFileChange, Priority: event.PriorityHigh, Fields: f}, false)
	}
	// Prune the audit-seen map.
	m.recent.Range(func(k, v any) bool {
		if time.Since(v.(time.Time)) > 3*m.cfg.SweepInterval+time.Minute {
			m.recent.Delete(k)
		}
		return true
	})
}
