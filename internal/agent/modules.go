package agent

import (
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/action"
	"github.com/PurdueBlueTeam/phylax/internal/detect"
	"github.com/PurdueBlueTeam/phylax/internal/rules"
	"github.com/PurdueBlueTeam/phylax/internal/spool"
	agentcrossview "github.com/PurdueBlueTeam/phylax/internal/agent/crossview"
	agentfim "github.com/PurdueBlueTeam/phylax/internal/agent/fimmod"
	agentlogs "github.com/PurdueBlueTeam/phylax/internal/agent/logsmod"
	agentnet "github.com/PurdueBlueTeam/phylax/internal/agent/netmod"
	agentproc "github.com/PurdueBlueTeam/phylax/internal/agent/procmod"
	agentrespond "github.com/PurdueBlueTeam/phylax/internal/agent/respond"
)

// Service is one declared service for attribution (docs: proc module).
type Service struct {
	Name string `json:"name"`
	Unit string `json:"unit,omitempty"`
	Exe  string `json:"exe,omitempty"`
}

// FimWatch is one watched path for the fim module.
type FimWatch struct {
	Path string `json:"path"`
	Kind string `json:"kind"` // persistence | content | config | log
}

// LogWatch is one file for the logs module.
type LogWatch struct {
	Path    string `json:"path"`
	Pattern string `json:"pattern,omitempty"`
}

// Modules is the wired telemetry/detection/response stack. It runs
// independently of the link: detection and automatic response keep
// working while the link is down (docs: principle 4).
type Modules struct {
	a        *Agent
	services *agentproc.Services
	fim      *agentfim.Module
	resp     *agentrespond.Module
	engine   *detect.Engine
	stop     chan struct{}
}

// StartModules wires and starts the module stack. It returns nil when
// nothing can run (e.g. invariants not met); it never fails the agent.
func (a *Agent) StartModules(services []Service, fimWatches []FimWatch, logWatches []LogWatch) *Modules {
	m := &Modules{
		a: a, services: agentproc.NewServices(),
		stop: make(chan struct{}),
	}
	for _, s := range services {
		m.services.Declare(s.Name, s.Unit, s.Exe)
	}

	// rules: embedded defaults, materialized under the state dir; a
	// config step may replace the dir later (hot reload).
	rulesDir := filepath.Join(a.dir, "rules")
	if err := rules.Default(rulesDir); err != nil {
		a.log.Printf("rules: %v (using none)", err)
	}
	recorder := &routerSink{m: m}
	m.engine = detect.New(recorder)
	if err := m.engine.Load(rulesDir); err != nil {
		a.log.Printf("rules: %v", err)
	}

	// fim
	fw := make([]agentfim.Watch, 0, len(fimWatches))
	for _, w := range fimWatches {
		fw = append(fw, agentfim.Watch{Path: w.Path, Kind: w.Kind})
	}
	m.fim = agentfim.New(recorder, fw, 5*time.Minute)

	// logs
	lw := make([]agentlogs.Watch, 0, len(logWatches))
	for _, w := range logWatches {
		var re *regexp.Regexp
		if w.Pattern != "" {
			re = regexp.MustCompile(w.Pattern)
		}
		lw = append(lw, agentlogs.Watch{File: w.Path, Pattern: re})
	}
	logs := agentlogs.New(recorder, lw)

	// proc
	proc := agentproc.New(recorder, m.services, "")

	// net
	net := agentnet.New(recorder, "")
	m.fim = agentfim.New(recorder, fw, 5*time.Minute)
	a.fim = m.fim
	xv := agentcrossview.New(recorder, "", "", nil)

	// respond (tier-0)
	resp := agentrespond.New(&agentrespond.Env{
		LockTry:     a.LockTry,
		LockRelease: a.LockRelease,
		LockOwner:   a.LockOwner,
		Health:      m.health,
		SafeMode:    func() bool { return a.safeMode },
		Publish:     a,
	}, m.recipes())
	m.resp = resp

	// supervised startup: each module restarts on panic/exit on its own
	a.StartModule("fim", m.fim.Run)
	a.StartModule("logs", logs.Run)
	a.StartModule("proc", proc.Run)
	a.StartModule("net", net.Run)
	a.StartModule("crossview", xv.Run)
	a.StartModule("respond", resp.Run)
	return m
}

// Router is the shared sink: module events go to the spool AND the rule
// engine.
type routerSink struct {
	m *Modules
}

func (r *routerSink) emit(evType string, data map[string]any, class int) {
	_ = r.m.a.PublishClass(evType, data, class)
	r.m.engine.Handle(evType, data)
}

// detect.AlertSink
func (r *routerSink) Alert(al detect.Alert) {
	// the alert is evidence: it goes to the spool, and tier-0 alerts
	// feed the respond module (docs: Response tiers).
	r.emit("alert", map[string]any{
		"rule": al.Rule, "severity": al.Severity, "tier": al.Tier,
		"attack": al.Attack, "key": al.Key, "ts": al.TS, "event": al.Event,
	}, spool.ClassProtected)
	if al.Tier == 0 {
		r.m.resp.Submit(al)
	}
}
// agentproc.Sink
func (r *routerSink) ProcStart(e agentproc.ProcEvent) {
	r.emit("process_start", evMap(e), spool.ClassProtected)
}
func (r *routerSink) ProcExit(pid int) {
	r.emit("process_exit", map[string]any{"pid": pid}, spool.ClassChurn)
}

// agentnet.Sink
func (r *routerSink) NetEvent(e agentnet.ConnEvent) {
	typ := "connection_new"
	switch e.Kind {
	case "listener_new":
		typ = "listener_new"
	case "connection_gone":
		typ = "connection_gone"
	}
	cl := spool.ClassChurn
	if typ != "connection_gone" {
		cl = spool.ClassProtected
	}
	r.emit(typ, evMap(e), cl)
}

// agentfim.Sink
func (r *routerSink) FileChange(e agentfim.FileEvent) {
	r.emit("file_change", evMap(e), spool.ClassProtected)
}

// agentlogs.Sink
func (r *routerSink) LogLine(e agentlogs.LogEvent) {
	r.emit("log_line", evMap(e), spool.ClassLog)
}
func (r *routerSink) LogCleared(e agentlogs.ClearedEvent) {
	r.emit("log_cleared", evMap(e), spool.ClassProtected)
}
// agentcrossview.Sink
func (r *routerSink) Crossview(e agentcrossview.Event) {
	switch e.Kind {
	case "hidden_pid":
		r.emit("hidden_pid", evMap(e), spool.ClassProtected)
	case "hidden_exec":
		r.emit("hidden_exec", evMap(e), spool.ClassProtected)
	case "ld_preload":
		r.emit("ld_preload", evMap(e), spool.ClassProtected)
	case "kernel_taint":
		r.emit("kernel_taint", evMap(e), spool.ClassProtected)
	}
}

// health is the post-action health check for tier-0 recipes.
func (m *Modules) health(name string) bool {
	// restore.firewall: once the real nftables restore lands (M4 egress
	// module) this checks the declared table is present. The scripted
	// restore always reports healthy.
	return true
}

// recipes are the built-in tier-0 automatic responses.
func (m *Modules) recipes() []agentrespond.Recipe {
	reg := m.a.Registry()
	return []agentrespond.Recipe{
		{
			For:  "D6.persistence-created",
			Name: "disable.persistence",
			Run: func(ctx context.Context, al detect.Alert, env *agentrespond.Env) (string, string, string, error) {
				path, _ := al.Event["path"].(string)
				if path == "" {
					return "", "", "no path in alert", nil
				}
				actName := "cron.disable"
				if filepath.Ext(path) == ".service" || filepath.Ext(path) == ".timer" {
					actName = "unit.disable"
				}
				act, err := reg.Get(actName)
				if err != nil {
					return "", "", "no action: "+err.Error(), nil
				}
				cr, err := act.Apply(action.Params{"path": path})
				return b64(cr.Before), b64(cr.After), cr.Diff, err
			},
		},
		{
			For:  "D2.content-tamper",
			Name: "quarantine.webshell",
			Run: func(ctx context.Context, al detect.Alert, env *agentrespond.Env) (string, string, string, error) {
				path, _ := al.Event["path"].(string)
				if path == "" || !looksLikeWebshell(path) {
					return "", "", "not a webshell candidate", nil
				}
				act, err := reg.Get("file.quarantine")
				if err != nil {
					return "", "", "no action: "+err.Error(), nil
				}
				cr, err := act.Apply(action.Params{"path": path})
				return b64(cr.Before), b64(cr.After), cr.Diff, err
			},
		},
		{
			// restore.firewall: the real nftables restore lands with the
			// egress/sinkhole module (M4, docker NET_ADMIN test). Until
			// then this recipe records the restore decision so the tier-0
			// machinery (rate limit, breaker, loop detection, locks) is
			// exercised end-to-end.
			For:  "D10b.firewall-tamper",
			Name: "restore.firewall",
			Run: func(ctx context.Context, al detect.Alert, env *agentrespond.Env) (string, string, string, error) {
				return "firewall:disabled", "firewall:declared", "re-apply declared host policy", nil
			},
		},
	}
}

func looksLikeWebshell(path string) bool {
	base := filepath.Base(path)
	for _, ext := range []string{".php", ".asp", ".aspx", ".jsp", ".phtml"} {
		if len(base) > len(ext) && base[len(base)-len(ext):] == ext {
			return true
		}
	}
	return false
}

// evMap marshals and back to a map so the rule engine sees one shape.
func evMap(v any) map[string]any {
	b, _ := json.Marshal(v)
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}

func b64(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return string(b)
}
