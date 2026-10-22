// Package palo is the PAN-OS adapter: the safe-change primitives over the XML
// API (config lock, scoped commit, validate, granular revert) and D14 drift
// detection from the running-config hash and the config log.
package palo

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/devices"
	"github.com/PurdueBlueTeam/phylax/internal/devices/palo/xmlapi"
)

// ManagedTag marks every object phylax creates; the adapter edits only tagged items.
const ManagedTag = "phylax-managed"

// Config configures one firewall.
type Config struct {
	Device    string // name in the manifest, for events
	Transport devices.Transport
	Key       string // API key of the read-write account
	Admin     string // that account's admin name (the partial-commit scope and journal attribution)
	Vsys      string // default vsys1

	PollInterval time.Duration // job and lock polling (default 2s)
	JobTimeout   time.Duration // commit/validate job deadline (default 5m)
	// FreshHTTP returns a client that shares no connection with the main one.
	// Default: a clone of the main transport with keep-alives off.
	FreshHTTP func() *http.Client
}

// Adapter implements devices.Adapter for PAN-OS.
type Adapter struct {
	cfg Config
	c   *xmlapi.Client
	seq atomic.Uint64
}

var _ devices.Adapter = (*Adapter)(nil)

// New builds the adapter. Nothing is contacted until a method is called.
func New(cfg Config) (*Adapter, error) {
	if cfg.Transport.HTTP == nil || cfg.Transport.Host == "" {
		return nil, errors.New("palo: transport HTTP client and host are required")
	}
	if cfg.Admin == "" || cfg.Key == "" {
		return nil, errors.New("palo: admin name and key are required")
	}
	if cfg.Vsys == "" {
		cfg.Vsys = "vsys1"
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 2 * time.Second
	}
	if cfg.JobTimeout == 0 {
		cfg.JobTimeout = 5 * time.Minute
	}
	if cfg.Device == "" {
		cfg.Device = cfg.Transport.Host
	}
	a := &Adapter{cfg: cfg}
	a.c = &xmlapi.Client{BaseURL: baseURL(cfg.Transport.Host), Key: cfg.Key, HTTP: cfg.Transport.HTTP}
	return a, nil
}

func baseURL(h string) string {
	if strings.Contains(h, "://") {
		return h
	}
	return "https://" + h
}

// Client exposes the XML client (for ad hoc reads such as rule hit counts).
func (a *Adapter) Client() *xmlapi.Client { return a.c }

func (a *Adapter) Kind() devices.Kind { return devices.PanOS }
func (a *Adapter) Close() error       { return nil }

// Caps: PAN-OS has no commit-confirm, so no dead-man of any kind.
func (a *Adapter) Caps() devices.Caps {
	return devices.Caps{ConfigLock: true, ScopedCommit: true, StagedDiff: true, Validate: true,
		ConnEvents: true, AuditLog: true, RollbackNative: true}
}

func (a *Adapter) devPath() string  { return "/config/devices/entry[@name='localhost.localdomain']" }
func (a *Adapter) vsysPath() string { return xmlapi.EntryXPath(a.devPath()+"/vsys", a.cfg.Vsys) }

// PermittedIPPath is the management ACL xpath.
func (a *Adapter) PermittedIPPath() string { return a.devPath() + "/deviceconfig/system/permitted-ip" }

var uptimeRE = regexp.MustCompile(`(?:(\d+) days?, )?(\d+):(\d+):(\d+)`)

func (a *Adapter) Info(ctx context.Context) (devices.Info, error) {
	m, err := a.c.SystemInfo(ctx)
	if err != nil {
		return devices.Info{}, err
	}
	return infoFrom(m), nil
}

func infoFrom(m map[string]string) devices.Info {
	in := devices.Info{Kind: devices.PanOS, Hostname: m["hostname"], Version: m["sw-version"], Serial: m["serial"], Extra: m}
	if g := uptimeRE.FindStringSubmatch(m["uptime"]); g != nil {
		d, _ := strconv.Atoi(g[1])
		h, _ := strconv.Atoi(g[2])
		mi, _ := strconv.Atoi(g[3])
		s, _ := strconv.Atoi(g[4])
		in.Uptime = time.Duration(d)*24*time.Hour + time.Duration(h)*time.Hour + time.Duration(mi)*time.Minute + time.Duration(s)*time.Second
	}
	return in
}

// freshClient is a client that opens a brand-new connection, so a management
// change that kills new sessions is seen even if the established one survives.
func (a *Adapter) freshClient() *xmlapi.Client {
	var hc *http.Client
	if a.cfg.FreshHTTP != nil {
		hc = a.cfg.FreshHTTP()
	} else if t, ok := a.cfg.Transport.HTTP.Transport.(*http.Transport); ok {
		tc := t.Clone()
		tc.DisableKeepAlives = true
		hc = &http.Client{Transport: tc, Timeout: a.cfg.Transport.HTTP.Timeout}
	} else {
		hc = a.cfg.Transport.HTTP
	}
	return &xmlapi.Client{BaseURL: a.c.BaseURL, Key: a.cfg.Key, HTTP: hc}
}

func (a *Adapter) Probe(ctx context.Context) error {
	fc := a.freshClient()
	_, err := fc.SystemInfo(ctx)
	if t, ok := fc.HTTP.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
	if err != nil {
		return fmt.Errorf("%w: %v", devices.ErrProbe, err)
	}
	return nil
}

// ---- snapshots ----

func (a *Adapter) latestCfgSeq(ctx context.Context) (int, error) {
	es, err := a.c.LogQuery(ctx, "config", "", 1, 0, a.cfg.PollInterval, a.cfg.JobTimeout)
	if err != nil {
		return 0, err
	}
	max := 0
	for _, e := range es {
		if n, _ := strconv.Atoi(e["seqno"]); n > max {
			max = n
		}
	}
	return max, nil
}

func (a *Adapter) Snapshot(ctx context.Context, label string) (devices.Snapshot, error) {
	seq, seqErr := a.latestCfgSeq(ctx) // read before the config so a racing commit shows up as drift
	n, err := a.c.ConfigShow(ctx, "/config")
	if err != nil {
		return devices.Snapshot{}, err
	}
	if n == nil {
		return devices.Snapshot{}, errors.New("palo: device returned no running config")
	}
	data := xmlapi.Canonical(n)
	snap := devices.Snapshot{Device: a.cfg.Device, Label: label, Taken: time.Now(), Data: data, Hash: devices.HashBytes(data), Meta: map[string]string{}}
	if seqErr == nil {
		snap.Meta["cfgseq"] = strconv.Itoa(seq)
	}
	return snap, nil
}

func flatten(data []byte) (map[string]string, error) {
	n, err := xmlapi.ParseNode(data)
	if err != nil {
		return nil, err
	}
	return xmlapi.Flatten(n), nil
}

func (a *Adapter) Diff(_ context.Context, x, y devices.Snapshot) (devices.Diff, error) {
	fx, err := flatten(x.Data)
	if err != nil {
		return devices.Diff{}, err
	}
	fy, err := flatten(y.Data)
	if err != nil {
		return devices.Diff{}, err
	}
	return devices.DiffMaps(fx, fy), nil
}

// ---- drift (D14) ----

func (a *Adapter) Drift(ctx context.Context, last devices.Snapshot) (devices.DriftReport, error) {
	cur, err := a.Snapshot(ctx, "drift")
	if err != nil {
		return devices.DriftReport{}, err
	}
	rep := devices.DriftReport{Device: a.cfg.Device, Hash: cur.Hash, Drifted: cur.Hash != last.Hash}
	now := time.Now()
	ev := func(e devices.ConfigEvent) {
		e.Device = a.cfg.Device
		if e.When.IsZero() {
			e.When = now
		}
		rep.Events = append(rep.Events, e)
	}
	if rep.Drifted {
		d, err := a.Diff(ctx, last, cur)
		if err == nil {
			rep.Diff = d
			for _, de := range d.Entries {
				ev(devices.ConfigEvent{Change: "diff", Path: de.Path, Detail: string(de.Kind)})
			}
		}
	}
	// Who did it: config log entries after the last known-good.
	since, _ := strconv.Atoi(last.Meta["cfgseq"])
	evs, _, err := a.Events(ctx, devices.EventFilter{Source: "config", Since: devices.Cursor(strconv.Itoa(since))})
	if err != nil {
		return rep, fmt.Errorf("palo: config log: %w", err)
	}
	for _, e := range evs {
		ours := e.Actor == a.cfg.Admin
		change := "diff"
		switch {
		case e.Cmd == "commit":
			change = "commit"
		case strings.HasPrefix(e.Path, "/config/mgt-config/users") && e.Cmd == "delete":
			change = "admin_del"
		case strings.HasPrefix(e.Path, "/config/mgt-config/users"):
			change = "admin_add"
		}
		ev(devices.ConfigEvent{Change: change, Actor: e.Actor, SrcIP: e.SrcIP, Path: e.Path, Detail: e.Cmd, Ours: ours, When: e.When})
	}
	// Foreign lock and foreign staged edits are early warnings.
	if locks, err := a.c.ShowConfigLocks(ctx, a.cfg.Vsys); err == nil {
		for _, l := range locks {
			if l.Admin != a.cfg.Admin {
				ev(devices.ConfigEvent{Change: "lock", Actor: l.Admin, Detail: l.Comment})
			}
		}
	}
	if ch, err := a.c.ListChanges(ctx); err == nil {
		for _, c := range ch {
			if c.Admin != a.cfg.Admin {
				ev(devices.ConfigEvent{Change: "pending", Actor: c.Admin, Path: c.XPath, Detail: c.Cmd})
			}
		}
	}
	return rep, nil
}

// ---- admins and events ----

func (a *Adapter) Admins(ctx context.Context) (devices.AdminState, error) {
	var st devices.AdminState
	live, err := a.c.ShowAdmins(ctx, false)
	if err != nil {
		return st, err
	}
	for _, s := range live {
		st.Sessions = append(st.Sessions, devices.AdminSession{Name: s.Name, From: s.From, Type: s.Type})
	}
	all, err := a.c.ShowAdmins(ctx, true)
	if err != nil {
		return st, err
	}
	for _, s := range all {
		st.Configured = append(st.Configured, s.Name)
	}
	sort.Strings(st.Configured)
	return st, nil
}

// Events reads the config, system or traffic log. Since is the last seqno seen.
func (a *Adapter) Events(ctx context.Context, f devices.EventFilter) ([]devices.Event, devices.Cursor, error) {
	src := f.Source
	if src == "" {
		src = "config"
	}
	switch src {
	case "config", "system", "traffic":
	default:
		return nil, f.Since, fmt.Errorf("palo: unknown log source %q", src)
	}
	q := f.Query
	since, _ := strconv.Atoi(string(f.Since))
	if since > 0 {
		sq := "(seqno geq " + strconv.Itoa(since+1) + ")"
		if q != "" {
			q = "(" + q + " and " + sq + ")"
		} else {
			q = sq
		}
	}
	n := f.Limit
	if n <= 0 || n > 5000 {
		n = 1000
	}
	recs, err := a.c.LogQuery(ctx, src, q, n, 0, a.cfg.PollInterval, a.cfg.JobTimeout)
	if err != nil {
		return nil, f.Since, err
	}
	maxSeq := since
	var out []devices.Event
	for _, r := range recs {
		sq, _ := strconv.Atoi(r["seqno"])
		if sq <= since {
			continue // device-side filters can be loose; the cursor is authoritative
		}
		if sq > maxSeq {
			maxSeq = sq
		}
		e := devices.Event{Source: src, Actor: r["admin"], SrcIP: r["host"], Cmd: r["cmd"], Path: r["path"], Seq: r["seqno"], Detail: r["opaque"]}
		if r["src"] != "" {
			e.SrcIP = r["src"]
		}
		if t, err := time.Parse("2006/01/02 15:04:05", r["time_generated"]); err == nil {
			e.When = t
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		x, _ := strconv.Atoi(out[i].Seq)
		y, _ := strconv.Atoi(out[j].Seq)
		return x < y
	})
	return out, devices.Cursor(strconv.Itoa(maxSeq)), nil
}

func (a *Adapter) nextID(opt devices.TxOptions) string {
	clean := func(s string) string {
		return strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
				return r
			}
			return '-'
		}, s)
	}
	return fmt.Sprintf("%s-%s-%d", clean(opt.Plan), clean(opt.Node), a.seq.Add(1))
}
