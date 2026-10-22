// Package vyos is the VyOS 1.4 adapter. The HTTP API commits on every request
// and VyOS's commit-confirm reboots the router, so lockout-class changes run
// over SSH under our own soft dead-man: a systemd-run timer on the router that
// loads the pre-change snapshot and commits. The config is saved only after
// the health check passes, so a surprise reboot returns to the old boot config.
package vyos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/devices"
)

// ManagedTag prefixes the description of every rule phylax creates.
const ManagedTag = "phylax-managed"

// Config configures one router.
type Config struct {
	Device    string
	Transport devices.Transport // HTTP client for reads, Dial for SSH, Host
	SSH       SSHConfig
	HTTPBase  string // https://host[:port]; empty disables HTTP reads
	APIKey    string
	// ArchiveDir holds pre-change snapshots (not /config/config.boot).
	ArchiveDir string // default /config/archive/phylax
	RevertUnit string // default phylax-revert
	// FreshHTTP returns an HTTP client sharing no connections with the main one.
	FreshHTTP func() *http.Client
}

// Adapter implements devices.Adapter for VyOS.
type Adapter struct {
	cfg  Config
	http *HTTPClient
	ssh  *SSHConfig
	seq  atomic.Uint64
}

var _ devices.Adapter = (*Adapter)(nil)

// New builds the adapter. Nothing is contacted until a method is called.
func New(cfg Config) (*Adapter, error) {
	if cfg.SSH.User == "" || len(cfg.SSH.Auth) == 0 {
		return nil, errors.New("vyos: SSH user and auth are required")
	}
	if cfg.SSH.Addr == "" {
		if cfg.Transport.Host == "" {
			return nil, errors.New("vyos: SSH address or transport host is required")
		}
		cfg.SSH.Addr = cfg.Transport.Host + ":22"
	}
	if cfg.SSH.Dial == nil {
		cfg.SSH.Dial = cfg.Transport.Dial
	}
	if cfg.ArchiveDir == "" {
		cfg.ArchiveDir = "/config/archive/phylax"
	}
	if cfg.RevertUnit == "" {
		cfg.RevertUnit = "phylax-revert"
	}
	if cfg.Device == "" {
		cfg.Device = cfg.Transport.Host
	}
	a := &Adapter{cfg: cfg}
	s := cfg.SSH
	a.ssh = &s
	if cfg.HTTPBase != "" {
		a.http = &HTTPClient{BaseURL: cfg.HTTPBase, Key: cfg.APIKey, HTTP: cfg.Transport.HTTP}
	}
	return a, nil
}

func (a *Adapter) Kind() devices.Kind { return devices.VyOS }
func (a *Adapter) Close() error       { return nil }

// Caps: no native confirm (it reboots); a soft dead-man instead.
func (a *Adapter) Caps() devices.Caps {
	return devices.Caps{SoftDeadman: true, StagedDiff: true, AuditLog: true, RollbackNative: true}
}

const prelude = "source /opt/vyatta/etc/functions/script-template\n"

// vbash runs a configure-mode script in one session.
func (a *Adapter) vbash(ctx context.Context, script string) (string, error) {
	return a.ssh.run(ctx, "vbash -s", prelude+script)
}

// op runs an op-mode command through the vyatta wrapper.
func (a *Adapter) op(ctx context.Context, cmd string) (string, error) {
	return a.ssh.run(ctx, "/opt/vyatta/bin/vyatta-op-cmd-wrapper "+cmd, "")
}

var errMarkers = []string{"commit failed", "set failed", "delete failed", "invalid command", "is not valid", "configuration path", "error:", "failed to"}

// scriptErr reports a vbash failure printed to the output.
func scriptErr(out string) error {
	for _, l := range strings.Split(out, "\n") {
		ll := strings.ToLower(l)
		if strings.Contains(ll, "nothing to delete") {
			continue
		}
		for _, m := range errMarkers {
			if strings.Contains(ll, m) {
				return fmt.Errorf("vyos: %s", strings.TrimSpace(l))
			}
		}
	}
	return nil
}

func (a *Adapter) Info(ctx context.Context) (devices.Info, error) {
	var txt string
	var err error
	if a.http != nil {
		txt, err = a.http.Show(ctx, "version")
	} else {
		txt, err = a.op(ctx, "show version")
	}
	if err != nil {
		return devices.Info{}, err
	}
	return parseVersion(txt), nil
}

var kvRE = regexp.MustCompile(`(?m)^\s*([A-Za-z][A-Za-z ]*?):\s+(.*?)\s*$`)

func parseVersion(txt string) devices.Info {
	in := devices.Info{Kind: devices.VyOS, Extra: map[string]string{}}
	for _, m := range kvRE.FindAllStringSubmatch(txt, -1) {
		in.Extra[strings.ToLower(m[1])] = m[2]
	}
	in.Version = strings.TrimPrefix(in.Extra["version"], "VyOS ")
	in.Hostname = in.Extra["hostname"]
	in.Serial = in.Extra["hardware s/n"]
	return in
}

func (a *Adapter) freshHTTP() *HTTPClient {
	if a.http == nil {
		return nil
	}
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
	return &HTTPClient{BaseURL: a.http.BaseURL, Key: a.http.Key, HTTP: hc}
}

// Probe: a brand-new SSH connection and (if configured) a new HTTPS connection.
func (a *Adapter) Probe(ctx context.Context) error {
	if _, err := a.op(ctx, "show version"); err != nil {
		return fmt.Errorf("%w: ssh: %v", devices.ErrProbe, err)
	}
	if fh := a.freshHTTP(); fh != nil {
		_, err := fh.Show(ctx, "version")
		if t, ok := fh.HTTP.Transport.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
		if err != nil {
			return fmt.Errorf("%w: https: %v", devices.ErrProbe, err)
		}
	}
	return nil
}

// ---- commit log ----

// CommitRec is one `show system commit` line.
type CommitRec struct {
	Index int
	When  string
	User  string
	Via   string
}

// Sig identifies a commit independent of its shifting index.
func (c CommitRec) Sig() string { return c.When + "|" + c.User + "|" + c.Via }

var commitRE = regexp.MustCompile(`^\s*(\d+)\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+by\s+(\S+)\s+via\s+(\S+)`)

func parseCommits(txt string) []CommitRec {
	var out []CommitRec
	for _, l := range strings.Split(txt, "\n") {
		if m := commitRE.FindStringSubmatch(l); m != nil {
			var idx int
			fmt.Sscanf(m[1], "%d", &idx)
			out = append(out, CommitRec{Index: idx, When: m[2], User: m[3], Via: m[4]})
		}
	}
	return out
}

func (a *Adapter) commits(ctx context.Context) ([]CommitRec, error) {
	var txt string
	var err error
	if a.http != nil {
		txt, err = a.http.Show(ctx, "system", "commit")
	} else {
		txt, err = a.op(ctx, "show system commit")
	}
	if err != nil {
		return nil, err
	}
	return parseCommits(txt), nil
}

// newSince returns the commits newer than the one with signature sig (newest
// first). If sig is not in the history (rotated out, or tampered with) every
// commit is returned and lost is true.
func newSince(cs []CommitRec, sig string) (out []CommitRec, lost bool) {
	if sig == "" {
		return cs, false
	}
	for i, c := range cs {
		if c.Sig() == sig {
			return cs[:i], false
		}
	}
	return cs, true
}

// ---- snapshot, diff, drift ----

func (a *Adapter) configLines(ctx context.Context) ([]string, error) {
	txt, err := a.op(ctx, "show configuration commands")
	if err != nil {
		return nil, err
	}
	return canonLines(txt), nil
}

func canonLines(txt string) []string {
	var ls []string
	for _, l := range strings.Split(txt, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			ls = append(ls, l)
		}
	}
	sort.Strings(ls)
	return ls
}

func (a *Adapter) bootHash(ctx context.Context) (string, error) {
	out, err := a.ssh.run(ctx, "sha256sum /config/config.boot", "")
	if err != nil {
		return "", err
	}
	f := strings.Fields(out)
	if len(f) == 0 {
		return "", errors.New("vyos: empty sha256sum output")
	}
	return f[0], nil
}

func (a *Adapter) Snapshot(ctx context.Context, label string) (devices.Snapshot, error) {
	cs, cerr := a.commits(ctx) // before the config, so a racing commit reads as drift
	ls, err := a.configLines(ctx)
	if err != nil {
		return devices.Snapshot{}, err
	}
	data := []byte(strings.Join(ls, "\n"))
	snap := devices.Snapshot{Device: a.cfg.Device, Label: label, Taken: time.Now(), Data: data, Hash: devices.HashBytes(data), Meta: map[string]string{}}
	if cerr == nil && len(cs) > 0 {
		snap.Meta["commit"] = cs[0].Sig()
	}
	if bh, err := a.bootHash(ctx); err == nil {
		snap.Meta["boot"] = bh
	}
	return snap, nil
}

func lineSet(data []byte) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(string(data), "\n") {
		if l != "" {
			m[l] = ""
		}
	}
	return m
}

func (a *Adapter) Diff(_ context.Context, x, y devices.Snapshot) (devices.Diff, error) {
	return devices.DiffMaps(lineSet(x.Data), lineSet(y.Data)), nil
}

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
		rep.Diff, _ = a.Diff(ctx, last, cur)
		for _, de := range rep.Diff.Entries {
			ev(devices.ConfigEvent{Change: "diff", Path: de.Path, Detail: string(de.Kind)})
		}
	}
	cs, err := a.commits(ctx)
	if err != nil {
		return rep, err
	}
	fresh, lost := newSince(cs, last.Meta["commit"])
	for i := len(fresh) - 1; i >= 0; i-- { // oldest first
		c := fresh[i]
		t, _ := time.Parse("2006-01-02 15:04:05", c.When)
		ev(devices.ConfigEvent{Change: "commit", Actor: c.User, Detail: "via " + c.Via, Ours: c.User == a.cfg.SSH.User, When: t})
	}
	if lost {
		ev(devices.ConfigEvent{Change: "oob", Detail: "last known commit is no longer in the history (rotated or altered)"})
	}
	if bh := cur.Meta["boot"]; bh != "" && last.Meta["boot"] != "" && bh != last.Meta["boot"] {
		ev(devices.ConfigEvent{Change: "oob", Path: "/config/config.boot", Detail: "boot config changed"})
		rep.Drifted = true
	}
	if out, err := a.vbash(ctx, "configure\ncompare saved\nexit discard\n"); err == nil && strings.TrimSpace(stripNoChange(out)) != "" {
		ev(devices.ConfigEvent{Change: "oob", Detail: "running config differs from the saved boot config"})
	}
	return rep, nil
}

func stripNoChange(out string) string {
	var keep []string
	for _, l := range strings.Split(out, "\n") {
		if !strings.Contains(strings.ToLower(l), "no changes") {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

// ---- admins, events ----

var loginUserRE = regexp.MustCompile(`^set system login user '?([^'\s]+)'?`)

func (a *Adapter) Admins(ctx context.Context) (devices.AdminState, error) {
	var st devices.AdminState
	out, err := a.ssh.run(ctx, "who", "")
	if err != nil {
		return st, err
	}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		s := devices.AdminSession{Name: f[0], Type: f[1]}
		if i := strings.Index(l, "("); i >= 0 {
			s.From = strings.Trim(l[i:], "()")
		}
		st.Sessions = append(st.Sessions, s)
	}
	ls, err := a.configLines(ctx)
	if err != nil {
		return st, err
	}
	seen := map[string]bool{}
	for _, l := range ls {
		if m := loginUserRE.FindStringSubmatch(l); m != nil && !seen[m[1]] {
			seen[m[1]] = true
			st.Configured = append(st.Configured, m[1])
		}
	}
	sort.Strings(st.Configured)
	return st, nil
}

// Events returns the commit log. The cursor is the newest commit signature seen.
func (a *Adapter) Events(ctx context.Context, f devices.EventFilter) ([]devices.Event, devices.Cursor, error) {
	if f.Source != "" && f.Source != "commit" {
		return nil, f.Since, fmt.Errorf("vyos: unknown event source %q", f.Source)
	}
	cs, err := a.commits(ctx)
	if err != nil {
		return nil, f.Since, err
	}
	fresh, _ := newSince(cs, string(f.Since))
	var out []devices.Event
	for i := len(fresh) - 1; i >= 0; i-- {
		c := fresh[i]
		t, _ := time.Parse("2006-01-02 15:04:05", c.When)
		out = append(out, devices.Event{When: t, Source: "commit", Actor: c.User, Cmd: "commit", Detail: "via " + c.Via, Seq: c.Sig()})
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	cur := f.Since
	if len(cs) > 0 {
		cur = devices.Cursor(cs[0].Sig())
	}
	return out, cur, nil
}

// HealthCheck is the runner callback: a fresh connection works and the router
// still has interfaces and routes; extra holds the scorer-mimic probes.
func (a *Adapter) HealthCheck(extra func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := a.Probe(ctx); err != nil {
			return err
		}
		for _, c := range []string{"show interfaces", "show ip route"} {
			out, err := a.op(ctx, c)
			if err != nil || strings.TrimSpace(out) == "" {
				return fmt.Errorf("vyos: %q unhealthy: %v", c, err)
			}
		}
		if extra != nil {
			return extra(ctx)
		}
		return nil
	}
}

func (a *Adapter) nextID(opt devices.TxOptions) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%d/%d", opt.Plan, opt.Node, a.seq.Add(1), time.Now().UnixNano())))
	return hex.EncodeToString(h[:])[:12]
}
