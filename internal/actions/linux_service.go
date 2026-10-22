package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

// ---- systemd.dropin ----

// dropinKeys are the unit settings a drop-in may set. ExecStart and friends
// are deliberately absent: a drop-in must not swap a service's binary.
var dropinKeys = map[string]bool{
	"Restart": true, "RestartSec": true, "LimitNOFILE": true, "LimitNPROC": true, "LimitCORE": true,
	"MemoryMax": true, "MemoryHigh": true, "MemorySwapMax": true, "CPUQuota": true, "CPUWeight": true,
	"TasksMax": true, "IOWeight": true, "OOMScoreAdjust": true, "Nice": true, "TimeoutStartSec": true,
	"TimeoutStopSec": true, "UMask": true, "Environment": true, "PrivateTmp": true, "NoNewPrivileges": true,
	"ProtectKernelModules": true, "ProtectKernelTunables": true, "ProtectControlGroups": true,
	"ProtectSystem": true, "ProtectHome": true, "ReadOnlyPaths": true, "InaccessiblePaths": true,
	"PrivateNetwork": true, "RestrictAddressFamilies": true, "CapabilityBoundingSet": true,
	"StartLimitIntervalSec": true, "StartLimitBurst": true,
}

// dropinRestrictive keys can break a scored service's own behaviour.
var dropinRestrictive = map[string]bool{
	"ProtectSystem": true, "ProtectHome": true, "ReadOnlyPaths": true, "InaccessiblePaths": true,
	"PrivateNetwork": true, "RestrictAddressFamilies": true, "CapabilityBoundingSet": true, "NoNewPrivileges": true,
}

const kindMultiService = "linux.multi_service"

var dropinNameRe = regexp.MustCompile(`^[A-Za-z0-9_\-]{1,60}$`)
var sectionNameRe = regexp.MustCompile(`^(Service|Unit|Install|Socket)$`)

type systemdDropin struct{}

func (systemdDropin) Spec() Spec {
	return Spec{Name: "systemd.dropin", Risk: RiskService,
		Doc: "Write a systemd drop-in override (/etc/systemd/system/<unit>.d/<name>.conf) from an allowlist of settings, then daemon-reload.",
		Params: []ParamSpec{
			{Name: "unit", Type: String, Required: true, Check: func(v any) error {
				if !unitRe.MatchString(v.(string)) {
					return errors.New("invalid unit name")
				}
				return nil
			}},
			{Name: "name", Type: String, Default: "10-phylax", Check: func(v any) error {
				if !dropinNameRe.MatchString(v.(string)) {
					return errors.New("invalid drop-in name")
				}
				return nil
			}},
			{Name: "section", Type: String, Default: "Service", Check: func(v any) error {
				if !sectionNameRe.MatchString(v.(string)) {
					return errors.New("section must be Service, Unit, Install or Socket")
				}
				return nil
			}},
			{Name: "settings", Type: StringMap, Required: true},
		}}
}

func dropinPath(p Params) string {
	u := p.Str("unit")
	if !strings.Contains(u, ".") {
		u += ".service"
	}
	return "/etc/systemd/system/" + u + ".d/" + p.Str("name") + ".conf"
}

func dropinContent(p Params) ([]byte, error) {
	m := p.Map("settings")
	if len(m) == 0 {
		return nil, errors.New("settings is empty")
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# managed by phylax\n[" + p.Str("section") + "]\n")
	for _, k := range keys {
		if !dropinKeys[k] {
			return nil, fmt.Errorf("setting %q is not allowed in a drop-in", k)
		}
		if err := checkConfText("value of "+k, m[k]); err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "%s=%s\n", k, m[k])
	}
	return []byte(b.String()), nil
}

func (systemdDropin) Locks(p Params) []string  { return []string{LockService(p.Str("unit"))} }
func (systemdDropin) Touches(p Params) []Touch { return []Touch{pathTouch(dropinPath(p), OpModify)} }

func (systemdDropin) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	want, err := dropinContent(p)
	if err != nil {
		return Plan{}, err
	}
	var notes []string
	if env.lintApplies(p.Str("unit")) && env.scoredInfo() != nil && env.scoredInfo().ServiceScored(p.Str("unit")) {
		for k, v := range p.Map("settings") {
			if dropinRestrictive[k] {
				return Plan{}, unsafeConf("drop-in %s=%s can break scored service %s", k, v, p.Str("unit"))
			}
			if k == "Restart" && v == "no" {
				return Plan{}, unsafeConf("Restart=no removes the scored service's crash recovery")
			}
		}
	}
	old, exists, err := readFileIfExists(env.Resolve(dropinPath(p)))
	if err != nil {
		return Plan{}, err
	}
	if exists && string(old) == string(want) {
		return Plan{Done: true}, nil
	}
	if _, ok := env.Services.(DaemonReloader); !ok {
		notes = append(notes, "service manager cannot daemon-reload; reload units manually")
	}
	return Plan{Diff: "write " + dropinPath(p) + "\n" + renderDiff(old, want), Notes: notes}, nil
}

func (systemdDropin) Capture(_ context.Context, env *Env, p Params) (Rollback, error) {
	fr, err := deadman.SnapshotFiles(env.Resolve(dropinPath(p)))
	if err != nil {
		return Rollback{}, err
	}
	return Rollback{Kind: kindRestoreThen, Data: restoreThen{Files: fr, DaemonReload: true}}, nil
}

func (systemdDropin) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	want, err := dropinContent(p)
	if err != nil {
		return nil, err
	}
	file := env.Resolve(dropinPath(p))
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return nil, err
	}
	if err := atomicfile.WriteFile(file, want, 0o644); err != nil {
		return nil, err
	}
	if dr, ok := env.Services.(DaemonReloader); ok {
		if err := dr.DaemonReload(ctx); err != nil {
			return nil, fmt.Errorf("daemon-reload: %w", err)
		}
		return Output{"daemon_reload": "true"}, nil
	}
	return Output{"daemon_reload": "false"}, nil
}

func (systemdDropin) Verify(_ context.Context, env *Env, p Params) error {
	want, _ := dropinContent(p)
	got, _, err := readBounded(env.Resolve(dropinPath(p)))
	if err != nil {
		return err
	}
	if string(got) != string(want) {
		return errors.New("drop-in content differs")
	}
	return nil
}

// ---- service.config ----

type svcCfg struct {
	path   string
	style  confStyle
	stanza string
	units  []string
	guard  []string // names the scoring guard may know the service by
}

var svcCfgs = map[string]svcCfg{
	"sshd":    {"/etc/ssh/sshd_config", styleSpace, "", []string{"sshd", "ssh"}, []string{"sshd", "ssh"}},
	"postfix": {"/etc/postfix/main.cf", styleEquals, "", []string{"postfix"}, []string{"postfix"}},
	"dovecot": {"/etc/dovecot/dovecot.conf", styleEquals, "", []string{"dovecot"}, []string{"dovecot"}},
	"php":     {"/etc/php.ini", styleINI, "PHP", nil, []string{"httpd", "apache2", "php-fpm"}},
}

type serviceConfig struct{}

func (serviceConfig) Spec() Spec {
	return Spec{Name: "service.config", Risk: RiskService,
		Doc: "Edit several keys of a service's main config in one transaction (sshd, postfix, dovecot, php), run the service's own config check, optionally restart.",
		Params: []ParamSpec{
			{Name: "service", Type: Enum, Required: true, Enum: []string{"sshd", "postfix", "dovecot", "php"}},
			{Name: "settings", Type: StringMap, Required: true},
			{Name: "path", Type: Path},
			{Name: "restart", Type: Bool},
		}}
}

func (serviceConfig) cfg(p Params) svcCfg {
	c := svcCfgs[p.Str("service")]
	if p.Has("path") {
		c.path = p.Str("path")
	}
	return c
}

func (s serviceConfig) Locks(p Params) []string {
	l := lockForPath(s.cfg(p).path)
	for _, u := range s.cfg(p).units {
		l = append(l, LockService(u))
	}
	return l
}
func (s serviceConfig) Touches(p Params) []Touch {
	return []Touch{pathTouch(s.cfg(p).path, OpModify)}
}

func (s serviceConfig) edit(env *Env, p Params, lint bool) (old []byte, out string, changed bool, notes []string, err error) {
	c := s.cfg(p)
	old, _, err = readFileIfExists(env.Resolve(c.path))
	if err != nil {
		return
	}
	out = string(old)
	keys := make([]string, 0, len(p.Map("settings")))
	for k := range p.Map("settings") {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := p.Map("settings")[k]
		if lint {
			var w []string
			w, err = env.lintConf(c.path, c.stanza, k, v)
			if err != nil {
				return
			}
			notes = append(notes, w...)
		}
		var ch bool
		out, ch, err = editConf(out, c.style, c.stanza, k, v)
		if err != nil {
			return
		}
		changed = changed || ch
	}
	return
}

func (s serviceConfig) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	if len(p.Map("settings")) == 0 {
		return Plan{}, errors.New("settings is empty")
	}
	old, out, changed, notes, err := s.edit(env, p, true)
	if err != nil {
		return Plan{}, err
	}
	if !changed {
		return Plan{Done: true, Notes: notes}, nil
	}
	return Plan{Diff: renderDiff(old, []byte(out)), Notes: notes}, nil
}

func (s serviceConfig) Capture(_ context.Context, env *Env, p Params) (Rollback, error) {
	c := s.cfg(p)
	fr, err := deadman.SnapshotFiles(env.Resolve(c.path))
	if err != nil {
		return Rollback{}, err
	}
	rt := restoreThen{Files: fr}
	if p.Bool("restart") {
		rt.Restart = c.units
	}
	return Rollback{Kind: kindRestoreThen, Data: rt}, nil
}

func (s serviceConfig) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	c := s.cfg(p)
	err := atomicfile.Modify(env.Resolve(c.path), 0o644, func(old []byte, _ bool) ([]byte, error) {
		out := string(old)
		for k, v := range p.Map("settings") {
			var err error
			if out, _, err = editConf(out, c.style, c.stanza, k, v); err != nil {
				return nil, err
			}
		}
		return []byte(out), nil
	})
	if err != nil {
		return nil, err
	}
	// Check the new config before any restart, so a bad edit never reaches the daemon.
	if err := env.validateConf(ctx, c.path); err != nil {
		return nil, err
	}
	if p.Bool("restart") && len(c.units) > 0 && env.Services != nil {
		return nil, env.Services.Restart(ctx, c.units[0])
	}
	return nil, nil
}

func (s serviceConfig) Verify(ctx context.Context, env *Env, p Params) error {
	c := s.cfg(p)
	b, _, err := readBounded(env.Resolve(c.path))
	if err != nil {
		return err
	}
	for k, v := range p.Map("settings") {
		got := getConf(string(b), c.style, c.stanza, k)
		if len(got) == 0 || got[len(got)-1] != v {
			return fmt.Errorf("%s not applied", k)
		}
	}
	if p.Bool("restart") && len(c.units) > 0 && env.Services != nil {
		st, err := env.Services.State(ctx, c.units[0])
		if err != nil {
			return err
		}
		if !st.Active {
			return fmt.Errorf("%s is not active after restart", c.units[0])
		}
	}
	return nil
}

// ---- cockpit.disable ----

var cockpitUnits = []string{"cockpit.socket", "cockpit.service"}

type cockpitDisable struct{}

func (cockpitDisable) Spec() Spec {
	return Spec{Name: "cockpit.disable", Risk: RiskService,
		Doc:    "Stop and disable Cockpit (socket and service); optionally mask. A host without Cockpit is already done.",
		Params: []ParamSpec{{Name: "mask", Type: Bool}}}
}
func (cockpitDisable) Locks(Params) []string {
	return []string{LockService("cockpit.socket"), LockService("cockpit.service")}
}
func (c cockpitDisable) Touches(p Params) []Touch {
	var ts []Touch
	for _, u := range cockpitUnits {
		ts = append(ts, Touch{Kind: TouchService, Name: u, Op: OpStop}, Touch{Kind: TouchService, Name: u, Op: OpDisable})
		if p.Bool("mask") {
			ts = append(ts, Touch{Kind: TouchService, Name: u, Op: OpMask})
		}
	}
	return ts
}
func cockpitWant(p Params) []string {
	ops := []string{"stop", "disable"}
	if p.Bool("mask") {
		ops = append(ops, "mask")
	}
	return ops
}
func (cockpitDisable) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	sm, err := svcOrErr(env)
	if err != nil {
		return Plan{}, err
	}
	var parts []string
	for _, u := range cockpitUnits {
		st, err := sm.State(ctx, u)
		if err != nil {
			return Plan{}, err
		}
		if !st.Exists {
			continue
		}
		if todo := pending(cockpitWant(p), st); len(todo) > 0 {
			parts = append(parts, fmt.Sprintf("%s: active=%v enabled=%s; will %s", u, st.Active, st.Enabled, strings.Join(todo, ", ")))
		}
	}
	if len(parts) == 0 {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: strings.Join(parts, "\n")}, nil
}
func (cockpitDisable) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	var snaps []serviceRestore
	for _, u := range cockpitUnits {
		st, err := env.Services.State(ctx, u)
		if err != nil {
			return Rollback{}, err
		}
		if st.Exists {
			snaps = append(snaps, serviceRestore{Unit: u, State: st})
		}
	}
	return Rollback{Kind: kindMultiService, Data: snaps}, nil
}
func undoMultiService(ctx context.Context, env *Env, e deadman.Entry) error {
	var l []serviceRestore
	if err := json.Unmarshal(e.Data, &l); err != nil {
		return err
	}
	var errs []error
	for i := len(l) - 1; i >= 0; i-- {
		b, _ := json.Marshal(l[i])
		errs = append(errs, restoreServices(ctx, env, deadman.Entry{Data: b}))
	}
	return errors.Join(errs...)
}
func (cockpitDisable) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	sm := env.Services
	// Socket first: the service would be re-activated by the socket otherwise.
	for _, u := range cockpitUnits {
		st, err := sm.State(ctx, u)
		if err != nil {
			return nil, err
		}
		if !st.Exists {
			continue
		}
		todo := map[string]bool{}
		for _, op := range pending(cockpitWant(p), st) {
			todo[op] = true
		}
		for _, op := range []string{"stop", "disable", "mask"} {
			if todo[op] {
				if err := runOp(ctx, sm, op, u); err != nil {
					return nil, fmt.Errorf("%s %s: %w", op, u, err)
				}
			}
		}
	}
	return nil, nil
}
func (cockpitDisable) Verify(ctx context.Context, env *Env, p Params) error {
	for _, u := range cockpitUnits {
		st, err := env.Services.State(ctx, u)
		if err != nil {
			return err
		}
		if st.Exists {
			if left := pending(cockpitWant(p), st); len(left) > 0 {
				return fmt.Errorf("%s not disabled (still: %v)", u, left)
			}
		}
	}
	return nil
}
