package actions

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/integrations/wazuh"
)

// WazuhAPI is the part of the Wazuh API client the actions use
// (*wazuh.Client implements it).
type WazuhAPI interface {
	Health(ctx context.Context) (*wazuh.Health, error)
	Agents(ctx context.Context) ([]wazuh.Agent, error)
}

// WazuhGroupsAPI is implemented by API clients that can list agent groups
// (*wazuh.Client does); wazuh.capture uses it when available.
type WazuhGroupsAPI interface {
	Groups(ctx context.Context) ([]wazuh.Group, error)
}

// WazuhFactory builds the LinuxEnv.Wazuh hook from a base client config (API
// credentials and CA come from the agent's configuration, never from params).
func WazuhFactory(base wazuh.Config) func(ctx context.Context, api, minVersion string) (WazuhAPI, error) {
	return func(_ context.Context, api, minVersion string) (WazuhAPI, error) {
		cfg := base
		cfg.APIURL = api
		if minVersion != "" {
			cfg.MinVersion = minVersion
		}
		return wazuh.New(cfg)
	}
}

func (e *Env) wazuhAPI(ctx context.Context, p Params) (WazuhAPI, error) {
	if e.lx().Wazuh == nil {
		return nil, errors.New("no Wazuh API credentials configured on this agent")
	}
	return e.lx().Wazuh(ctx, p.Str("api"), p.Str("min_version"))
}

var apiParam = ParamSpec{Name: "api", Type: String, Required: true, Max: 512, Check: func(v any) error {
	if !strings.HasPrefix(v.(string), "https://") && !strings.HasPrefix(v.(string), "http://") {
		return errors.New("api must be an http(s) URL")
	}
	return nil
}}

type wazuhRO struct{}

func (wazuhRO) Locks(Params) []string                                   { return nil }
func (wazuhRO) Touches(Params) []Touch                                  { return nil }
func (wazuhRO) Plan(context.Context, *Env, Params) (Plan, error)        { return Plan{Diff: "read-only"}, nil }
func (wazuhRO) Capture(context.Context, *Env, Params) (Rollback, error) { return Rollback{}, nil }
func (wazuhRO) Verify(context.Context, *Env, Params) error              { return nil }

// ---- wazuh.health ----

type wazuhHealth struct{ wazuhRO }

func (wazuhHealth) Spec() Spec {
	return Spec{Name: "wazuh.health", Risk: RiskNone, ReadOnly: true,
		Doc:    "Wazuh API health: manager version pin (>= min_version), no agent newer than the manager, active/disconnected/never-connected counts. min_active requires at least that many active agents.",
		Params: []ParamSpec{apiParam, {Name: "min_version", Type: String, Max: 32}, {Name: "min_active", Type: Int}}}
}

func (wazuhHealth) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	c, err := env.wazuhAPI(ctx, p)
	if err != nil {
		return nil, err
	}
	h, err := c.Health(ctx)
	out := Output{}
	if h != nil {
		out["manager_version"] = h.ManagerVersion.String()
		out["agents"] = fmt.Sprint(len(h.Agents))
		out["active"] = fmt.Sprint(h.Active)
		out["disconnected"] = strings.Join(h.Disconnected, ",")
		out["never_connected"] = strings.Join(h.NeverConnected, ",")
	}
	if err != nil {
		return out, err
	}
	if n, ok := p.Int("min_active"); ok && h.Active < n {
		return out, fmt.Errorf("%d agents active, want at least %d (disconnected: %v, never connected: %v)", h.Active, n, h.Disconnected, h.NeverConnected)
	}
	return out, nil
}

// ---- wazuh.capture ----

type wazuhCapture struct{ wazuhRO }

func (wazuhCapture) Spec() Spec {
	return Spec{Name: "wazuh.capture", Risk: RiskNone, ReadOnly: true,
		Doc:    "Write health.json, agents.json, agents.csv, groups.json and (from the groups endpoint) group_details.json to the inject-kit directory out.",
		Params: []ParamSpec{apiParam, {Name: "out", Type: Path, Required: true}, {Name: "min_version", Type: String, Max: 32}}}
}
func (wazuhCapture) Touches(p Params) []Touch { return []Touch{pathTouch(p.Str("out"), OpModify)} }

func (wazuhCapture) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	c, err := env.wazuhAPI(ctx, p)
	if err != nil {
		return nil, err
	}
	agents, err := c.Agents(ctx)
	if err != nil {
		return nil, err
	}
	dir := env.Resolve(p.Str("out"))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	write := func(name string, b []byte) error { return atomicfile.WriteFile(filepath.Join(dir, name), b, 0o640) }
	aj, _ := json.MarshalIndent(agents, "", "  ")
	if err := write("agents.json", aj); err != nil {
		return nil, err
	}
	var cb bytes.Buffer
	w := csv.NewWriter(&cb)
	_ = w.Write([]string{"id", "name", "ip", "version", "status", "last_keepalive", "groups"})
	groups := map[string][]string{}
	for _, a := range agents {
		_ = w.Write([]string{csvSafe(a.ID), csvSafe(a.Name), csvSafe(a.IP), csvSafe(a.Version), csvSafe(a.Status), csvSafe(a.LastKeepAlive), csvSafe(strings.Join(a.Groups, ";"))})
		for _, g := range a.Groups {
			groups[g] = append(groups[g], a.Name)
		}
	}
	w.Flush()
	if err := write("agents.csv", cb.Bytes()); err != nil {
		return nil, err
	}
	// Groups from the API: includes groups with no agents yet, with sizes and
	// configuration checksums (groups.json stays group -> agent names).
	var details []wazuh.Group
	if ga, ok := c.(WazuhGroupsAPI); ok {
		gs, err := ga.Groups(ctx)
		if err != nil {
			return nil, fmt.Errorf("groups: %w", err)
		}
		details = gs
		for _, g := range gs {
			if _, ok := groups[g.Name]; !ok {
				groups[g.Name] = []string{}
			}
		}
		dj, _ := json.MarshalIndent(gs, "", "  ")
		if err := write("group_details.json", dj); err != nil {
			return nil, err
		}
	}
	gj, _ := json.MarshalIndent(groups, "", "  ")
	if err := write("groups.json", gj); err != nil {
		return nil, err
	}
	h, herr := c.Health(ctx)
	hr := map[string]any{"time": env.Now().UTC().Format(time.RFC3339), "agents": len(agents)}
	if h != nil {
		hr["manager_version"], hr["active"] = h.ManagerVersion.String(), h.Active
		hr["disconnected"], hr["never_connected"] = h.Disconnected, h.NeverConnected
	}
	if herr != nil {
		hr["health_error"] = herr.Error()
	}
	hb, _ := json.MarshalIndent(hr, "", "  ")
	if err := write("health.json", hb); err != nil {
		return nil, err
	}
	return Output{"agents": fmt.Sprint(len(agents)), "groups": fmt.Sprint(len(groups)), "group_details": fmt.Sprint(len(details)), "dir": dir}, nil
}

// csvSafe neutralises spreadsheet formula injection from agent-supplied names.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// ---- wazuh.test_alert ----

var markerRe = regexp.MustCompile(`^[A-Za-z0-9 _.:\-]{1,200}$`)

type wazuhTestAlert struct{ wazuhRO }

func (wazuhTestAlert) Spec() Spec {
	return Spec{Name: "wazuh.test_alert", Risk: RiskNone,
		Doc: "Append a marker line to a monitored log under /var/log so a test alert fires. Append only; not idempotent by design.",
		Params: []ParamSpec{
			{Name: "path", Type: Path, Required: true, Check: func(v any) error {
				if s := v.(string); filepath.Clean(s) != s || !strings.HasPrefix(s, "/var/log/") {
					return errors.New("path must be a clean file under /var/log")
				}
				return nil
			}},
			{Name: "marker", Type: String, Required: true, Max: 200, Check: func(v any) error {
				if !markerRe.MatchString(v.(string)) {
					return errors.New("marker may contain only letters, digits, space and _.:-")
				}
				return nil
			}}}}
}
func (wazuhTestAlert) Touches(p Params) []Touch { return []Touch{pathTouch(p.Str("path"), OpModify)} }
func (wazuhTestAlert) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	if st, err := os.Lstat(env.Resolve(p.Str("path"))); err == nil && !st.Mode().IsRegular() {
		return Plan{}, errors.New("path is not a regular file")
	}
	return Plan{Diff: "append marker line to " + p.Str("path")}, nil
}

func markerLine(env *Env, p Params) string {
	return env.Now().UTC().Format(time.RFC3339) + " phylax " + p.Str("marker") + "\n"
}

func (wazuhTestAlert) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	path := env.Resolve(p.Str("path"))
	if st, err := os.Lstat(path); err == nil && !st.Mode().IsRegular() {
		return nil, errors.New("path is not a regular file")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	line := markerLine(env, p)
	if _, err := f.WriteString(line); err != nil {
		return nil, err
	}
	return Output{"line": strings.TrimSpace(line)}, f.Sync()
}

func (wazuhTestAlert) Verify(_ context.Context, env *Env, p Params) error {
	b, _, err := readBounded(env.Resolve(p.Str("path")))
	if err != nil {
		return err
	}
	if !strings.Contains(string(b), " phylax "+p.Str("marker")+"\n") {
		return errors.New("marker not found in the log after append")
	}
	return nil
}
