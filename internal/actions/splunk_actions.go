package actions

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

// Splunk actions. None of them reads or changes searches, saved searches,
// dashboards, roles or scored indexes: they touch the HEC input, one new
// index, one user's password (guarded) and the sidecar switch in server.conf.

const (
	hecBase     = "/servicesNS/nobody/splunk_httpinput/data/inputs/http"
	kindSplunk  = "splunk.hec"
	maxRESTBody = 64 << 10
)

var (
	indexRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	tokenRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	restPath  = regexp.MustCompile(`^/(services|servicesNS/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/[A-Za-z0-9_./%:@-]*$`)
	splunkSys = map[string]bool{"main": true, "summary": true, "history": true, "defaultdb": true,
		"lastchanceindex": true, "splunklogger": true, "notable": true, "risk": true}
)

func init() {
	RegisterUndo(kindSplunk, func(ctx context.Context, env *Env, e deadman.Entry) error {
		var r hecUndo
		if err := jsonUndo(e, &r); err != nil {
			return err
		}
		api, err := splunkOrErr(ctx, env)
		if err != nil {
			return err
		}
		var errs []error
		if r.TokenCreated {
			if _, err := api.Delete(ctx, hecBase+"/"+url.PathEscape(r.Token)); err != nil && !isSplunkStatus(err, 404) {
				errs = append(errs, err)
			}
		}
		if r.HECEnabledByUs {
			if _, err := api.Post(ctx, hecBase+"/http", url.Values{"disabled": {"1"}}); err != nil {
				errs = append(errs, err)
			}
		}
		if r.IndexCreated {
			if _, err := api.Delete(ctx, "/services/data/indexes/"+url.PathEscape(r.Index)); err != nil && !isSplunkStatus(err, 404) {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	})
}

// ---- splunk.rest (read-only) ----

type splunkREST struct{}

func (splunkREST) Spec() Spec {
	return Spec{Name: "splunk.rest", Runs: RunsController, Risk: RiskNone, ReadOnly: true,
		Doc:    "Read-only splunkd REST GET (apps, inputs, users) for review. Search job endpoints are refused.",
		Params: []ParamSpec{{Name: "path", Type: String, Required: true, Max: 512, Check: checkRESTPath}}}
}

func checkRESTPath(v any) error {
	p := v.(string)
	if !restPath.MatchString(p) || strings.Contains(p, "..") {
		return errors.New("path must be a /services or /servicesNS REST path")
	}
	l := strings.ToLower(p)
	if strings.Contains(l, "/search/jobs") || strings.Contains(l, "/saved/searches") || strings.Contains(l, "/search/") && strings.Contains(l, "export") {
		return errors.New("search endpoints are never used (scored searches stay untouched)")
	}
	return nil
}

func (splunkREST) Locks(Params) []string  { return nil }
func (splunkREST) Touches(Params) []Touch { return nil }
func (splunkREST) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	if _, err := splunkOrErr(ctx, env); err != nil {
		return Plan{}, err
	}
	return Plan{Diff: "GET " + p.Str("path")}, nil
}
func (splunkREST) Capture(context.Context, *Env, Params) (Rollback, error) { return Rollback{}, nil }
func (splunkREST) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	api, err := splunkOrErr(ctx, env)
	if err != nil {
		return nil, err
	}
	b, err := api.Get(ctx, p.Str("path"), url.Values{"count": {"0"}})
	if err != nil {
		return nil, err
	}
	out := Output{}
	if es, err := splunkEntries(b); err == nil {
		names := make([]string, 0, len(es))
		for _, e := range es {
			names = append(names, e.Name)
		}
		out["count"] = fmt.Sprint(len(es))
		out["names"] = strings.Join(names, ",")
	}
	body := b
	if len(body) > maxRESTBody {
		body = body[:maxRESTBody]
		out["truncated"] = "true"
	}
	out["body"] = redactSplunk(string(body))
	return out, nil
}
func (splunkREST) Verify(context.Context, *Env, Params) error { return nil }

var secretJSON = regexp.MustCompile(`("(?:password|token|hash|sessionKey|secret|pass4SymmKey|sslPassword|clear_password)"\s*:\s*)"[^"]*"`)

// redactSplunk masks secret-looking JSON fields in a response.
func redactSplunk(s string) string { return secretJSON.ReplaceAllString(s, `$1"<redacted>"`) }

// ---- splunk.password ----

type splunkPassword struct{}

func (splunkPassword) Spec() Spec {
	return Spec{Name: "splunk.password", Runs: RunsController, Risk: RiskLockout,
		Doc: "Change a Splunk local user's password; proves the new password with a fresh login. Scored users change only in a PCR transaction.",
		Params: []ParamSpec{
			{Name: "user", Type: String, Required: true, Max: 128, Check: func(v any) error {
				if !tokenRe.MatchString(v.(string)) {
					return errors.New("invalid user name")
				}
				return nil
			}},
			{Name: "password", Type: String, Secret: true, Max: 256}}}
}
func (splunkPassword) Locks(Params) []string { return nil }
func (splunkPassword) Touches(p Params) []Touch {
	return []Touch{acctTouch(p.Str("user"), OpSetPassword)}
}
func (splunkPassword) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	if len(p.Str("password")) < 8 {
		return Plan{}, errors.New("password of at least 8 characters required (injected from the vault)")
	}
	api, err := splunkOrErr(ctx, env)
	if err != nil {
		return Plan{}, err
	}
	if _, err := api.Get(ctx, "/services/authentication/users/"+url.PathEscape(p.Str("user")), nil); err != nil {
		return Plan{}, fmt.Errorf("user %q: %w", p.Str("user"), err)
	}
	// Idempotence: if the new password already logs in, nothing to do.
	if _, err := api.As(p.Str("user"), p.Str("password")).Get(ctx, "/services/authentication/current-context", nil); err == nil {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: fmt.Sprintf("set password of Splunk user %s: <redacted>", p.Str("user")),
		Notes: []string{"not reversible: the old password is unknown to the agent"}}, nil
}
func (splunkPassword) Capture(context.Context, *Env, Params) (Rollback, error) {
	return Rollback{}, nil
}
func (splunkPassword) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	api, err := splunkOrErr(ctx, env)
	if err != nil {
		return nil, err
	}
	_, err = api.Post(ctx, "/services/authentication/users/"+url.PathEscape(p.Str("user")), url.Values{"password": {p.Str("password")}})
	if err != nil {
		return nil, redactErr(err, p.Str("password"))
	}
	return nil, nil
}
func (splunkPassword) Verify(ctx context.Context, env *Env, p Params) error {
	api, err := splunkOrErr(ctx, env)
	if err != nil {
		return err
	}
	if _, err := api.As(p.Str("user"), p.Str("password")).Get(ctx, "/services/authentication/current-context", nil); err != nil {
		return fmt.Errorf("fresh login with the new password failed: %w", err)
	}
	return nil
}

func redactErr(err error, secrets ...string) error {
	msg := err.Error()
	for _, s := range secrets {
		if s != "" {
			msg = strings.ReplaceAll(msg, s, "<redacted>")
		}
	}
	return errors.New(msg)
}

// ---- splunk.hec_setup ----

type hecUndo struct {
	Index          string `json:"index"`
	IndexCreated   bool   `json:"index_created"`
	Token          string `json:"token"`
	TokenCreated   bool   `json:"token_created"`
	HECEnabledByUs bool   `json:"hec_enabled_by_us"`
}

type splunkHEC struct{}

func (splunkHEC) Spec() Spec {
	return Spec{Name: "splunk.hec_setup", Runs: RunsController, Risk: RiskService,
		Doc: "Create the phylax index and an HEC token bound to it through the management API. Existing indexes and tokens are never modified; scored indexes are refused. The token value is returned in Output secret.token for the vault.",
		Params: []ParamSpec{
			{Name: "index", Type: String, Required: true, Check: func(v any) error {
				s := v.(string)
				if !indexRe.MatchString(s) || splunkSys[s] {
					return errors.New("invalid or reserved index name (lowercase letters, digits, - and _; no built-in index)")
				}
				return nil
			}},
			{Name: "token_name", Type: String, Required: true, Check: func(v any) error {
				if !tokenRe.MatchString(v.(string)) {
					return errors.New("invalid token name")
				}
				return nil
			}}}}
}
func (splunkHEC) Locks(Params) []string  { return nil }
func (splunkHEC) Touches(Params) []Touch { return nil }

type hecState struct {
	indexExists bool
	tokenExists bool
	tokenIndex  string
	tokenOff    bool
	token       string
	hecDisabled bool
}

func readHEC(ctx context.Context, api SplunkAPI, p Params) (hecState, error) {
	var st hecState
	b, err := api.Get(ctx, "/services/data/indexes/"+url.PathEscape(p.Str("index")), nil)
	switch {
	case err == nil:
		st.indexExists = true
	case isSplunkStatus(err, 404):
	default:
		return st, fmt.Errorf("index lookup: %w", err)
	}
	_ = b
	b, err = api.Get(ctx, hecBase+"/"+url.PathEscape(p.Str("token_name")), nil)
	switch {
	case err == nil:
		es, derr := splunkEntries(b)
		if derr != nil {
			return st, derr
		}
		if len(es) > 0 {
			st.tokenExists = true
			c := es[0].Content
			st.tokenIndex = contentStr(c, "index")
			st.tokenOff = contentStr(c, "disabled") == "true" || contentStr(c, "disabled") == "1"
			st.token = contentStr(c, "token")
		}
	case isSplunkStatus(err, 404):
	default:
		return st, fmt.Errorf("token lookup: %w", err)
	}
	b, err = api.Get(ctx, hecBase+"/http", nil)
	switch {
	case err == nil:
		if es, derr := splunkEntries(b); derr == nil && len(es) > 0 {
			d := contentStr(es[0].Content, "disabled")
			st.hecDisabled = d == "true" || d == "1"
		}
	case isSplunkStatus(err, 404):
		st.hecDisabled = true
	default:
		return st, fmt.Errorf("HEC settings: %w", err)
	}
	return st, nil
}

func (splunkHEC) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	api, err := splunkOrErr(ctx, env)
	if err != nil {
		return Plan{}, err
	}
	st, err := readHEC(ctx, api, p)
	if err != nil {
		return Plan{}, err
	}
	if st.tokenExists && st.tokenIndex != p.Str("index") {
		return Plan{}, fmt.Errorf("%w: HEC token %q exists bound to index %q; refusing to rebind it", ErrScoringUnsafe, p.Str("token_name"), st.tokenIndex)
	}
	if st.tokenExists && st.indexExists && !st.tokenOff && !st.hecDisabled {
		return Plan{Done: true}, nil
	}
	var d []string
	if !st.indexExists {
		d = append(d, "+ index "+p.Str("index"))
	}
	if st.hecDisabled {
		d = append(d, "~ HEC input enabled (was disabled)")
	}
	if !st.tokenExists {
		d = append(d, "+ HEC token "+p.Str("token_name")+" -> index "+p.Str("index"))
	} else if st.tokenOff {
		return Plan{}, fmt.Errorf("HEC token %q exists but is disabled; enabling an existing token is a human decision", p.Str("token_name"))
	}
	return Plan{Diff: strings.Join(d, "\n")}, nil
}

func (splunkHEC) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	api, err := splunkOrErr(ctx, env)
	if err != nil {
		return Rollback{}, err
	}
	st, err := readHEC(ctx, api, p)
	if err != nil {
		return Rollback{}, err
	}
	return Rollback{Kind: kindSplunk, Data: hecUndo{Index: p.Str("index"), IndexCreated: !st.indexExists,
		Token: p.Str("token_name"), TokenCreated: !st.tokenExists, HECEnabledByUs: st.hecDisabled}}, nil
}

func (splunkHEC) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	api, err := splunkOrErr(ctx, env)
	if err != nil {
		return nil, err
	}
	st, err := readHEC(ctx, api, p)
	if err != nil {
		return nil, err
	}
	if !st.indexExists {
		if _, err := api.Post(ctx, "/services/data/indexes", url.Values{"name": {p.Str("index")}, "datatype": {"event"}}); err != nil {
			return nil, fmt.Errorf("create index: %w", err)
		}
	}
	if st.hecDisabled {
		if _, err := api.Post(ctx, hecBase+"/http", url.Values{"disabled": {"0"}}); err != nil {
			return nil, fmt.Errorf("enable HEC: %w", err)
		}
	}
	if !st.tokenExists {
		_, err := api.Post(ctx, hecBase, url.Values{"name": {p.Str("token_name")}, "index": {p.Str("index")},
			"indexes": {p.Str("index")}, "description": {"phylax-managed"}, "disabled": {"0"}})
		if err != nil {
			return nil, fmt.Errorf("create HEC token: %w", err)
		}
	}
	st, err = readHEC(ctx, api, p)
	if err != nil {
		return nil, err
	}
	out := Output{"index": p.Str("index"), "token_name": p.Str("token_name")}
	if st.token != "" {
		out["secret.token"] = st.token
	}
	return out, nil
}

func (splunkHEC) Verify(ctx context.Context, env *Env, p Params) error {
	api, err := splunkOrErr(ctx, env)
	if err != nil {
		return err
	}
	st, err := readHEC(ctx, api, p)
	if err != nil {
		return err
	}
	switch {
	case !st.indexExists:
		return errors.New("index missing after setup")
	case !st.tokenExists || st.tokenOff:
		return errors.New("HEC token missing or disabled after setup")
	case st.tokenIndex != p.Str("index"):
		return fmt.Errorf("HEC token bound to %q, want %q", st.tokenIndex, p.Str("index"))
	case st.hecDisabled:
		return errors.New("HEC input still disabled")
	}
	return nil
}

// ---- splunk.sidecar_off ----

type splunkSidecar struct{}

func (splunkSidecar) Spec() Spec {
	return Spec{Name: "splunk.sidecar_off", Risk: RiskService,
		Doc: "Disable the Splunk PostgreSQL sidecar ([postgres] disabled = true in etc/system/local/server.conf; CVE-2026-20253 workaround). Needs a splunkd restart; scored ports and users are untouched.",
		Params: []ParamSpec{
			{Name: "home", Type: Path, Default: "/opt/splunk"}}}
}

func (splunkSidecar) conf(p Params) string {
	home := p.Str("home")
	sep := "/"
	if strings.Contains(home, `\`) {
		sep = `\`
	}
	return strings.TrimRight(home, `/\`) + sep + strings.Join([]string{"etc", "system", "local", "server.conf"}, sep)
}
func (s splunkSidecar) Locks(Params) []string    { return nil }
func (s splunkSidecar) Touches(p Params) []Touch { return []Touch{pathTouch(s.conf(p), OpModify)} }

func (s splunkSidecar) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	path := env.Resolve(s.conf(p))
	old, _, err := readBounded(path)
	if err != nil && !os.IsNotExist(err) {
		return Plan{}, err
	}
	nw := iniSet(string(old), "postgres", "disabled", "true")
	if nw == string(old) {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: lineDiff(string(old), nw), Notes: []string{"restart splunkd for the change to take effect"}}, nil
}
func (s splunkSidecar) Capture(_ context.Context, env *Env, p Params) (Rollback, error) {
	return snapshotRollback(env.Resolve(s.conf(p)))
}
func (s splunkSidecar) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	path := env.Resolve(s.conf(p))
	old, st, err := readBounded(path)
	perm := os.FileMode(0o644)
	switch {
	case err == nil:
		perm = st.Mode().Perm()
	case os.IsNotExist(err):
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	return nil, atomicfile.WriteFile(path, []byte(iniSet(string(old), "postgres", "disabled", "true")), perm)
}
func (s splunkSidecar) Verify(_ context.Context, env *Env, p Params) error {
	b, _, err := readBounded(env.Resolve(s.conf(p)))
	if err != nil {
		return err
	}
	if v, ok := iniGet(string(b), "postgres", "disabled"); !ok || v != "true" {
		return errors.New("[postgres] disabled is not true after the write")
	}
	return nil
}

// iniGet returns key's value in stanza (first occurrence).
func iniGet(src, stanza, key string) (string, bool) {
	cur := ""
	for _, l := range strings.Split(src, "\n") {
		t := strings.TrimSpace(strings.TrimSuffix(l, "\r"))
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			cur = t[1 : len(t)-1]
			continue
		}
		if cur != stanza || t == "" || t[0] == '#' || t[0] == ';' {
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), key) {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}

// iniSet sets key=value in [stanza] of a Splunk-style .conf text, keeping every
// other line (comments, other stanzas, order) and the file's line endings.
func iniSet(src, stanza, key, value string) string {
	crlf := strings.Contains(src, "\r\n")
	nl := "\n"
	if crlf {
		nl = "\r\n"
	}
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}
	cur, stanzaEnd := "", -1
	found := false
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			if cur == stanza {
				break
			}
			cur = t[1 : len(t)-1]
			if cur == stanza {
				stanzaEnd = i + 1
			}
			continue
		}
		if cur == stanza {
			if t != "" {
				stanzaEnd = i + 1
			}
			if k, _, ok := strings.Cut(t, "="); ok && t[0] != '#' && t[0] != ';' && strings.EqualFold(strings.TrimSpace(k), key) {
				lines[i] = key + " = " + value
				found = true
				break
			}
		}
	}
	if !found {
		line := key + " = " + value
		if stanzaEnd >= 0 {
			lines = append(lines[:stanzaEnd], append([]string{line}, lines[stanzaEnd:]...)...)
		} else {
			if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
				lines = append(lines, "")
			}
			lines = append(lines, "["+stanza+"]", line)
		}
	}
	out := strings.Join(lines, nl)
	if !strings.HasSuffix(out, nl) {
		out += nl
	}
	return out
}
