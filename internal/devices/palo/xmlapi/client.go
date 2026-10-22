package xmlapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// maxResponse bounds any single API response (a full running config is a few MB).
const maxResponse = 64 << 20

// Client talks to one firewall's /api/ endpoint. All calls are POST form
// requests with the key in X-PAN-KEY.
type Client struct {
	BaseURL string // https://host
	Key     string
	HTTP    *http.Client
	// Timeout bounds a call when ctx has no deadline (default 60s).
	Timeout time.Duration
}

// APIError is a status="error" response.
type APIError struct {
	Code string
	Msg  string
}

func (e *APIError) Error() string { return "panos: api error (code " + e.Code + "): " + e.Msg }

var (
	// ErrLockHeld: the config lock is held by another admin.
	ErrLockHeld = errors.New("panos: config lock held")
	// ErrNotLocked: remove on a lock that is not held.
	ErrNotLocked = errors.New("panos: no lock held")
)

// Response is a parsed <response>.
type Response struct {
	Status string
	Code   string
	Msg    string
	Result *Node // may be nil
	Raw    []byte
}

// Do posts form to /api/ and parses the reply. A status="error" reply is an *APIError.
func (c *Client) Do(ctx context.Context, form url.Values) (*Response, error) {
	raw, err := c.post(ctx, form)
	if err != nil {
		return nil, err
	}
	return parseResponse(raw)
}

func (c *Client) post(ctx context.Context, form url.Values) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		t := c.Timeout
		if t == 0 {
			t = 60 * time.Second
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.BaseURL, "/")+"/api/", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.Key != "" {
		req.Header.Set("X-PAN-KEY", c.Key)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxResponse {
		return nil, errors.New("panos: response too large")
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return nil, &APIError{Code: strconv.Itoa(resp.StatusCode), Msg: "access denied"}
	}
	return b, nil
}

func parseResponse(raw []byte) (*Response, error) {
	n, err := ParseNode(raw)
	if err != nil {
		return nil, fmt.Errorf("panos: bad response: %w", err)
	}
	if n.Name != "response" {
		return nil, fmt.Errorf("panos: unexpected root %q", n.Name)
	}
	r := &Response{Status: n.Attr("status"), Code: n.Attr("code"), Result: n.Child("result"), Raw: raw}
	if m := n.Child("msg"); m != nil {
		var parts []string
		if m.Text != "" {
			parts = append(parts, m.Text)
		}
		for _, l := range m.Children {
			parts = append(parts, l.Text)
		}
		r.Msg = strings.Join(parts, "; ")
	}
	if r.Result != nil && r.Msg == "" {
		if m := r.Result.Child("msg"); m != nil {
			var parts []string
			parts = append(parts, m.Text)
			for _, l := range m.Children {
				parts = append(parts, l.Text)
			}
			r.Msg = strings.Join(parts, "; ")
		}
	}
	if r.Status == "error" {
		// Error text may live in <result><msg> too.
		return r, &APIError{Code: r.Code, Msg: r.Msg}
	}
	return r, nil
}

// Keygen exchanges a username and password for an API key. The key is not
// sent in a header for this call.
func (c *Client) Keygen(ctx context.Context, user, password string) (string, error) {
	cc := *c
	cc.Key = ""
	r, err := cc.Do(ctx, url.Values{"type": {"keygen"}, "user": {user}, "password": {password}})
	if err != nil {
		return "", err
	}
	if r.Result == nil || r.Result.ChildText("key") == "" {
		return "", errors.New("panos: keygen returned no key")
	}
	return r.Result.ChildText("key"), nil
}

func (c *Client) config(ctx context.Context, action, xpath, element string, extra url.Values) (*Response, error) {
	f := url.Values{"type": {"config"}, "action": {action}}
	if xpath != "" {
		f.Set("xpath", xpath)
	}
	if element != "" {
		f.Set("element", element)
	}
	for k, v := range extra {
		f[k] = v
	}
	return c.Do(ctx, f)
}

// ConfigGet reads the candidate config at xpath; nil when absent.
func (c *Client) ConfigGet(ctx context.Context, xpath string) (*Node, error) {
	r, err := c.config(ctx, "get", xpath, "", nil)
	return firstResultChild(r, err)
}

// ConfigShow reads the running config at xpath; nil when absent.
func (c *Client) ConfigShow(ctx context.Context, xpath string) (*Node, error) {
	r, err := c.config(ctx, "show", xpath, "", nil)
	return firstResultChild(r, err)
}

func firstResultChild(r *Response, err error) (*Node, error) {
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) && (ae.Code == "7" || strings.Contains(strings.ToLower(ae.Msg), "object not present")) {
			return nil, nil
		}
		return nil, err
	}
	if r.Result == nil || len(r.Result.Children) == 0 {
		return nil, nil
	}
	return r.Result.Children[0], nil
}

// ConfigSet merges element under xpath (the parent).
func (c *Client) ConfigSet(ctx context.Context, xpath, element string) error {
	_, err := c.config(ctx, "set", xpath, element, nil)
	return err
}

// ConfigEdit replaces the node at xpath with element.
func (c *Client) ConfigEdit(ctx context.Context, xpath, element string) error {
	_, err := c.config(ctx, "edit", xpath, element, nil)
	return err
}

// ConfigDelete deletes the node at xpath.
func (c *Client) ConfigDelete(ctx context.Context, xpath string) error {
	_, err := c.config(ctx, "delete", xpath, "", nil)
	return err
}

// MultiOp is one step of a multi-config request.
type MultiOp struct {
	Action  string // set | edit | delete
	XPath   string
	Element string // XML, empty for delete
}

// MultiConfig sends several changes in one request. strict makes the batch
// all-or-nothing on the device.
func (c *Client) MultiConfig(ctx context.Context, ops []MultiOp, strict bool) error {
	var b strings.Builder
	b.WriteString("<multi-config>")
	for _, o := range ops {
		switch o.Action {
		case "set", "edit", "delete":
		default:
			return fmt.Errorf("panos: bad multi-config action %q", o.Action)
		}
		b.WriteString("<" + o.Action + ` xpath="`)
		b.WriteString(xmlEscape(o.XPath))
		b.WriteString(`">`)
		b.WriteString(o.Element)
		b.WriteString("</" + o.Action + ">")
	}
	b.WriteString("</multi-config>")
	extra := url.Values{}
	if strict {
		extra.Set("strict-transactional", "yes")
	}
	_, err := c.config(ctx, "multi-config", "", b.String(), extra)
	return err
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// Op runs an operational command (cmd is XML).
func (c *Client) Op(ctx context.Context, cmd string) (*Response, error) {
	return c.Do(ctx, url.Values{"type": {"op"}, "cmd": {cmd}})
}

// ConfigLockAdd takes the config lock. A lock held by another admin is ErrLockHeld.
func (c *Client) ConfigLockAdd(ctx context.Context, comment string) error {
	_, err := c.Op(ctx, "<request><config-lock><add><comment>"+xmlEscape(comment)+"</comment></add></config-lock></request>")
	return mapLockErr(err)
}

// ConfigLockRemove releases our config lock. Not held is ErrNotLocked.
func (c *Client) ConfigLockRemove(ctx context.Context) error {
	_, err := c.Op(ctx, "<request><config-lock><remove></remove></config-lock></request>")
	var ae *APIError
	if errors.As(err, &ae) && strings.Contains(strings.ToLower(ae.Msg), "not currently locked") {
		return ErrNotLocked
	}
	return err
}

func mapLockErr(err error) error {
	var ae *APIError
	if errors.As(err, &ae) && strings.Contains(strings.ToLower(ae.Msg), "lock") {
		return fmt.Errorf("%w: %s", ErrLockHeld, ae.Msg)
	}
	return err
}

// Lock is a held config or commit lock.
type Lock struct{ Admin, Type, Comment string }

// ShowConfigLocks lists config locks.
func (c *Client) ShowConfigLocks(ctx context.Context, vsys string) ([]Lock, error) {
	r, err := c.Op(ctx, "<show><config-locks><vsys>"+xmlEscape(vsys)+"</vsys></config-locks></show>")
	if err != nil {
		return nil, err
	}
	var out []Lock
	if r.Result != nil {
		if cl := r.Result.Child("config-locks"); cl != nil {
			for _, e := range cl.Children {
				if e.Name == "entry" {
					out = append(out, Lock{Admin: e.Attr("name"), Type: e.ChildText("type"), Comment: e.ChildText("comment")})
				}
			}
		}
	}
	return out, nil
}

// Change is one staged-but-uncommitted edit.
type Change struct{ XPath, Admin, Cmd string }

// ListChanges reads <show><config><list><changes>.
func (c *Client) ListChanges(ctx context.Context) ([]Change, error) {
	r, err := c.Op(ctx, "<show><config><list><changes></changes></list></config></show>")
	if err != nil {
		return nil, err
	}
	var out []Change
	if r.Result != nil {
		if j := r.Result.Child("journal"); j != nil {
			for _, e := range j.Children {
				out = append(out, Change{XPath: e.ChildText("xpath"), Admin: e.ChildText("admin"), Cmd: e.ChildText("command")})
			}
		}
	}
	return out, nil
}

// Job is a PAN-OS job.
type Job struct {
	ID       string
	Type     string
	Status   string // ACT | PEND | FIN
	Result   string // OK | FAIL | PEND
	Progress string
	Details  []string
}

// Done reports Status == FIN.
func (j Job) Done() bool { return j.Status == "FIN" }

func parseJob(n *Node) Job {
	j := Job{ID: n.ChildText("id"), Type: n.ChildText("type"), Status: n.ChildText("status"), Result: n.ChildText("result"), Progress: n.ChildText("progress")}
	if d := n.Child("details"); d != nil {
		for _, l := range d.Children {
			j.Details = append(j.Details, l.Text)
		}
	}
	return j
}

// ShowJob reads one job.
func (c *Client) ShowJob(ctx context.Context, id string) (Job, error) {
	r, err := c.Op(ctx, "<show><jobs><id>"+xmlEscape(id)+"</id></jobs></show>")
	if err != nil {
		return Job{}, err
	}
	if r.Result == nil || r.Result.Child("job") == nil {
		return Job{}, fmt.Errorf("panos: job %s not found", id)
	}
	return parseJob(r.Result.Child("job")), nil
}

// ShowJobs lists all jobs.
func (c *Client) ShowJobs(ctx context.Context) ([]Job, error) {
	r, err := c.Op(ctx, "<show><jobs><all/></jobs></show>")
	if err != nil {
		return nil, err
	}
	var out []Job
	if r.Result != nil {
		for _, n := range r.Result.Children {
			if n.Name == "job" {
				out = append(out, parseJob(n))
			}
		}
	}
	return out, nil
}

// WaitJob polls until the job finishes or ctx ends. timeout (if >0) bounds the wait.
func (c *Client) WaitJob(ctx context.Context, id string, poll, timeout time.Duration) (Job, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if poll <= 0 {
		poll = 2 * time.Second
	}
	for {
		j, err := c.ShowJob(ctx, id)
		if err != nil {
			return j, err
		}
		if j.Done() {
			return j, nil
		}
		select {
		case <-ctx.Done():
			return j, fmt.Errorf("panos: job %s did not finish: %w", id, ctx.Err())
		case <-time.After(poll):
		}
	}
}

// ValidateFull starts a full validation and returns its job id.
func (c *Client) ValidateFull(ctx context.Context) (string, error) {
	r, err := c.Op(ctx, "<validate><full></full></validate>")
	if err != nil {
		return "", err
	}
	return jobID(r)
}

func jobID(r *Response) (string, error) {
	if r.Result != nil && r.Result.ChildText("job") != "" {
		return r.Result.ChildText("job"), nil
	}
	return "", errors.New("panos: reply carries no job id")
}

// CommitPartialAdmin commits only the named admin's changes. When there is
// nothing to commit it returns noChanges and no job. A plain commit is never
// offered: it would publish other admins' pending edits.
func (c *Client) CommitPartialAdmin(ctx context.Context, admin, description string) (job string, noChanges bool, err error) {
	var b strings.Builder
	b.WriteString("<commit>")
	if description != "" {
		b.WriteString("<description>" + xmlEscape(description) + "</description>")
	}
	b.WriteString("<partial><admin><member>" + xmlEscape(admin) + "</member></admin></partial></commit>")
	r, err := c.Do(ctx, url.Values{"type": {"commit"}, "action": {"partial"}, "cmd": {b.String()}})
	if err != nil {
		return "", false, err
	}
	if r.Code == "19" && strings.Contains(strings.ToLower(r.Msg), "no changes") {
		return "", true, nil
	}
	id, err := jobID(r)
	return id, false, err
}

// SaveConfig saves the candidate to a named file on the device.
func (c *Client) SaveConfig(ctx context.Context, name string) error {
	_, err := c.Op(ctx, "<save><config><to>"+xmlEscape(name)+"</to></config></save>")
	return err
}

// LoadConfig loads a named saved config into the candidate (replacing it).
func (c *Client) LoadConfig(ctx context.Context, name string) error {
	_, err := c.Op(ctx, "<load><config><from>"+xmlEscape(name)+"</from></config></load>")
	return err
}

// ExportConfig fetches the running configuration file.
func (c *Client) ExportConfig(ctx context.Context) ([]byte, error) {
	raw, err := c.post(ctx, url.Values{"type": {"export"}, "category": {"configuration"}})
	if err != nil {
		return nil, err
	}
	n, err := ParseNode(raw)
	if err != nil {
		return nil, err
	}
	if n.Name == "response" {
		return nil, fmt.Errorf("panos: export failed: %s", n.String())
	}
	return raw, nil
}

// SystemInfo is <show><system><info>.
func (c *Client) SystemInfo(ctx context.Context) (map[string]string, error) {
	r, err := c.Op(ctx, "<show><system><info></info></system></show>")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	if r.Result != nil {
		if s := r.Result.Child("system"); s != nil {
			for _, ch := range s.Children {
				out[ch.Name] = ch.Text
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("panos: empty system info")
	}
	return out, nil
}

// Admin is a live session or configured admin.
type Admin struct{ Name, From, Type string }

// ShowAdmins lists logged-in admins (all=false) or configured admins (all=true).
func (c *Client) ShowAdmins(ctx context.Context, all bool) ([]Admin, error) {
	cmd := "<show><admins></admins></show>"
	if all {
		cmd = "<show><admins><all/></admins></show>"
	}
	r, err := c.Op(ctx, cmd)
	if err != nil {
		return nil, err
	}
	var out []Admin
	if r.Result != nil {
		if a := r.Result.Child("admins"); a != nil {
			for _, e := range a.Children {
				name := e.ChildText("admin")
				if name == "" {
					name = e.ChildText("name")
				}
				out = append(out, Admin{Name: name, From: e.ChildText("from"), Type: e.ChildText("type")})
			}
		}
	}
	return out, nil
}

// PolicyMatch asks the running policy what it would do with a flow, without sending traffic.
type PolicyMatch struct {
	From, To, Source, Destination string
	Port                          int
	Protocol                      int
}

// TestSecurityPolicyMatch returns the matching rule name and its action.
func (c *Client) TestSecurityPolicyMatch(ctx context.Context, m PolicyMatch) (rule, action string, err error) {
	cmd := "<test><security-policy-match><from>" + xmlEscape(m.From) + "</from><to>" + xmlEscape(m.To) +
		"</to><source>" + xmlEscape(m.Source) + "</source><destination>" + xmlEscape(m.Destination) + "</destination>"
	if m.Port != 0 {
		cmd += "<destination-port>" + strconv.Itoa(m.Port) + "</destination-port>"
	}
	if m.Protocol != 0 {
		cmd += "<protocol>" + strconv.Itoa(m.Protocol) + "</protocol>"
	}
	cmd += "</security-policy-match></test>"
	r, err := c.Op(ctx, cmd)
	if err != nil {
		return "", "", err
	}
	if r.Result != nil {
		if rules := r.Result.Child("rules"); rules != nil && len(rules.Children) > 0 {
			e := rules.Children[0]
			return e.Attr("name"), e.ChildText("action"), nil
		}
	}
	return "", "", errors.New("panos: no policy match")
}

// LogEntry is one log record (child tag -> text).
type LogEntry map[string]string

// LogQuery runs the two-step log protocol: start a job, poll, read the entries.
// logType is config, system, traffic, ...; dir is "backward" for newest first.
func (c *Client) LogQuery(ctx context.Context, logType, query string, nlogs, skip int, poll, timeout time.Duration) ([]LogEntry, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	f := url.Values{"type": {"log"}, "log-type": {logType}, "dir": {"backward"}}
	if query != "" {
		f.Set("query", query)
	}
	if nlogs > 0 {
		f.Set("nlogs", strconv.Itoa(nlogs))
	}
	if skip > 0 {
		f.Set("skip", strconv.Itoa(skip))
	}
	r, err := c.Do(ctx, f)
	if err != nil {
		return nil, err
	}
	id, err := jobID(r)
	if err != nil {
		return nil, err
	}
	if poll <= 0 {
		poll = time.Second
	}
	for {
		r, err := c.Do(ctx, url.Values{"type": {"log"}, "action": {"get"}, "job-id": {id}})
		if err != nil {
			return nil, err
		}
		if r.Result != nil {
			status := ""
			if j := r.Result.Child("job"); j != nil {
				status = j.ChildText("status")
			}
			if status == "FIN" {
				var out []LogEntry
				if lg := r.Result.Child("log"); lg != nil {
					if logs := lg.Child("logs"); logs != nil {
						for _, e := range logs.Children {
							le := LogEntry{}
							for _, ch := range e.Children {
								le[ch.Name] = ch.Text
							}
							out = append(out, le)
						}
					}
				}
				return out, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("panos: log job %s did not finish: %w", id, ctx.Err())
		case <-time.After(poll):
		}
	}
}
