package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// SplunkAPI is the splunkd management API (port 8089) as the splunk.* actions
// use it. Calls return the JSON body (output_mode=json is added).
type SplunkAPI interface {
	Get(ctx context.Context, path string, q url.Values) ([]byte, error)
	Post(ctx context.Context, path string, form url.Values) ([]byte, error)
	Delete(ctx context.Context, path string) ([]byte, error)
	// As returns a client that authenticates with other credentials (used to
	// prove a password change worked on a fresh login).
	As(user, password string) SplunkAPI
}

// SplunkDirectory resolves the management client of a Splunk host. The
// controller builds it from the vault; the actions never see the admin
// password.
type SplunkDirectory interface {
	Client(ctx context.Context, host string) (SplunkAPI, error)
}

// SplunkError is a non-2xx answer from splunkd.
type SplunkError struct {
	Status int
	Body   string
}

func (e *SplunkError) Error() string {
	b := e.Body
	if len(b) > 300 {
		b = b[:300]
	}
	return fmt.Sprintf("splunkd: HTTP %d: %s", e.Status, strings.TrimSpace(b))
}

func isSplunkStatus(err error, code int) bool {
	var se *SplunkError
	return errors.As(err, &se) && se.Status == code
}

// HTTPSplunk is the real SplunkAPI: basic auth over HTTPS to splunkd. The
// caller supplies the http.Client (pinned or lab-trusting TLS).
type HTTPSplunk struct {
	Base     string // https://host:8089
	User     string
	Password string
	HTTP     *http.Client
}

const maxSplunkBody = 4 << 20

func (h *HTTPSplunk) do(ctx context.Context, method, path string, q url.Values, form url.Values) ([]byte, error) {
	if !strings.HasPrefix(path, "/services/") && !strings.HasPrefix(path, "/servicesNS/") || strings.Contains(path, "..") {
		return nil, fmt.Errorf("splunkd: refusing path %q", path)
	}
	u, err := url.Parse(strings.TrimSuffix(h.Base, "/") + path)
	if err != nil {
		return nil, err
	}
	qq := url.Values{"output_mode": {"json"}}
	for k, v := range q {
		qq[k] = v
	}
	u.RawQuery = qq.Encode()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.SetBasicAuth(h.User, h.Password)
	c := h.HTTP
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxSplunkBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return b, &SplunkError{Status: resp.StatusCode, Body: string(b)}
	}
	return b, nil
}

func (h *HTTPSplunk) Get(ctx context.Context, path string, q url.Values) ([]byte, error) {
	return h.do(ctx, http.MethodGet, path, q, nil)
}
func (h *HTTPSplunk) Post(ctx context.Context, path string, form url.Values) ([]byte, error) {
	if form == nil {
		form = url.Values{}
	}
	return h.do(ctx, http.MethodPost, path, nil, form)
}
func (h *HTTPSplunk) Delete(ctx context.Context, path string) ([]byte, error) {
	return h.do(ctx, http.MethodDelete, path, nil, nil)
}
func (h *HTTPSplunk) As(user, password string) SplunkAPI {
	c := *h
	c.User, c.Password = user, password
	return &c
}

// splunkEntries decodes the standard {"entry":[{"name":..,"content":{..}}]} answer.
type splunkEntry struct {
	Name    string         `json:"name"`
	Content map[string]any `json:"content"`
}

func splunkEntries(b []byte) ([]splunkEntry, error) {
	var r struct {
		Entry []splunkEntry `json:"entry"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("splunkd: bad JSON: %w", err)
	}
	return r.Entry, nil
}

func contentStr(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case float64:
		return fmt.Sprint(v)
	case bool:
		return fmt.Sprint(v)
	}
	return ""
}

func splunkOrErr(ctx context.Context, env *Env) (SplunkAPI, error) {
	if env.Win.Splunk == nil {
		return nil, Unsupported("splunk management API")
	}
	return env.Win.Splunk.Client(ctx, env.Host)
}
