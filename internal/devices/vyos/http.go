package vyos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxHTTPResponse = 16 << 20

// HTTPClient is the VyOS HTTP API client. Every call is a POST with form
// fields data (JSON) and key. The API commits on every /configure request, so
// this client is used for reads only; changes go over SSH under the dead-man.
type HTTPClient struct {
	BaseURL string
	Key     string
	HTTP    *http.Client
	Timeout time.Duration // when ctx has no deadline (default 30s)
}

type apiReply struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   *string         `json:"error"`
}

// Do posts to endpoint (for example "/show") and returns the data field.
func (c *HTTPClient) Do(ctx context.Context, endpoint string, data any) (json.RawMessage, error) {
	if _, ok := ctx.Deadline(); !ok {
		t := c.Timeout
		if t == 0 {
			t = 30 * time.Second
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t)
		defer cancel()
	}
	b, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	form := url.Values{"data": {string(b)}, "key": {c.Key}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.BaseURL, "/")+endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponse+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxHTTPResponse {
		return nil, errors.New("vyos: response too large")
	}
	var r apiReply
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("vyos: HTTP %d: unreadable reply: %w", resp.StatusCode, err)
	}
	if !r.Success {
		msg := "unknown error"
		if r.Error != nil {
			msg = *r.Error
		}
		return nil, fmt.Errorf("vyos: HTTP %d: %s", resp.StatusCode, msg)
	}
	return r.Data, nil
}

// Show runs an op-mode show command (returns text).
func (c *HTTPClient) Show(ctx context.Context, path ...string) (string, error) {
	d, err := c.Do(ctx, "/show", map[string]any{"op": "show", "path": path})
	if err != nil {
		return "", err
	}
	var s string
	if err := json.Unmarshal(d, &s); err != nil {
		return "", err
	}
	return s, nil
}

// Retrieve reads config: op is showConfig, returnValue, returnValues or exists.
func (c *HTTPClient) Retrieve(ctx context.Context, op string, path ...string) (json.RawMessage, error) {
	switch op {
	case "showConfig", "returnValue", "returnValues", "exists":
	default:
		return nil, fmt.Errorf("vyos: retrieve op %q is not a read", op)
	}
	return c.Do(ctx, "/retrieve", map[string]any{"op": op, "path": path})
}
