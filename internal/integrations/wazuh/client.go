package wazuh

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

const maxBody = 8 << 20

// Config configures the client. APIURL is the manager API (https://host:55000).
// IndexerURL (optional) is the Wazuh indexer used for alert queries.
type Config struct {
	APIURL      string
	User        string
	Password    string
	IndexerURL  string
	IdxUser     string
	IdxPassword string
	CAPEM       []byte // trust this CA; empty uses system roots
	InsecureTLS bool   // self-signed lab certs; off by default
	Timeout     time.Duration
	MinVersion  string
	HTTPClient  *http.Client // tests
}

// Client talks to Wazuh. Safe for concurrent use.
type Client struct {
	cfg  Config
	hc   *http.Client
	mu   sync.Mutex
	tok  string
	tokT time.Time
}

// New builds a client.
func New(cfg Config) (*Client, error) {
	if cfg.APIURL == "" {
		return nil, errors.New("wazuh: APIURL required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	hc := cfg.HTTPClient
	if hc == nil {
		tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureTLS}
		if len(cfg.CAPEM) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(cfg.CAPEM) {
				return nil, errors.New("wazuh: bad CA PEM")
			}
			tc.RootCAs = pool
		}
		hc = &http.Client{Timeout: cfg.Timeout, Transport: &http.Transport{TLSClientConfig: tc, MaxIdleConns: 2}}
	}
	return &Client{cfg: cfg, hc: hc}, nil
}

// Agent is one enrolled agent.
type Agent struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	IP            string   `json:"ip"`
	Version       string   `json:"version"`
	Status        string   `json:"status"` // active, disconnected, never_connected, pending
	LastKeepAlive string   `json:"lastKeepAlive"`
	Groups        []string `json:"group"`
}

// Health is the result of a health check.
type Health struct {
	ManagerVersion Version
	Agents         []Agent
	Active         int
	Disconnected   []string
	NeverConnected []string
}

func (c *Client) do(ctx context.Context, method, base, path string, auth func(*http.Request), body []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	auth(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(b) > maxBody {
		return nil, resp.StatusCode, errors.New("wazuh: response too large")
	}
	return b, resp.StatusCode, nil
}

func (c *Client) token(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.tok != "" && time.Since(c.tokT) < 10*time.Minute {
		return c.tok, nil
	}
	b, code, err := c.do(ctx, http.MethodPost, c.cfg.APIURL, "/security/user/authenticate?raw=true",
		func(r *http.Request) { r.SetBasicAuth(c.cfg.User, c.cfg.Password) }, nil)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("wazuh: authenticate: HTTP %d", code)
	}
	c.tok = strings.TrimSpace(string(b))
	c.tokT = time.Now()
	return c.tok, nil
}

// apiGet does an authenticated GET, re-authenticating once on 401.
func (c *Client) apiGet(ctx context.Context, path string, out any) error {
	for attempt := 0; attempt < 2; attempt++ {
		tok, err := c.token(ctx, attempt > 0)
		if err != nil {
			return err
		}
		b, code, err := c.do(ctx, http.MethodGet, c.cfg.APIURL, path,
			func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }, nil)
		if err != nil {
			return err
		}
		if code == http.StatusUnauthorized && attempt == 0 {
			continue
		}
		if code != http.StatusOK {
			return fmt.Errorf("wazuh: GET %s: HTTP %d", path, code)
		}
		return json.Unmarshal(b, out)
	}
	return errors.New("wazuh: unauthorized")
}

// ManagerVersion returns the manager's version string via /manager/info.
func (c *Client) ManagerVersion(ctx context.Context) (string, error) {
	var r struct {
		Data struct {
			Items []struct {
				Version string `json:"version"`
			} `json:"affected_items"`
		} `json:"data"`
	}
	if err := c.apiGet(ctx, "/manager/info", &r); err != nil {
		return "", err
	}
	if len(r.Data.Items) == 0 {
		return "", errors.New("wazuh: no manager info")
	}
	return r.Data.Items[0].Version, nil
}

// Agents lists agents (paged, bounded at 5000).
func (c *Client) Agents(ctx context.Context) ([]Agent, error) {
	var all []Agent
	const page = 500
	for off := 0; off < 5000; off += page {
		var r struct {
			Data struct {
				Items []Agent `json:"affected_items"`
				Total int     `json:"total_affected_items"`
			} `json:"data"`
		}
		q := url.Values{"limit": {fmt.Sprint(page)}, "offset": {fmt.Sprint(off)},
			"select": {"id,name,ip,version,status,lastKeepAlive,group"}}
		if err := c.apiGet(ctx, "/agents?"+q.Encode(), &r); err != nil {
			return nil, err
		}
		all = append(all, r.Data.Items...)
		if len(all) >= r.Data.Total || len(r.Data.Items) == 0 {
			break
		}
	}
	return all, nil
}

// Health checks the manager version pin and the agent fleet. Version-pin
// violations are returned as ErrVersionPin together with the partial result.
func (c *Client) Health(ctx context.Context) (*Health, error) {
	vs, err := c.ManagerVersion(ctx)
	if err != nil {
		return nil, err
	}
	h := &Health{}
	mv, perr := CheckManager(vs, c.cfg.MinVersion)
	h.ManagerVersion = mv
	if perr != nil {
		return h, perr
	}
	ags, err := c.Agents(ctx)
	if err != nil {
		return h, err
	}
	h.Agents = ags
	for _, a := range ags {
		switch a.Status {
		case "active":
			h.Active++
		case "never_connected":
			h.NeverConnected = append(h.NeverConnected, a.Name)
		default:
			if a.ID != "000" {
				h.Disconnected = append(h.Disconnected, a.Name)
			}
		}
	}
	return h, CheckAgents(mv, ags)
}

// Alert is one Wazuh alert document.
type Alert struct {
	ID        string
	Time      time.Time
	RuleID    string
	Level     int
	RuleDesc  string
	AgentName string
	AgentID   string
	AgentIP   string
	Location  string
	FullLog   string
}

// Alerts queries the indexer for alerts at or after since with rule level >=
// minLevel, oldest first, at most limit (cap 1000).
func (c *Client) Alerts(ctx context.Context, since time.Time, minLevel, limit int) ([]Alert, error) {
	if c.cfg.IndexerURL == "" {
		return nil, errors.New("wazuh: IndexerURL not configured")
	}
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	q := map[string]any{
		"size": limit,
		"sort": []any{map[string]any{"timestamp": "asc"}},
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format("2006-01-02T15:04:05.000Z")}}},
			map[string]any{"range": map[string]any{"rule.level": map[string]any{"gte": minLevel}}},
		}}},
	}
	body, _ := json.Marshal(q)
	b, code, err := c.do(ctx, http.MethodPost, c.cfg.IndexerURL, "/wazuh-alerts-*/_search",
		func(r *http.Request) { r.SetBasicAuth(c.cfg.IdxUser, c.cfg.IdxPassword) }, body)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("wazuh: indexer search: HTTP %d", code)
	}
	var r struct {
		Hits struct {
			Hits []struct {
				ID  string `json:"_id"`
				Src struct {
					Timestamp string `json:"timestamp"`
					Rule      struct {
						ID          string `json:"id"`
						Level       int    `json:"level"`
						Description string `json:"description"`
					} `json:"rule"`
					Agent struct {
						ID   string `json:"id"`
						Name string `json:"name"`
						IP   string `json:"ip"`
					} `json:"agent"`
					Location string `json:"location"`
					FullLog  string `json:"full_log"`
				} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	var out []Alert
	for _, h := range r.Hits.Hits {
		t, err := time.Parse("2006-01-02T15:04:05.000-0700", h.Src.Timestamp)
		if err != nil {
			if t, err = time.Parse(time.RFC3339Nano, h.Src.Timestamp); err != nil {
				continue
			}
		}
		out = append(out, Alert{ID: h.ID, Time: t.UTC(), RuleID: h.Src.Rule.ID, Level: h.Src.Rule.Level,
			RuleDesc: h.Src.Rule.Description, AgentName: h.Src.Agent.Name, AgentID: h.Src.Agent.ID,
			AgentIP: h.Src.Agent.IP, Location: h.Src.Location, FullLog: truncate(h.Src.FullLog, 2048)})
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// EventKind is the kind of imported alerts.
const EventKind = "wazuh.alert"

// ToEvent converts an alert to a low-priority context event. Seq and hashes are
// assigned by the spool.
func (a Alert) ToEvent() event.Event {
	return event.Event{
		Agent: "wazuh", Time: a.Time, Kind: EventKind, Priority: event.PriorityNormal,
		Fields: map[string]any{
			"alert_id": a.ID, "rule_id": a.RuleID, "level": a.Level, "description": a.RuleDesc,
			"wazuh_agent": a.AgentName, "wazuh_agent_id": a.AgentID, "agent_ip": a.AgentIP,
			"location": a.Location, "full_log": a.FullLog,
		},
	}
}
