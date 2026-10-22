package checks

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Splunk on 8089: Basic-auth GET /services/server/info (the management port
// and credentials work) or, with a Query, a REST login then a search export
// whose results are compared with Output. The scorer's real logic is not
// public; this follows the design table.
func probeSplunk(ctx context.Context, p *probe) error {
	if err := p.needCred(); err != nil {
		return err
	}
	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DialContext:       func(ctx context.Context, n, a string) (net.Conn, error) { return p.dial(ctx, n, a) },
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr}
	base := "https://" + p.spec.addr()
	get := func(req *http.Request) (*http.Response, []byte, error) {
		resp, err := cl.Do(req)
		if err != nil {
			return nil, nil, classify(err, "splunk request errored out")
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		return resp, b, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/services/server/info?output_mode=json", nil)
	req.SetBasicAuth(p.cred.User, p.cred.Pass.Reveal())
	resp, body, err := get(req)
	if err != nil {
		return err
	}
	p.step("info")
	switch {
	case resp.StatusCode == 401:
		return fail(ClassAuth, "splunk login failed for %s", p.cred.User)
	case resp.StatusCode != 200:
		return failDebug(ClassProtocol, string(body), "splunk server/info returned %d", resp.StatusCode)
	}
	if p.item.Query == "" {
		return nil
	}
	form := url.Values{"username": {p.cred.User}, "password": {p.cred.Pass.Reveal()}, "output_mode": {"json"}}
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, base+"/services/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, body, err = get(req)
	if err != nil {
		return err
	}
	var lr struct {
		SessionKey string `json:"sessionKey"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &lr) != nil || lr.SessionKey == "" {
		return fail(ClassAuth, "splunk login failed for %s", p.cred.User)
	}
	p.step("login")
	q := p.item.Query
	if !strings.HasPrefix(strings.TrimSpace(q), "|") && !strings.HasPrefix(strings.TrimSpace(q), "search") {
		q = "search " + q
	}
	sf := url.Values{"search": {q}, "output_mode": {"json"}}
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, base+"/services/search/jobs/export", strings.NewReader(sf.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Splunk "+lr.SessionKey)
	resp, body, err = get(req)
	if err != nil {
		return err
	}
	p.step("search")
	if resp.StatusCode != 200 {
		return failDebug(ClassProtocol, string(body), "splunk search returned %d", resp.StatusCode)
	}
	if p.item.Output != "" {
		ok := strings.Contains(string(body), p.item.Output)
		if p.item.UseRegex {
			re, err := regexp.Compile(p.item.Output)
			if err != nil {
				return fail(ClassConfig, "bad regex: %v", err)
			}
			ok = re.Match(body)
		}
		if !ok {
			return failDebug(ClassContent, string(body), "no matching output found for search")
		}
	} else if p.strict() && !strings.Contains(string(body), `"result"`) {
		p.strictIssue("search returned no results")
	}
	return nil
}
