package checks

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// A small stand-in for uarand: the scorer sends a random real-looking browser
// string, so the User-Agent is not a stable fingerprint.
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.101 Safari/537.36",
	"Opera/9.64 (X11; Linux i686; U; en) Presto/2.1.1",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0",
}

const maxBody = 8 << 20

func probeWeb(ctx context.Context, p *probe) error {
	scheme := "http"
	if p.spec.Type == HTTPS || p.spec.Encrypted {
		scheme = "https"
	}
	path := p.item.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	var re *regexp.Regexp
	if p.item.Regex != "" {
		var err error
		if re, err = regexp.Compile(p.item.Regex); err != nil {
			return fail(ClassConfig, "bad regex: %v", err)
		}
	}
	// A new Transport per request, keep-alives off, TLS verification off: the
	// scorer's client. Go sends no SNI for an IP and no ALPN is offered
	// because we set our own TLS config and DialContext.
	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return p.dial(ctx, network, addr)
		},
		TLSHandshakeTimeout: p.opts.timeout(),
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+p.spec.addr()+path, nil)
	if err != nil {
		return fail(ClassConfig, "bad request: %v", err)
	}
	req.Header.Set("User-Agent", userAgents[p.rng.IntN(len(userAgents))])
	resp, err := cl.Do(req)
	if err != nil {
		return classify(err, "web request errored out")
	}
	defer resp.Body.Close()
	p.step("response")
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return classify(err, "web request errored out")
	}
	p.step("body")
	if p.item.Status != 0 && resp.StatusCode != p.item.Status {
		return failDebug(ClassContent, "", "status returned by webserver was incorrect: status was %d wanted %d for url %s", resp.StatusCode, p.item.Status, path)
	}
	if re != nil && !re.Match(body) {
		return fail(ClassContent, "didn't find regex on page")
	}
	if p.strict() {
		if p.item.Status == 0 && (resp.StatusCode < 200 || resp.StatusCode > 299) {
			p.strictIssue("status %d with no expected status configured", resp.StatusCode)
		}
		if p.item.SHA256 != "" {
			sum := sha256.Sum256(body)
			if !strings.EqualFold(hex.EncodeToString(sum[:]), p.item.SHA256) {
				p.strictIssue("body hash differs from the expected hash")
			}
		}
		if p.item.Status == 0 && re == nil && p.item.SHA256 == "" && len(body) == 0 {
			p.strictIssue("empty body")
		}
	}
	return nil
}

var _ = time.Second
