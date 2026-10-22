package decoys

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/PurdueBlueTeam/phylax/pools"
)

const (
	maxHTTPRequests = 20
	maxHTTPHeader   = 16 << 10
	maxHTTPBody     = 4 << 10
)

const loginPage = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>%s</title>
<style>body{font-family:sans-serif;background:#eef1f5}form{width:300px;margin:12%% auto;padding:24px;background:#fff;border:1px solid #ccd}input{display:block;width:100%%;margin:8px 0;padding:6px;box-sizing:border-box}.e{color:#b00}</style></head>
<body><form method="post" action="/login"><h2>%s</h2><p>%s</p>%s
<input name="username" placeholder="Username" autocomplete="off"><input name="password" type="password" placeholder="Password">
<button type="submit">Sign in</button></form></body></html>`

// serveHTTP answers the admin-panel lookalike (http_admin) or a WinRM
// lookalike (winrm: 401 challenge on /wsman). Nothing the client sends is
// reflected in a response or acted on; credentials are only recorded.
func (m *Module) serveHTTP(ctx context.Context, s *sess, c net.Conn) {
	panels := pools.Lines("http_panels.txt")
	f := strings.Split(panels[m.bannerIdx%len(panels)], "|")
	title, sub, server := f[0], f[1], f[2]
	winrm := s.l.Kind == KindWinRM
	if winrm {
		server = "Microsoft-HTTPAPI/2.0"
	}
	r := bufio.NewReaderSize(io.LimitReader(c, 1<<20), 4096)
	for n := 0; n < maxHTTPRequests; n++ {
		s.idle()
		req, err := readRequest(r)
		if err != nil {
			return
		}
		var body []byte
		if req.Body != nil {
			body, _ = io.ReadAll(io.LimitReader(req.Body, maxHTTPBody))
		}
		status, ctype, page, hdr := 200, "text/html; charset=utf-8", "", http.Header{}
		bad := ""
		switch {
		case winrm:
			status, page, ctype = 401, "", "text/plain"
			hdr.Add("WWW-Authenticate", "Negotiate")
			hdr.Add("WWW-Authenticate", `Basic realm="WSMAN"`)
			if !m.httpAuth(s, req) {
				s.hit(StageRequest, SevInfo, map[string]any{"method": req.Method, "path": trunc(req.URL.Path, 128)})
			}
			s.pause()
		case req.Method == http.MethodPost && req.URL.Path == "/login":
			vals, _ := url.ParseQuery(string(body))
			user, pw := firstOf(vals, "username", "user", "login", "email"), firstOf(vals, "password", "pass", "pwd")
			s.credential(user, pw, "http_form")
			s.pause()
			bad = `<p class="e">Invalid username or password.</p>`
			fallthrough
		case req.URL.Path == "/" || req.URL.Path == "/login" || req.URL.Path == "/admin":
			m.httpAuth(s, req)
			if req.Method != http.MethodPost {
				s.hit(StageRequest, SevInfo, map[string]any{"method": req.Method, "path": trunc(req.URL.Path, 128)})
			}
			page = fmt.Sprintf(loginPage, title, title, sub, bad)
		default:
			m.httpAuth(s, req)
			s.hit(StageRequest, SevInfo, map[string]any{"method": req.Method, "path": trunc(req.URL.Path, 128)})
			status, page = 404, "<html><body><h1>404 Not Found</h1></body></html>"
		}
		keep := n+1 < maxHTTPRequests && !req.Close
		if !writeResponse(c, status, ctype, server, page, hdr, keep) || !keep {
			return
		}
	}
}

func readRequest(r *bufio.Reader) (*http.Request, error) {
	// A request head is bounded by the reader's 4 KiB buffer plus the header cap below.
	req, err := http.ReadRequest(r)
	if err != nil {
		return nil, err
	}
	if len(req.URL.String()) > maxHTTPHeader {
		return nil, fmt.Errorf("http: url too long")
	}
	return req, nil
}

func firstOf(v url.Values, names ...string) string {
	for _, n := range names {
		if x := v.Get(n); x != "" {
			return x
		}
	}
	return ""
}

// httpAuth records an Authorization: Basic credential, if present.
func (m *Module) httpAuth(s *sess, req *http.Request) bool {
	h := req.Header.Get("Authorization")
	if h == "" {
		return false
	}
	scheme, rest, _ := strings.Cut(h, " ")
	if strings.EqualFold(scheme, "basic") {
		if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(trunc(rest, 512))); err == nil {
			u, p, _ := strings.Cut(string(b), ":")
			s.credential(u, p, "http_basic")
			return true
		}
	}
	s.credential("", "", trunc(strings.ToLower(scheme), 16)) // NTLM/Negotiate: the attempt itself is the signal
	return true
}

func writeResponse(c net.Conn, status int, ctype, server, page string, hdr http.Header, keep bool) bool {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\nServer: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n", status, http.StatusText(status), server, ctype, len(page))
	for k, vs := range hdr {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	if keep {
		b.WriteString("Connection: keep-alive\r\n")
	} else {
		b.WriteString("Connection: close\r\n")
	}
	b.WriteString("\r\n" + page)
	_, err := io.WriteString(c, b.String())
	return err == nil
}
