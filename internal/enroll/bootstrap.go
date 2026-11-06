package enroll

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/svcinstall"
)

const (
	releaseLinux   = "phylax-linux-amd64"
	releaseWindows = "phylax-windows-amd64.exe"
)

// releaseFile is one cached release hash, refreshed when size or mtime moves.
type releaseFile struct {
	size int64
	mod  time.Time
	sha  string
}

// release returns the path and sha256 of the agent binary for osName.
func (e *Enroller) release(osName string) (string, string, error) {
	name := ""
	switch osName {
	case OSLinux:
		name = releaseLinux
	case OSWindows:
		name = releaseWindows
	default:
		return "", "", fmt.Errorf("enroll: unknown OS %q", osName)
	}
	if e.opt.ReleaseDir == "" {
		return "", "", fmt.Errorf("enroll: release dir is not configured (missing %s)", name)
	}
	path := filepath.Join(e.opt.ReleaseDir, name)
	fi, err := os.Stat(path)
	if err != nil {
		return "", "", fmt.Errorf("enroll: release file %s: %w", path, err)
	}
	if fi.Size() > 64<<20 {
		return "", "", fmt.Errorf("enroll: release file %s is larger than 64 MiB", path)
	}
	e.relMu.Lock()
	defer e.relMu.Unlock()
	if r := e.releases[osName]; r != nil && r.size == fi.Size() && r.mod.Equal(fi.ModTime()) {
		return path, r.sha, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", "", fmt.Errorf("enroll: release file %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", "", fmt.Errorf("enroll: release file %s: %w", path, err)
	}
	sha := hex.EncodeToString(h.Sum(nil))
	e.releases[osName] = &releaseFile{size: fi.Size(), mod: fi.ModTime(), sha: sha}
	return path, sha, nil
}

// Bootstrap returns the handler for connections that negotiated no phylax
// protocol. One connection serves one request.
func (e *Enroller) Bootstrap() link.Handler {
	return func(ctx context.Context, c *link.Conn) {
		e.serveBootstrap(ctx, c, http.HandlerFunc(e.bootstrap))
	}
}

// serveBootstrap runs one HTTP request on c with h. It is separate from
// Bootstrap so tests can count the requests that reach the HTTP layer.
func (e *Enroller) serveBootstrap(ctx context.Context, c *link.Conn, h http.Handler) {
	ln := &onceListener{conn: c, done: make(chan struct{})}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    8 << 10,
		IdleTimeout:       time.Second,
	}
	_ = srv.Serve(ln) // the connection is per-request; every return is final
}

func (e *Enroller) bootstrap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Connection", "close")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ip := remoteIP(r.RemoteAddr)
	if e.limited(ip) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/l/"):
		e.serveScript(w, r, ip, strings.TrimPrefix(p, "/l/"), OSLinux)
	case strings.HasPrefix(p, "/w/"):
		e.serveScript(w, r, ip, strings.TrimPrefix(p, "/w/"), OSWindows)
	case strings.HasPrefix(p, "/b/"):
		e.serveBundleFile(w, r, ip, strings.TrimPrefix(p, "/b/"))
	default:
		notFound(w)
	}
}

func (e *Enroller) serveScript(w http.ResponseWriter, r *http.Request, ip, token, osName string) {
	if _, ok := e.tokenHost(w, ip, token); !ok {
		return
	}
	ctl, ok := e.controllerAddr(r)
	if !ok {
		notFound(w)
		return
	}
	_, sha, err := e.release(osName)
	if err != nil {
		notFound(w)
		return
	}
	dir := svcinstall.DeriveNames([]byte(token)).Dir
	var body string
	if osName == OSLinux {
		body, err = e.linuxScript(ctl, token, sha, dir)
	} else {
		body, err = e.windowsScript(ctl, token, sha, dir)
	}
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = io.WriteString(w, body)
}

func (e *Enroller) serveBundleFile(w http.ResponseWriter, r *http.Request, ip, rest string) {
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		notFound(w)
		return
	}
	token, what := parts[0], parts[1]
	host, ok := e.tokenHost(w, ip, token)
	if !ok {
		return
	}
	switch what {
	case "linux", "windows":
		osName := OSLinux
		if what == OSWindows {
			osName = OSWindows
		}
		path, _, err := e.release(osName)
		if err != nil {
			notFound(w)
			return
		}
		f, err := os.Open(path)
		if err != nil {
			notFound(w)
			return
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			notFound(w)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
		_, _ = io.Copy(w, f)
	case "boot":
		ctl, ok := e.controllerAddr(r)
		if !ok {
			notFound(w)
			return
		}
		b, err := e.bundleFor(host, BundleOptions{Controllers: []string{ctl}}, token)
		if err != nil {
			notFound(w)
			return
		}
		body, err := json.Marshal(b)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	default:
		notFound(w)
	}
}

// controllerAddr is the address written into scripts and the boot bundle:
// the configured advertised address, or the request Host when none is set. A
// value that is not a hostname, IPv4 or bracketed IPv6 plus a numeric port is
// refused before it can reach a template.
func (e *Enroller) controllerAddr(r *http.Request) (string, bool) {
	ctl := e.opt.Advertise
	if ctl == "" {
		ctl = r.Host
	}
	return ctl, validControllerAddr(ctl)
}

func validControllerAddr(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '.' || c == ':' || c == '[' || c == ']' || c == '-'
		if !ok {
			return false
		}
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false
	}
	if strings.Contains(host, ":") {
		return net.ParseIP(host) != nil // bracketed IPv6, brackets stripped above
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.To4() != nil
	}
	return validHostname(host)
}

func validHostname(host string) bool {
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func (e *Enroller) tokenHost(w http.ResponseWriter, ip, token string) (string, bool) {
	host, err := e.tokens.Peek(token)
	if err != nil {
		e.noteFailure(ip)
		notFound(w)
		return "", false
	}
	return host, true
}

func notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, "not found\n")
}

func remoteIP(remote string) string {
	if h, _, err := net.SplitHostPort(remote); err == nil {
		return h
	}
	return remote
}

// limited reports whether ip already had 20 failed token lookups in the last
// minute.
//
// shortcut: in-memory, resets on restart, fine for an event.
func (e *Enroller) limited(ip string) bool {
	now := e.opt.Now()
	e.failMu.Lock()
	defer e.failMu.Unlock()
	f := e.fails[ip]
	if f.since.IsZero() || now.Sub(f.since) >= time.Minute {
		delete(e.fails, ip)
		return false
	}
	return f.n >= 20
}

func (e *Enroller) noteFailure(ip string) {
	now := e.opt.Now()
	e.failMu.Lock()
	defer e.failMu.Unlock()
	f := e.fails[ip]
	if f.since.IsZero() || now.Sub(f.since) >= time.Minute {
		f = failEntry{since: now}
	}
	f.n++
	e.fails[ip] = f
}

func renderScript(name, text string, data map[string]string) (string, error) {
	t, err := template.New(name).Option("missingkey=error").Parse(text)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// onceListener returns the wrapped connection once; the next Accept waits for
// the connection to close.
type onceListener struct {
	conn  net.Conn
	done  chan struct{}
	once  sync.Once
	mu    sync.Mutex
	taken bool
}

func (l *onceListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.taken {
		l.taken = true
		c := l.conn
		l.mu.Unlock()
		// Go's header limit allows 4 KiB of slack; cap the whole request read
		// so a header block over 8 KiB is refused, not parsed.
		return &notifyConn{Conn: &readCapConn{Conn: c, left: 8 << 10}, close: l.Close}, nil
	}
	l.mu.Unlock()
	<-l.done
	return nil, net.ErrClosed
}

func (l *onceListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *onceListener) Addr() net.Addr { return l.conn.LocalAddr() }

// readCapConn stops the connection being read after left bytes; the bootstrap
// server serves one body-less request per connection.
type readCapConn struct {
	net.Conn
	left int
}

func (c *readCapConn) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, io.EOF
	}
	if len(p) > c.left {
		p = p[:c.left]
	}
	n, err := c.Conn.Read(p)
	c.left -= n
	return n, err
}

type notifyConn struct {
	net.Conn
	close func() error
}

func (c *notifyConn) Close() error {
	err := c.Conn.Close()
	_ = c.close()
	return err
}
