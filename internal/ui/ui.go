// Package ui is the operator web UI: a server-rendered, htmx-enhanced HTTP
// handler for the controller's localhost listener. Every route except the
// login page and static assets requires a session; every state-changing
// request requires a CSRF synchronizer token. There is no "loopback means
// trusted" anywhere in this package.
package ui

import (
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// AuditEntry records one operator action.
type AuditEntry struct {
	Time   time.Time
	Actor  string // operator name, or the attempted name for failed logins
	Action string // e.g. "login", "login_failed", "logout", "request"
	Remote string
	Detail string
}

// AuditLog is implemented by the controller on top of the store.
type AuditLog interface {
	Record(ctx context.Context, e AuditEntry) error
}

// AgentInfo is one row of the Agents page. All strings may be attacker
// controlled; templates escape them.
type AgentInfo struct {
	Name       string
	OS         string
	Version    string
	LinkState  string // "up", "degraded", "down"
	LagMillis  int64
	SpoolDepth int
	SafeMode   bool
	LastSeen   time.Time
}

// AgentLister supplies the Agents page.
type AgentLister interface {
	ListAgents(ctx context.Context) ([]AgentInfo, error)
}

// Pane is the placeholder content of one dashboard pane.
type Pane struct {
	Title string
	Lines []string
}

// Dashboard holds the data for the one-screen dashboard.
type Dashboard struct {
	Overview, Alerts, Plans, Approvals, RoundClock, Health Pane
}

// DashboardSource supplies dashboard data; nil means placeholders.
type DashboardSource interface {
	Dashboard(ctx context.Context) (Dashboard, error)
}

// Config configures a Server. Zero values are safe defaults.
type Config struct {
	Accounts  AccountStore // default: in-memory
	Agents    AgentLister  // default: none
	Audit     AuditLog     // default: discard
	Dashboard DashboardSource
	Logger    *slog.Logger

	Addr             string   // default 127.0.0.1:8443
	AllowNonLoopback bool     // permit a non-loopback Addr (e.g. never, by default)
	AllowedHosts     []string // Host header names accepted; default 127.0.0.1, localhost, ::1
	SecureCookies    bool     // set when served over TLS

	IdleTimeout     time.Duration // default 30m
	AbsoluteTimeout time.Duration // default 8h
	LoginMaxFails   int           // default 5 per key per LoginWindow
	LoginWindow     time.Duration // default 15m
	LoginLockout    time.Duration // default 15m

	Argon2 Argon2Params // default DefaultArgon2
	Now    func() time.Time
}

// Server is the operator UI.
type Server struct {
	cfg      Config
	log      *slog.Logger
	accounts AccountStore
	sessions *sessionStore
	limiter  *loginLimiter
	pages    map[string]*template.Template
	mux      *http.ServeMux
	hosts    map[string]bool
	dummy    string // hash verified for unknown users to equalise timing
	handler  http.Handler
}

type ctxKey int

const (
	keyUser ctxKey = iota
	keyCSRF
)

// Principal returns the authenticated operator name for a request that
// passed through a Handle-registered route.
func Principal(ctx context.Context) string { s, _ := ctx.Value(keyUser).(string); return s }

// CSRFToken returns the session's CSRF token, for embedding in forms.
func CSRFToken(ctx context.Context) string { s, _ := ctx.Value(keyCSRF).(string); return s }

// New builds a Server.
func New(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8443"
	}
	if !cfg.AllowNonLoopback {
		if err := checkLoopback(cfg.Addr); err != nil {
			return nil, err
		}
	}
	if cfg.Accounts == nil {
		cfg.Accounts = NewMemAccounts()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&cfg.IdleTimeout, 30*time.Minute)
	def(&cfg.AbsoluteTimeout, 8*time.Hour)
	def(&cfg.LoginWindow, 15*time.Minute)
	def(&cfg.LoginLockout, 15*time.Minute)
	if cfg.LoginMaxFails <= 0 {
		cfg.LoginMaxFails = 5
	}
	if cfg.Argon2 == (Argon2Params{}) {
		cfg.Argon2 = DefaultArgon2
	}
	hosts := cfg.AllowedHosts
	if len(hosts) == 0 {
		hosts = []string{"127.0.0.1", "localhost", "::1"}
	}
	s := &Server{
		cfg: cfg, log: cfg.Logger, accounts: cfg.Accounts,
		sessions: newSessionStore(cfg.IdleTimeout, cfg.AbsoluteTimeout, cfg.Now),
		limiter:  newLoginLimiter(cfg.LoginMaxFails, cfg.LoginWindow, cfg.LoginLockout, cfg.Now),
		mux:      http.NewServeMux(),
		hosts:    map[string]bool{},
	}
	for _, h := range hosts {
		s.hosts[strings.ToLower(h)] = true
	}
	var err error
	if s.dummy, err = HashPassword("dummy-password-for-timing", cfg.Argon2); err != nil {
		return nil, err
	}
	if err := s.loadTemplates(); err != nil {
		return nil, err
	}
	s.routes()
	s.handler = s.outer(s.mux)
	return s, nil
}

func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("ui: bad listen address %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("ui: refusing non-loopback listen address %q", addr)
	}
	return nil
}

// Handler returns the full handler (host check, headers, auth, CSRF).
func (s *Server) Handler() http.Handler { return s.handler }

// Addr is the configured listen address.
func (s *Server) Addr() string { return s.cfg.Addr }

// Serve serves on ln until ctx is cancelled. Use net.Listen(s.Addr()).
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sc)
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// EnsureAdmin creates the first operator "admin" with a random password if no
// accounts exist. It returns the password exactly once (created=true); the
// caller prints it. It is never stored or logged in clear.
func (s *Server) EnsureAdmin(ctx context.Context) (password string, created bool, err error) {
	n, err := s.accounts.Count(ctx)
	if err != nil || n > 0 {
		return "", false, err
	}
	pw := randToken(18)
	h, err := HashPassword(pw, s.cfg.Argon2)
	if err != nil {
		return "", false, err
	}
	if err := s.accounts.Put(ctx, Account{Name: "admin", Hash: h, Created: s.cfg.Now()}); err != nil {
		return "", false, err
	}
	return pw, true, nil
}

// Handle registers an authenticated, CSRF-protected, audited route. The
// controller uses it to add pages and actions. Call before serving.
func (s *Server) Handle(pattern string, h http.Handler) {
	s.mux.Handle(pattern, s.protected(h))
}

// AuditAction lets handlers record a named operator action.
func (s *Server) AuditAction(r *http.Request, action, detail string) error {
	return s.audit(r, Principal(r.Context()), action, detail)
}

func (s *Server) audit(r *http.Request, actor, action, detail string) error {
	if s.cfg.Audit == nil {
		return nil
	}
	return s.cfg.Audit.Record(r.Context(), AuditEntry{Time: s.cfg.Now(), Actor: actor, Action: action, Remote: remoteIP(r), Detail: detail})
}

func remoteIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// ---------------------------------------------------------------- middleware

const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

func setSecurityHeaders(h http.Header) {
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
}

const maxBody = 64 << 10

// outer applies headers, the Host check (DNS-rebinding defence) and body cap.
func (s *Server) outer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w.Header())
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(strings.ToLower(host), "[]")
		if !s.hosts[host] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		next.ServeHTTP(w, r)
	})
}

const cookieBase = "phylax_session"

func (s *Server) cookieName() string {
	if s.cfg.SecureCookies {
		return "__Host-" + cookieBase
	}
	return cookieBase
}

func (s *Server) setCookie(w http.ResponseWriter, id string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: id, Path: "/", HttpOnly: true,
		Secure: s.cfg.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}

func (s *Server) cookieID(r *http.Request) string {
	c, err := r.Cookie(s.cookieName())
	if err != nil {
		return ""
	}
	return c.Value
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// checkCSRF validates origin and synchronizer token against the session.
func (s *Server) checkCSRF(r *http.Request, want string) bool {
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			return false
		}
	}
	got := r.Header.Get("X-CSRF-Token")
	if got == "" {
		if err := r.ParseForm(); err != nil {
			return false
		}
		got = r.PostForm.Get("csrf_token")
	}
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// protected wraps h with authentication, CSRF and audit of mutations.
func (s *Server) protected(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := s.cookieID(r)
		sess, ok := s.sessions.get(id)
		if !ok || !sess.authed() {
			if r.Method == http.MethodGet && r.Header.Get("HX-Request") == "" {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			w.Header().Set("HX-Redirect", "/login")
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if !safeMethod(r.Method) {
			if !s.checkCSRF(r, sess.csrf) {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
			if err := s.audit(r, sess.user, "request", r.Method+" "+r.URL.Path); err != nil {
				s.log.Error("ui: audit failed; refusing request", "err", err)
				http.Error(w, "audit unavailable", http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		ctx := context.WithValue(r.Context(), keyUser, sess.user)
		ctx = context.WithValue(ctx, keyCSRF, sess.csrf)
		ctx = context.WithValue(ctx, ctxKey(100), id) // session id for logout
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func sessionID(ctx context.Context) string { s, _ := ctx.Value(ctxKey(100)).(string); return s }

// ---------------------------------------------------------------- templates

func (s *Server) loadTemplates() error {
	s.pages = map[string]*template.Template{}
	entries, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return err
	}
	funcs := template.FuncMap{
		"ago": func(t time.Time) string {
			if t.IsZero() {
				return "never"
			}
			return s.cfg.Now().Sub(t).Round(time.Second).String() + " ago"
		},
	}
	for _, e := range entries {
		name := strings.TrimSuffix(strings.TrimPrefix(e, "templates/"), ".html")
		if name == "base" || strings.HasPrefix(name, "_") {
			continue
		}
		t, err := template.New("base.html").Funcs(funcs).ParseFS(templateFS, "templates/base.html", e)
		if err != nil {
			return fmt.Errorf("ui: template %s: %w", name, err)
		}
		s.pages[name] = t
	}
	return nil
}

type pageData struct {
	Title string
	Nav   string
	User  string
	CSRF  string
	// HXHeaders is JSON for hx-headers so htmx sends the CSRF token.
	HXHeaders string
	Error     string
	Notice    string
	Block     string // template to execute instead of the full page
	Data      any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, pd pageData) {
	t := s.pages[name]
	if t == nil {
		http.Error(w, "no such template", http.StatusInternalServerError)
		return
	}
	pd.User = Principal(r.Context())
	if pd.CSRF == "" {
		pd.CSRF = CSRFToken(r.Context())
	}
	pd.HXHeaders = `{"X-CSRF-Token":"` + pd.CSRF + `"}` // token is base64url: no escaping needed
	var buf strings.Builder
	exec := "base.html"
	if pd.Block != "" {
		exec = pd.Block
	}
	if err := t.ExecuteTemplate(&buf, exec, pd); err != nil {
		s.log.Error("ui: render", "page", name, "err", err)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(buf.String()))
}
