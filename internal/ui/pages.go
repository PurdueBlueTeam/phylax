package ui

import (
	"errors"
	"io/fs"
	"net/http"
	"strings"
	"time"
)

func (s *Server) routes() {
	sub, _ := fs.Sub(staticFS, "static")
	files := http.StripPrefix("/static/", http.FileServerFS(sub))
	s.mux.HandleFunc("GET /static/{file}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		files.ServeHTTP(w, r)
	})
	s.mux.HandleFunc("GET /login", s.getLogin)
	s.mux.HandleFunc("POST /login", s.postLogin)

	s.Handle("GET /{$}", http.HandlerFunc(s.getDashboard))
	s.Handle("GET /agents", http.HandlerFunc(s.getAgents))
	s.Handle("GET /agents/table", http.HandlerFunc(s.getAgentsTable))
	s.Handle("GET /account", http.HandlerFunc(s.getAccount))
	s.Handle("POST /account/password", http.HandlerFunc(s.postPassword))
	s.Handle("POST /logout", http.HandlerFunc(s.postLogout))
	// Everything else: authenticate first so unauthenticated probing learns nothing.
	s.Handle("/", http.NotFoundHandler())
}

// ---------------------------------------------------------------- login

func (s *Server) getLogin(w http.ResponseWriter, r *http.Request) {
	id := s.cookieID(r)
	sess, ok := s.sessions.get(id)
	if ok && sess.authed() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !ok {
		var ns *session
		id, ns = s.sessions.create("")
		sess = *ns
		s.setCookie(w, id, 0)
	}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, r, http.StatusOK, "login", pageData{Title: "Sign in", CSRF: sess.csrf})
}

func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id := s.cookieID(r)
	sess, ok := s.sessions.get(id)
	if !ok || !s.checkCSRF(r, sess.csrf) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("username"))
	pw := r.PostForm.Get("password")
	ipKey, userKey := "ip:"+remoteIP(r), "user:"+strings.ToLower(name)
	if d, blocked := s.limiter.blocked(ipKey, userKey); blocked {
		secs := int(d/time.Second) + 1
		w.Header().Set("Retry-After", itoa(secs))
		_ = s.audit(r, name, "login_rate_limited", "")
		s.render(w, r, http.StatusTooManyRequests, "login", pageData{Title: "Sign in", CSRF: sess.csrf, Error: "Too many attempts. Try again later."})
		return
	}
	good := false
	acct, err := s.accounts.Get(r.Context(), name)
	switch {
	case err == nil && len(pw) <= maxPassword:
		good = VerifyPassword(pw, acct.Hash)
	case errors.Is(err, ErrNoAccount) && len(pw) <= maxPassword:
		VerifyPassword(pw, s.dummy) // equalise timing
	case err != nil && !errors.Is(err, ErrNoAccount):
		s.log.Error("ui: account lookup", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !good {
		s.limiter.fail(ipKey, userKey)
		_ = s.audit(r, name, "login_failed", "")
		s.render(w, r, http.StatusUnauthorized, "login", pageData{Title: "Sign in", CSRF: sess.csrf, Error: "Invalid username or password."})
		return
	}
	s.limiter.success(ipKey, userKey)
	s.sessions.destroy(id) // fixation defence: new id on privilege change
	nid, _ := s.sessions.create(acct.Name)
	s.setCookie(w, nid, 0)
	_ = s.audit(r, acct.Name, "login", "")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) postLogout(w http.ResponseWriter, r *http.Request) {
	s.sessions.destroy(sessionID(r.Context()))
	s.setCookie(w, "", -1)
	_ = s.AuditAction(r, "logout", "")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---------------------------------------------------------------- pages

func (s *Server) getDashboard(w http.ResponseWriter, r *http.Request) {
	d := placeholderDashboard()
	if s.cfg.Dashboard != nil {
		var err error
		if d, err = s.cfg.Dashboard.Dashboard(r.Context()); err != nil {
			s.log.Error("ui: dashboard", "err", err)
			http.Error(w, "dashboard unavailable", http.StatusInternalServerError)
			return
		}
	}
	s.render(w, r, http.StatusOK, "dashboard", pageData{Title: "Dashboard", Nav: "dashboard", Data: d})
}

func placeholderDashboard() Dashboard {
	return Dashboard{
		Overview:   Pane{"Overview", []string{"Hosts: -", "Services: -", "Scorer: unknown", "Safe mode: off"}},
		Alerts:     Pane{"Alerts and incidents", []string{"No data yet"}},
		Plans:      Pane{"Plans", []string{"No plans running"}},
		Approvals:  Pane{"Approvals", []string{"Nothing waiting"}},
		RoundClock: Pane{"Round clock and SLA", []string{"Next round: -", "Streaks: -"}},
		Health:     Pane{"Platform health", []string{"Controller: ok", "Agents: -"}},
	}
}

func (s *Server) agents(r *http.Request) ([]AgentInfo, error) {
	if s.cfg.Agents == nil {
		return nil, nil
	}
	return s.cfg.Agents.ListAgents(r.Context())
}

func (s *Server) getAgents(w http.ResponseWriter, r *http.Request) {
	a, err := s.agents(r)
	if err != nil {
		s.log.Error("ui: agents", "err", err)
		http.Error(w, "agents unavailable", http.StatusInternalServerError)
		return
	}
	s.render(w, r, http.StatusOK, "agents", pageData{Title: "Agents", Nav: "agents", Data: a})
}

func (s *Server) getAgentsTable(w http.ResponseWriter, r *http.Request) {
	a, err := s.agents(r)
	if err != nil {
		http.Error(w, "agents unavailable", http.StatusInternalServerError)
		return
	}
	s.render(w, r, http.StatusOK, "agents", pageData{Block: "agents_table", Data: a})
}

func (s *Server) getAccount(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "account", pageData{Title: "Account", Nav: "account"})
}

func (s *Server) postPassword(w http.ResponseWriter, r *http.Request) {
	user := Principal(r.Context())
	cur, next := r.PostForm.Get("current"), r.PostForm.Get("new")
	fail := func(code int, msg string) {
		s.render(w, r, code, "account", pageData{Title: "Account", Nav: "account", Error: msg})
	}
	acct, err := s.accounts.Get(r.Context(), user)
	if err != nil || len(cur) > maxPassword || !VerifyPassword(cur, acct.Hash) {
		_ = s.AuditAction(r, "password_change_failed", "")
		fail(http.StatusUnauthorized, "Current password is wrong.")
		return
	}
	if len(next) < minPassword || len(next) > maxPassword {
		fail(http.StatusBadRequest, "New password must be 12 to 256 bytes.")
		return
	}
	h, err := HashPassword(next, s.cfg.Argon2)
	if err == nil {
		acct.Hash = h
		err = s.accounts.Put(r.Context(), acct)
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.sessions.destroyUser(user, sessionID(r.Context()))
	_ = s.AuditAction(r, "password_changed", "")
	s.render(w, r, http.StatusOK, "account", pageData{Title: "Account", Nav: "account", Notice: "Password changed; other sessions signed out."})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
