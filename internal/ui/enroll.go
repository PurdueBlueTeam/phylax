package ui

import "net/http"

// The enrollment page: mint a host's one-time line and push the agent. Token
// minting is reachable only from these POST routes, so it needs a session, the
// CSRF token and a successful audit write (T28: token minting only from the UI).

type enrollPage struct {
	Hosts []EnrollRow
	Line  string // the one-liner, after minting (shown once)
	Host  string // the host the line belongs to
}

func (s *Server) enrollRoutes() {
	s.Handle("GET /enroll", http.HandlerFunc(s.getEnroll))
	s.Handle("POST /enroll/{host}/line", http.HandlerFunc(s.postEnrollLine))
	s.Handle("POST /enroll/{host}/push", http.HandlerFunc(s.postEnrollPush))
	s.Handle("POST /enroll/reenroll-all", http.HandlerFunc(s.postReenrollAll))
}

// enrollPage builds the page data from the backend's host list.
func (s *Server) enrollPage(r *http.Request, o Ops) (enrollPage, error) {
	rows, err := o.EnrollHosts(r.Context())
	if err != nil {
		return enrollPage{}, err
	}
	return enrollPage{Hosts: rows}, nil
}

func (s *Server) getEnroll(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	if o == nil {
		return
	}
	ep, err := s.enrollPage(r, o)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "enroll", pageData{Title: "Enroll", Nav: "enroll", Data: ep})
}

func (s *Server) postEnrollLine(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	if o == nil {
		return
	}
	host := r.PathValue("host")
	osName := r.PostForm.Get("os")
	if osName == "" {
		osName = "linux"
	}
	line, err := o.EnrollLine(r.Context(), host, osName, Principal(r.Context()))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.AuditAction(r, "enroll.line", host); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	ep, err := s.enrollPage(r, o)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ep.Line, ep.Host = line, host
	s.render(w, r, http.StatusOK, "enroll", pageData{Title: "Enroll", Nav: "enroll", Data: ep})
}

func (s *Server) postEnrollPush(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	if o == nil {
		return
	}
	host := r.PathValue("host")
	pushErr := o.EnrollPush(r.Context(), host, Principal(r.Context()))
	detail := host
	if pushErr != nil {
		detail += " failed"
	}
	if err := s.AuditAction(r, "enroll.push", detail); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	ep, err := s.enrollPage(r, o)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ep.Host = host
	pd := pageData{Title: "Enroll", Nav: "enroll", Data: ep}
	if pushErr != nil {
		// The class and the next step; the template shows them.
		pd.Error = pushErr.Error()
	}
	s.render(w, r, http.StatusOK, "enroll", pd)
}

func (s *Server) postReenrollAll(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	if o == nil {
		return
	}
	if r.PostForm.Get("confirm") != "REENROLL" {
		http.Error(w, "type REENROLL to confirm", http.StatusBadRequest)
		return
	}
	if err := o.ReenrollAll(r.Context(), Principal(r.Context())); err != nil {
		_ = s.AuditAction(r, "enroll.reenroll_all", "failed")
		ep, lerr := s.enrollPage(r, o)
		if lerr != nil {
			s.fail(w, r, lerr)
			return
		}
		s.render(w, r, http.StatusOK, "enroll", pageData{Title: "Enroll", Nav: "enroll", Data: ep, Error: err.Error()})
		return
	}
	_ = s.AuditAction(r, "enroll.reenroll_all", "")
	s.redirect(w, r, "/enroll")
}
