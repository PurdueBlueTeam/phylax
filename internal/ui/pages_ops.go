package ui

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Operator pages. Reads are GET; every state change is a POST registered with
// Handle, so it passes authentication, the CSRF check and the audit write
// before the handler runs, and the handler adds a named audit entry.

func (s *Server) opsRoutes() {
	h := func(pattern string, f http.HandlerFunc) { s.Handle(pattern, f) }
	h("GET /agents/{host}", s.getAgentDetail)
	h("GET /agents/{host}/safemode", s.getSafeMode)
	h("POST /agents/{host}/safemode", s.postSafeMode)

	h("GET /alerts", s.getAlerts)
	h("GET /alerts/{id}", s.getAlert)
	h("POST /alerts/{id}/trace", s.postTrace)
	h("POST /alerts/{id}/state", s.postAlertState)

	h("GET /chains", s.getChains)
	h("GET /chains/{id}", s.getChain)

	h("GET /plans", s.getPlans)
	h("POST /plans", s.postCreatePlan)
	h("GET /plans/{id}", s.getPlan)
	h("GET /plans/{id}/nodes", s.getPlanNodes)
	h("POST /plans/{id}/dryrun", s.postDryRun)
	h("POST /plans/{id}/approve", s.postApprovePlan)
	h("POST /plans/{id}/nodes/{node}/approve", s.postApproveNode)
	h("POST /plans/{id}/apply", s.postApply)
	h("POST /plans/{id}/rollback", s.postRollback)
	s.reportRoutes()
}

// ops returns the backend, or answers 404 when none is configured.
func (s *Server) ops(w http.ResponseWriter) Ops {
	if s.cfg.Ops == nil {
		http.NotFound(w, nil)
		return nil
	}
	return s.cfg.Ops
}

// fail maps backend errors to responses. Messages from ErrConflict/ErrInvalid
// wrap operator-facing text; anything else is logged and hidden.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, ErrConflict):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, ErrInvalid):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		s.log.Error("ui: operation failed", "path", r.URL.Path, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (s *Server) redirect(w http.ResponseWriter, r *http.Request, to string) {
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func idParam(r *http.Request) (int64, bool) {
	n, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return n, err == nil && n > 0
}

// ---------------------------------------------------------------- agents

type safeModePage struct {
	Host string
	On   bool
}

func (s *Server) getAgentDetail(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	if o == nil {
		return
	}
	d, err := o.AgentDetail(r.Context(), r.PathValue("host"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "agent", pageData{Title: "Agent " + d.Host, Nav: "agents", Data: d})
}

func (s *Server) getSafeMode(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	if o == nil {
		return
	}
	host := r.PathValue("host")
	d, err := o.AgentDetail(r.Context(), host)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "safemode", pageData{Title: "Safe mode " + host, Nav: "agents",
		Data: safeModePage{Host: host, On: !d.SafeMode}})
}

func (s *Server) postSafeMode(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	if o == nil {
		return
	}
	host := r.PathValue("host")
	if r.PostForm.Get("confirm") != host {
		http.Error(w, "type the host name to confirm", http.StatusBadRequest)
		return
	}
	on := r.PostForm.Get("on") == "1"
	if err := o.SetSafeMode(r.Context(), host, on, Principal(r.Context())); err != nil {
		s.fail(w, r, err)
		return
	}
	state := "off"
	if on {
		state = "on"
	}
	_ = s.AuditAction(r, "safe_mode", host+" "+state)
	s.redirect(w, r, "/agents/"+url.PathEscape(host))
}

// ---------------------------------------------------------------- alerts

type alertsPage struct {
	State  string
	Alerts []AlertRow
}

func (s *Server) getAlerts(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	if o == nil {
		return
	}
	state := r.URL.Query().Get("state")
	if state == "" {
		state = "open"
	}
	if state == "all" {
		state = ""
	}
	a, err := o.Alerts(r.Context(), state)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "alerts", pageData{Title: "Alerts", Nav: "alerts", Data: alertsPage{State: state, Alerts: a}})
}

func (s *Server) getAlert(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	id, ok := idParam(r)
	if o == nil || !ok {
		if o != nil {
			http.NotFound(w, r)
		}
		return
	}
	d, err := o.Alert(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "alert", pageData{Title: "Alert " + strconv.FormatInt(id, 10), Nav: "alerts", Data: d})
}

func (s *Server) postTrace(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	id, ok := idParam(r)
	if o == nil || !ok {
		if o != nil {
			http.NotFound(w, r)
		}
		return
	}
	cid, err := o.TraceAlert(r.Context(), id, Principal(r.Context()))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.AuditAction(r, "alert_trace", "alert "+strconv.FormatInt(id, 10)+" chain "+strconv.FormatInt(cid, 10))
	s.redirect(w, r, "/chains/"+strconv.FormatInt(cid, 10))
}

func (s *Server) postAlertState(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	id, ok := idParam(r)
	if o == nil || !ok {
		if o != nil {
			http.NotFound(w, r)
		}
		return
	}
	st := r.PostForm.Get("state")
	if err := o.SetAlertState(r.Context(), id, st, Principal(r.Context())); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.AuditAction(r, "alert_state", "alert "+strconv.FormatInt(id, 10)+" -> "+st)
	s.redirect(w, r, "/alerts/"+strconv.FormatInt(id, 10))
}

// ---------------------------------------------------------------- chains

func (s *Server) getChains(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	if o == nil {
		return
	}
	c, err := o.Chains(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "chains", pageData{Title: "Chains", Nav: "chains", Data: c})
}

func (s *Server) getChain(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	id, ok := idParam(r)
	if o == nil || !ok {
		if o != nil {
			http.NotFound(w, r)
		}
		return
	}
	c, err := o.Chain(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "chain", pageData{Title: "Chain " + strconv.FormatInt(id, 10), Nav: "chains", Data: c})
}

// ---------------------------------------------------------------- plans

type plansPage struct {
	Plans     []PlanBrief
	Templates []TemplateInfo
}

func (s *Server) getPlans(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	if o == nil {
		return
	}
	p, err := o.Plans(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := o.Templates(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "plans", pageData{Title: "Plans", Nav: "plans", Data: plansPage{Plans: p, Templates: t}})
}

func (s *Server) postCreatePlan(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	if o == nil {
		return
	}
	tpl := strings.TrimSpace(r.PostForm.Get("template"))
	id, err := o.CreatePlan(r.Context(), tpl, strings.TrimSpace(r.PostForm.Get("plan_id")), Principal(r.Context()))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.AuditAction(r, "plan_create", id+" from "+tpl)
	s.redirect(w, r, "/plans/"+url.PathEscape(id))
}

func (s *Server) getPlan(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	if o == nil {
		return
	}
	p, err := o.Plan(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "plan", pageData{Title: "Plan " + p.ID, Nav: "plans", Data: p})
}

// getPlanNodes is the htmx polling fragment: live node states.
func (s *Server) getPlanNodes(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	if o == nil {
		return
	}
	p, err := o.Plan(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "plan", pageData{Block: "plan_live", Data: p})
}

// planAction runs one plan state change and redirects back to the plan.
func (s *Server) planAction(name string, f func(o Ops, r *http.Request, id, by string) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		o := s.ops(w)
		if o == nil {
			return
		}
		id := r.PathValue("id")
		if err := f(o, r, id, Principal(r.Context())); err != nil {
			s.fail(w, r, err)
			return
		}
		detail := id
		if n := r.PathValue("node"); n != "" {
			detail += "/" + n
		}
		_ = s.AuditAction(r, name, detail)
		s.redirect(w, r, "/plans/"+url.PathEscape(id))
	}
}

func (s *Server) postDryRun(w http.ResponseWriter, r *http.Request) {
	s.planAction("plan_dryrun", func(o Ops, r *http.Request, id, _ string) error { return o.DryRun(r.Context(), id) })(w, r)
}

func (s *Server) postApprovePlan(w http.ResponseWriter, r *http.Request) {
	s.planAction("plan_approve", func(o Ops, r *http.Request, id, by string) error { return o.ApprovePlan(r.Context(), id, by) })(w, r)
}

func (s *Server) postApproveNode(w http.ResponseWriter, r *http.Request) {
	s.planAction("plan_approve_node", func(o Ops, r *http.Request, id, by string) error {
		note := r.PostForm.Get("note")
		if len(note) > 500 {
			note = note[:500]
		}
		return o.ApproveNode(r.Context(), id, r.PathValue("node"), by, note)
	})(w, r)
}

func (s *Server) postApply(w http.ResponseWriter, r *http.Request) {
	s.planAction("plan_apply", func(o Ops, r *http.Request, id, by string) error { return o.Apply(r.Context(), id, by) })(w, r)
}

func (s *Server) postRollback(w http.ResponseWriter, r *http.Request) {
	s.planAction("plan_rollback", func(o Ops, r *http.Request, id, by string) error { return o.Rollback(r.Context(), id, by) })(w, r)
}
