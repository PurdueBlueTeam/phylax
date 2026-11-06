package ui

import (
	"net/http"
	"strconv"
)

// Proposal routes: open suggestions from modules, each one click from a plan.
// They are registered with Handle, so a POST passes authentication, CSRF and
// the audit write before the handler runs.
func (s *Server) proposalRoutes() {
	s.Handle("GET /proposals", http.HandlerFunc(s.getProposals))
	s.Handle("POST /proposals/{id}/accept", http.HandlerFunc(s.postAcceptProposal))
	s.Handle("POST /proposals/{id}/dismiss", http.HandlerFunc(s.postDismissProposal))
}

func (s *Server) getProposals(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	if o == nil {
		return
	}
	p, err := o.Proposals(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "proposals", pageData{Title: "Proposals", Nav: "proposals", Data: p})
}

func (s *Server) postAcceptProposal(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	id, ok := idParam(r)
	if o == nil || !ok {
		if o != nil {
			http.NotFound(w, r)
		}
		return
	}
	planID, err := o.AcceptProposal(r.Context(), id, Principal(r.Context()))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.AuditAction(r, "proposal_accept", strconv.FormatInt(id, 10)+" plan "+planID)
	s.redirect(w, r, "/proposals")
}

func (s *Server) postDismissProposal(w http.ResponseWriter, r *http.Request) {
	o := s.ops(w)
	id, ok := idParam(r)
	if o == nil || !ok {
		if o != nil {
			http.NotFound(w, r)
		}
		return
	}
	if err := o.DismissProposal(r.Context(), id, Principal(r.Context())); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.AuditAction(r, "proposal_dismiss", strconv.FormatInt(id, 10))
	s.redirect(w, r, "/proposals")
}
