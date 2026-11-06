package ui

import (
	"net/http"
)

// lockedStopped is what a locked controller does not do. It is the same list
// the controller puts in the controller.locked event.
var lockedStopped = []string{"auto plans", "facts", "deadman_confirm", "safe_mode toggles", "snapshots"}

// unlockedPage is the passphrase-entry form the LOCKED banner links to.
type unlockedPage struct {
	Stopped []string
}

func (s *Server) getUnlock(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "unlock", pageData{Title: "Unlock", Nav: "account", Data: unlockedPage{Stopped: lockedStopped}})
}

func (s *Server) postUnlock(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Unlock == nil {
		http.Error(w, "unlock is not available", http.StatusServiceUnavailable)
		return
	}
	pass := r.PostForm.Get("passphrase")
	if pass == "" || len(pass) > maxPassword {
		s.render(w, r, http.StatusBadRequest, "unlock", pageData{Title: "Unlock", Nav: "account",
			Data: unlockedPage{Stopped: lockedStopped}, Error: "Enter the operator passphrase."})
		return
	}
	if err := s.cfg.Unlock(r.Context(), pass); err != nil {
		_ = s.AuditAction(r, "unlock_failed", "")
		s.render(w, r, http.StatusForbidden, "unlock", pageData{Title: "Unlock", Nav: "account",
			Data: unlockedPage{Stopped: lockedStopped}, Error: "The passphrase did not unlock the controller."})
		return
	}
	_ = s.AuditAction(r, "unlock", "")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
