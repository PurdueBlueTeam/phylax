package ui

import (
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The report, inject, checks, health and audit pages. They are optional
// extensions of Ops: a backend implements the interfaces it supports and the
// matching routes are registered (a fake Ops without them gets no routes).

// MaxUpload is the largest screenshot accepted.
const MaxUpload = 8 << 20

// ReportOps is the IR drafter and inject workflow backend.
type ReportOps interface {
	// Drafts lists IR and inject drafts, newest first.
	Drafts(ctx context.Context) ([]DraftBrief, error)
	// NewIR drafts an incident report for a chain or a campaign (one of the
	// ids is set) and stores it.
	NewIR(ctx context.Context, chainID, campaignID int64, by string) (int64, error)
	InjectKinds(ctx context.Context) ([]InjectKindInfo, error)
	NewInject(ctx context.Context, kind string, number int, code, title, by string) (int64, error)
	Draft(ctx context.Context, id int64) (DraftView, error)
	// SaveDraft stores the operator's field values and fills and regenerates.
	SaveDraft(ctx context.Context, id int64, e DraftEdit, by string) error
	// AddEvidence attaches a screenshot (data is already size-bounded) with
	// its metadata; the controller sniffs, hashes and stores it.
	AddEvidence(ctx context.Context, id int64, m EvidenceMeta, filename string, data io.Reader, by string) error
	// AddHostEvidence adds a log excerpt built from the host's stored events.
	AddHostEvidence(ctx context.Context, id int64, r HostEvidenceReq, by string) error
	RemoveEvidence(ctx context.Context, id int64, n int, by string) error
	// Download renders the final PDF. It returns ErrConflict (with the failed
	// checks in the message) unless ValidateSubmission passes.
	Download(ctx context.Context, id int64, by string) (name string, pdf []byte, err error)
}

// DraftBrief is one row of the report list.
type DraftBrief struct {
	ID       int64
	Kind     string // incident, inject
	Number   int
	Filename string
	Title    string
	Updated  time.Time
	By       string
}

// InjectKindInfo describes an inject template.
type InjectKindInfo struct{ Kind, Title string }

// FieldView is one input of the draft form.
type FieldView struct {
	Name, Label, Value, Hint string
	Multiline                bool
}

// FillView is one [[FILL]] placeholder still in (or filled in) the draft.
type FillView struct {
	Section, What, Value string
	Open                 bool
}

// CheckView is one rubric item.
type CheckView struct {
	ID, Rubric, Name, Status, Detail string
	Weight                           int
	Lines                            []string
}

// RubricScore is the share of a rubric the draft satisfies.
type RubricScore struct {
	Rubric        string
	Earned, Total int
}

// EvidenceView is one attached figure.
type EvidenceView struct {
	N                           int
	Kind, Host, Caption, Taken  string
	SHA256, Path, Tags          string
	Annotated, Excerpt, IsImage bool
}

// ValidationLine is one ValidateSubmission finding.
type ValidationLine struct{ Name, Severity, Detail string }

// ValidationView is the pre-submit result.
type ValidationView struct {
	OK     bool
	Pages  int
	Words  int
	Checks []ValidationLine
	Error  string
}

// DraftView is the review page of one draft.
type DraftView struct {
	ID       int64
	Kind     string
	Number   int
	Team     int
	Filename string
	Title    string
	Source   string
	Updated  time.Time

	Fields    []FieldView
	Fills     []FillView
	OpenFills int
	Checklist []CheckView
	Scores    []RubricScore
	Evidence  []EvidenceView
	Hosts     []string // hosts with stored events, for the evidence picker
	Help      []string
	Markdown  string

	Validation ValidationView
}

// DraftEdit is the posted form.
type DraftEdit struct {
	Fields map[string]string
	Fills  map[string]string
}

// EvidenceMeta describes an uploaded screenshot.
type EvidenceMeta struct {
	Host, Caption, Taken string
	Tags                 []string
	Annotated            bool
}

// HostEvidenceReq asks for an excerpt of a host's stored events.
type HostEvidenceReq struct {
	Host, Kind, Caption string
	Limit               int
	Tags                []string
}

func (s *Server) reportOps(w http.ResponseWriter) ReportOps {
	if s.cfg.Ops != nil {
		if o, ok := s.cfg.Ops.(ReportOps); ok {
			return o
		}
	}
	http.NotFound(w, nil)
	return nil
}

func (s *Server) reportRoutes() {
	if s.cfg.Ops == nil {
		return
	}
	if _, ok := s.cfg.Ops.(ReportOps); ok {
		h := func(p string, f http.HandlerFunc) { s.Handle(p, f) }
		h("GET /reports", s.getReports)
		h("POST /reports/ir", s.postNewIR)
		h("POST /reports/inject", s.postNewInject)
		h("GET /reports/{id}", s.getDraft)
		h("POST /reports/{id}/save", s.postSaveDraft)
		h("POST /reports/{id}/validate", s.postValidateDraft)
		h("POST /reports/{id}/upload", s.postUpload)
		h("POST /reports/{id}/hostevidence", s.postHostEvidence)
		h("POST /reports/{id}/evidence/{n}/delete", s.postRemoveEvidence)
		h("GET /reports/{id}/download", s.getDownload)
	}
	if _, ok := s.cfg.Ops.(ChecksOps); ok {
		s.Handle("GET /checks", http.HandlerFunc(s.getChecks))
		s.Handle("GET /checks/{id...}", http.HandlerFunc(s.getCheck))
	}
	if _, ok := s.cfg.Ops.(HealthOps); ok {
		s.Handle("GET /health", http.HandlerFunc(s.getHealth))
		s.Handle("GET /audit", http.HandlerFunc(s.getAudit))
	}
}

type reportsPage struct {
	Drafts []DraftBrief
	Kinds  []InjectKindInfo
}

func (s *Server) getReports(w http.ResponseWriter, r *http.Request) {
	o := s.reportOps(w)
	if o == nil {
		return
	}
	d, err := o.Drafts(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	k, err := o.InjectKinds(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "reports", pageData{Title: "Reports", Nav: "reports", Data: reportsPage{Drafts: d, Kinds: k}})
}

func formInt(r *http.Request, name string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(r.PostForm.Get(name)), 10, 64)
	return n
}

func (s *Server) postNewIR(w http.ResponseWriter, r *http.Request) {
	o := s.reportOps(w)
	if o == nil {
		return
	}
	chain, camp := formInt(r, "chain"), formInt(r, "campaign")
	if (chain > 0) == (camp > 0) {
		http.Error(w, "give exactly one of chain and campaign", http.StatusBadRequest)
		return
	}
	id, err := o.NewIR(r.Context(), chain, camp, Principal(r.Context()))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.AuditAction(r, "ir_draft", fmt.Sprintf("draft %d from chain %d campaign %d", id, chain, camp))
	s.redirect(w, r, "/reports/"+strconv.FormatInt(id, 10))
}

func (s *Server) postNewInject(w http.ResponseWriter, r *http.Request) {
	o := s.reportOps(w)
	if o == nil {
		return
	}
	kind := r.PostForm.Get("kind")
	id, err := o.NewInject(r.Context(), kind, int(formInt(r, "number")), strings.TrimSpace(r.PostForm.Get("code")),
		strings.TrimSpace(r.PostForm.Get("title")), Principal(r.Context()))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.AuditAction(r, "inject_draft", fmt.Sprintf("draft %d kind %s", id, kind))
	s.redirect(w, r, "/reports/"+strconv.FormatInt(id, 10))
}

func (s *Server) getDraft(w http.ResponseWriter, r *http.Request) {
	o := s.reportOps(w)
	id, ok := idParam(r)
	if o == nil {
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	d, err := o.Draft(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "draft", pageData{Title: d.Filename, Nav: "reports", Data: d})
}

func (s *Server) draftAction(name string, f func(o ReportOps, r *http.Request, id int64, by string) (string, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		o := s.reportOps(w)
		id, ok := idParam(r)
		if o == nil {
			return
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		detail, err := f(o, r, id, Principal(r.Context()))
		if err != nil {
			s.fail(w, r, err)
			return
		}
		_ = s.AuditAction(r, name, "draft "+strconv.FormatInt(id, 10)+" "+detail)
		s.redirect(w, r, "/reports/"+strconv.FormatInt(id, 10))
	}
}

func (s *Server) postSaveDraft(w http.ResponseWriter, r *http.Request) {
	s.draftAction("report_save", func(o ReportOps, r *http.Request, id int64, by string) (string, error) {
		e := DraftEdit{Fields: map[string]string{}, Fills: map[string]string{}}
		for k, v := range r.PostForm {
			if strings.HasPrefix(k, "f_") && len(v) > 0 && len(k) < 64 {
				e.Fields[strings.TrimPrefix(k, "f_")] = clipStr(v[0], 8000)
			}
		}
		whats, fills := r.PostForm["what"], r.PostForm["fill"]
		for i := 0; i < len(whats) && i < len(fills) && i < 500; i++ {
			e.Fills[whats[i]] = clipStr(fills[i], 2000)
		}
		return fmt.Sprintf("%d fields %d fills", len(e.Fields), len(e.Fills)), o.SaveDraft(r.Context(), id, e, by)
	})(w, r)
}

func (s *Server) postValidateDraft(w http.ResponseWriter, r *http.Request) {
	s.draftAction("report_validate", func(o ReportOps, r *http.Request, id int64, by string) (string, error) {
		d, err := o.Draft(r.Context(), id)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("ok=%v", d.Validation.OK), nil
	})(w, r)
}

func clipStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (s *Server) postHostEvidence(w http.ResponseWriter, r *http.Request) {
	s.draftAction("report_host_evidence", func(o ReportOps, r *http.Request, id int64, by string) (string, error) {
		req := HostEvidenceReq{Host: strings.TrimSpace(r.PostForm.Get("host")), Kind: strings.TrimSpace(r.PostForm.Get("kind")),
			Caption: strings.TrimSpace(r.PostForm.Get("caption")), Limit: int(formInt(r, "limit")), Tags: r.PostForm["tag"]}
		return "host " + req.Host, o.AddHostEvidence(r.Context(), id, req, by)
	})(w, r)
}

func (s *Server) postRemoveEvidence(w http.ResponseWriter, r *http.Request) {
	s.draftAction("report_evidence_remove", func(o ReportOps, r *http.Request, id int64, by string) (string, error) {
		n, err := strconv.Atoi(r.PathValue("n"))
		if err != nil {
			return "", fmt.Errorf("%w: figure number", ErrInvalid)
		}
		return "figure " + strconv.Itoa(n), o.RemoveEvidence(r.Context(), id, n, by)
	})(w, r)
}

func (s *Server) postUpload(w http.ResponseWriter, r *http.Request) {
	s.draftAction("report_upload", func(o ReportOps, r *http.Request, id int64, by string) (string, error) {
		mf := r.MultipartForm
		if mf == nil {
			return "", fmt.Errorf("%w: multipart form expected", ErrInvalid)
		}
		defer mf.RemoveAll()
		fhs := mf.File["file"]
		if len(fhs) != 1 {
			return "", fmt.Errorf("%w: attach exactly one image", ErrInvalid)
		}
		first := func(k string) string {
			if v := mf.Value[k]; len(v) > 0 {
				return strings.TrimSpace(v[0])
			}
			return ""
		}
		m := EvidenceMeta{Host: first("host"), Caption: first("caption"), Taken: first("taken"), Tags: mf.Value["tag"], Annotated: first("annotated") == "1"}
		var f multipart.File
		f, err := fhs[0].Open()
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		defer f.Close()
		return "file " + url.PathEscape(fhs[0].Filename), o.AddEvidence(r.Context(), id, m, fhs[0].Filename, io.LimitReader(f, MaxUpload+1), by)
	})(w, r)
}

// getDownload is a GET but it is audited explicitly: handing out a final
// submission file is an operator action.
func (s *Server) getDownload(w http.ResponseWriter, r *http.Request) {
	o := s.reportOps(w)
	id, ok := idParam(r)
	if o == nil {
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	name, pdf, err := o.Download(r.Context(), id, Principal(r.Context()))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.AuditAction(r, "report_download", "draft "+strconv.FormatInt(id, 10)+" "+name); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(pdf)))
	_, _ = w.Write(pdf)
}

// ---------------------------------------------------------------- checks

// ChecksOps is the probe-library and vantage check backend.
type ChecksOps interface {
	Checks(ctx context.Context) (ChecksView, error)
	CheckHistory(ctx context.Context, id string) (CheckHistoryView, error)
}

// ChecksView is the checks page.
type ChecksView struct {
	Services []ServiceChecks
	Note     string
}

// ServiceChecks groups the checks of one scored service.
type ServiceChecks struct {
	Service   string
	Streak    int
	Penalties int
	Level     string
	Checks    []CheckSummary
}

// CheckSummary is one check's latest result and recent history.
type CheckSummary struct {
	ID, Kind  string
	Vantage   string
	OK        bool
	Known     bool // false: no result yet
	Class     string
	Err       string
	Time      time.Time
	Elapsed   string
	Recent    []bool // newest first
	UpPercent int
	Samples   int
}

// CheckHistoryView is the history of one check.
type CheckHistoryView struct {
	ID, Service, Kind string
	Streak, Penalties int
	Level             string
	Rows              []CheckHistoryRow
}

// CheckHistoryRow is one stored result.
type CheckHistoryRow struct {
	Time          time.Time
	Vantage       string
	OK            bool
	Class, Err    string
	Mode, Item    string
	Elapsed       string
	ScorerVerdict string
}

func (s *Server) getChecks(w http.ResponseWriter, r *http.Request) {
	o, _ := s.cfg.Ops.(ChecksOps)
	v, err := o.Checks(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "checks", pageData{Title: "Checks", Nav: "checks", Data: v})
}

func (s *Server) getCheck(w http.ResponseWriter, r *http.Request) {
	o, _ := s.cfg.Ops.(ChecksOps)
	v, err := o.CheckHistory(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "check", pageData{Title: "Check " + v.ID, Nav: "checks", Data: v})
}

// ---------------------------------------------------------------- health and audit

// HealthOps is the platform self-health and audit-log backend.
type HealthOps interface {
	Health(ctx context.Context) (HealthView, error)
	Audit(ctx context.Context, f AuditQuery) (AuditPageView, error)
}

// HealthView is the platform health page.
type HealthView struct {
	Problems []string
	Platform []KV
	Store    []KV
	Agents   []HealthAgent
}

// HealthAgent is one agent's health line.
type HealthAgent struct {
	Host, State, Link string
	LastSeen          time.Time
	ClockSkew         time.Duration
	SkewBad           bool
	SpoolDepth        uint64
	Congestion        string
	Dropped           uint64
	GapRecords        int
	ModuleErrors      []string
	Modules           int
}

// AuditQuery filters the audit viewer.
type AuditQuery struct {
	Actor, Action string
	Before        int64
	Limit         int
}

// AuditPageView is one page of the audit log.
type AuditPageView struct {
	Rows    []AuditRowView
	Next    int64
	Actors  []string
	Actions []string
	Query   AuditQuery
}

// AuditRowView is one audit row.
type AuditRowView struct {
	ID                    int64
	Time                  time.Time
	Actor, Action, Remote string
	Detail                string
}

func (s *Server) getHealth(w http.ResponseWriter, r *http.Request) {
	o, _ := s.cfg.Ops.(HealthOps)
	v, err := o.Health(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "health", pageData{Title: "Platform health", Nav: "health", Data: v})
}

func (s *Server) getAudit(w http.ResponseWriter, r *http.Request) {
	o, _ := s.cfg.Ops.(HealthOps)
	q := r.URL.Query()
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	v, err := o.Audit(r.Context(), AuditQuery{Actor: clipStr(q.Get("actor"), 128), Action: clipStr(q.Get("action"), 128), Before: before, Limit: 50})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "audit", pageData{Title: "Audit log", Nav: "audit", Data: v})
}
