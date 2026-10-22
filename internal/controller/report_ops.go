package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	_ "image/jpeg" // registered for image.DecodeConfig on uploads
	_ "image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/report"
	"github.com/PurdueBlueTeam/phylax/internal/store"
	"github.com/PurdueBlueTeam/phylax/internal/ui"
)

var _ ui.ReportOps = (*WebOps)(nil)

const (
	maxEvidence    = 60
	maxExcerptSize = 6000
	maxImagePixels = 40_000_000
)

func marshalSpec(sp *draftSpec) (json.RawMessage, error) {
	b, err := json.Marshal(sp)
	return json.RawMessage(b), err
}

// Drafts lists IR and inject drafts.
func (o *WebOps) Drafts(ctx context.Context) ([]ui.DraftBrief, error) {
	ds, err := o.c.st.Drafts(ctx, "")
	if err != nil {
		return nil, err
	}
	out := make([]ui.DraftBrief, 0, len(ds))
	for _, d := range ds {
		fn, _ := report.Filename(report.Kind(d.Kind), d.Number, d.Team)
		out = append(out, ui.DraftBrief{ID: d.ID, Kind: d.Kind, Number: d.Number, Filename: fn, Title: d.Title, Updated: d.Updated, By: d.CreatedBy})
	}
	return out, nil
}

func (o *WebOps) render(ctx context.Context, d store.Draft, sp *draftSpec) (*renderedDoc, error) {
	switch d.Kind {
	case draftIR:
		return o.renderIR(ctx, d, sp)
	case draftInject:
		return o.renderInject(d, sp)
	}
	return nil, fmt.Errorf("draft %d has unknown kind %q", d.ID, d.Kind)
}

// Draft renders the review page, including live validation.
func (o *WebOps) Draft(ctx context.Context, id int64) (ui.DraftView, error) {
	d, sp, err := o.loadDraft(ctx, id)
	if err != nil {
		return ui.DraftView{}, err
	}
	if d.Kind == draftInject {
		return o.injectView(ctx, d, sp)
	}
	return o.irView(ctx, d, sp)
}

// SaveDraft stores the operator's inputs. The draft is rendered with them
// first, so input that cannot be parsed is refused instead of stored.
func (o *WebOps) SaveDraft(ctx context.Context, id int64, e ui.DraftEdit, by string) error {
	o.dmu.Lock()
	defer o.dmu.Unlock()
	d, sp, err := o.loadDraft(ctx, id)
	if err != nil {
		return err
	}
	switch d.Kind {
	case draftIR:
		err = o.saveIR(&d, sp, e)
	case draftInject:
		err = o.saveInject(&d, sp, e)
	}
	if err != nil {
		return err
	}
	if sp.Fills == nil {
		sp.Fills = map[string]string{}
	}
	for what, v := range e.Fills {
		if strings.TrimSpace(v) == "" {
			delete(sp.Fills, what)
		} else {
			sp.Fills[what] = v
		}
	}
	if _, err := o.render(ctx, d, sp); err != nil {
		return err
	}
	return o.saveDraft(ctx, d, sp)
}

// Download returns the final PDF, only when ValidateSubmission passes.
func (o *WebOps) Download(ctx context.Context, id int64, by string) (string, []byte, error) {
	d, sp, err := o.loadDraft(ctx, id)
	if err != nil {
		return "", nil, err
	}
	r, err := o.render(ctx, d, sp)
	if err != nil {
		return "", nil, err
	}
	if r.PDFErr != nil {
		return "", nil, fmt.Errorf("%w: the PDF could not be rendered: %v", ui.ErrConflict, r.PDFErr)
	}
	if !r.Val.OK() {
		var bad []string
		for _, c := range r.Val.Failures() {
			bad = append(bad, c.Name+" ("+c.Detail+")")
		}
		return "", nil, fmt.Errorf("%w: validation failed, nothing to download: %s", ui.ErrConflict, strings.Join(bad, "; "))
	}
	return r.Filename, r.PDF, nil
}

// ---------------------------------------------------------------- evidence

func (o *WebOps) addEvidence(ctx context.Context, id int64, mk func(d store.Draft, sp *draftSpec) (evSpec, error)) error {
	o.dmu.Lock()
	defer o.dmu.Unlock()
	d, sp, err := o.loadDraft(ctx, id)
	if err != nil {
		return err
	}
	if len(sp.Evidence) >= maxEvidence {
		return fmt.Errorf("%w: at most %d figures per draft", ui.ErrConflict, maxEvidence)
	}
	ev, err := mk(d, sp)
	if err != nil {
		return err
	}
	sp.Evidence = append(sp.Evidence, ev)
	return o.saveDraft(ctx, d, sp)
}

// AddEvidence stores a PNG or JPEG under the state directory, named by the
// first 16 hex digits of its SHA-256, and attaches it to the draft.
func (o *WebOps) AddEvidence(ctx context.Context, id int64, m ui.EvidenceMeta, filename string, data io.Reader, by string) error {
	buf, err := io.ReadAll(io.LimitReader(data, ui.MaxUpload+1))
	if err != nil {
		return fmt.Errorf("%w: reading the upload: %v", ui.ErrInvalid, err)
	}
	if len(buf) > ui.MaxUpload {
		return fmt.Errorf("%w: the image is over %d MiB", ui.ErrInvalid, ui.MaxUpload>>20)
	}
	if len(buf) == 0 {
		return fmt.Errorf("%w: empty upload", ui.ErrInvalid)
	}
	ext := ""
	switch http.DetectContentType(buf) {
	case "image/png":
		ext = ".png"
	case "image/jpeg":
		ext = ".jpg"
	default:
		return fmt.Errorf("%w: only PNG and JPEG screenshots are accepted (the report embeds those)", ui.ErrInvalid)
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(buf))
	if err != nil || cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width*cfg.Height > maxImagePixels {
		return fmt.Errorf("%w: not a readable image of a sane size", ui.ErrInvalid)
	}
	taken, err := parseCentral(m.Taken)
	if err != nil {
		return err
	}
	if taken.IsZero() {
		taken = o.c.now()
	}
	sum := sha256.Sum256(buf)
	hexsum := hex.EncodeToString(sum[:])
	name := hexsum[:16] + ext
	return o.addEvidence(ctx, id, func(d store.Draft, sp *draftSpec) (evSpec, error) {
		dir := o.draftDir(d.ID)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return evSpec{}, err
		}
		if err := atomicfile.WriteFile(filepath.Join(dir, name), buf, 0o600); err != nil {
			return evSpec{}, err
		}
		return evSpec{Kind: string(report.EvScreenshot), File: name, SHA256: hexsum, Host: clip(m.Host, 128), Caption: clip(oneLine(m.Caption), 300),
			Taken: taken, Tags: cleanTags(m.Tags), Annotated: m.Annotated}, nil
	})
}

// AddHostEvidence attaches the newest stored events of a host as a log
// excerpt figure (hashed from its text).
func (o *WebOps) AddHostEvidence(ctx context.Context, id int64, r ui.HostEvidenceReq, by string) error {
	if r.Host == "" {
		return fmt.Errorf("%w: choose a host", ui.ErrInvalid)
	}
	if _, err := o.c.st.Agent(ctx, r.Host); err != nil {
		return fmt.Errorf("%w: no stored events for host %q", ui.ErrInvalid, clip(r.Host, 64))
	}
	limit := min(max(r.Limit, 1), 40)
	if r.Limit == 0 {
		limit = 10
	}
	evs, err := o.c.st.Events(ctx, store.Query{Agent: r.Host, Kind: r.Kind, Limit: limit, Desc: true})
	if err != nil {
		return err
	}
	if len(evs) == 0 {
		return fmt.Errorf("%w: no stored events of that kind for %s", ui.ErrConflict, r.Host)
	}
	var b strings.Builder
	var latest time.Time
	for i := len(evs) - 1; i >= 0; i-- { // chronological
		e := evs[i]
		if e.Time.After(latest) {
			latest = e.Time
		}
		body, _ := json.Marshal(e.Fields)
		fmt.Fprintf(&b, "%s %s#%d %s %s\n", e.Time.UTC().Format("2006-01-02T15:04:05.000Z"), e.Agent, e.Seq, e.Kind, clip(string(body), 400))
	}
	ex := strings.TrimRight(clip(b.String(), maxExcerptSize), "\n")
	return o.addEvidence(ctx, id, func(d store.Draft, sp *draftSpec) (evSpec, error) {
		return evSpec{Kind: string(report.EvLog), Host: r.Host, Caption: clip(oneLine(r.Caption), 300), Taken: latest, Tags: cleanTags(r.Tags), Excerpt: ex}, nil
	})
}

// RemoveEvidence detaches figure n (1-based). The stored file stays on disk.
func (o *WebOps) RemoveEvidence(ctx context.Context, id int64, n int, by string) error {
	o.dmu.Lock()
	defer o.dmu.Unlock()
	d, sp, err := o.loadDraft(ctx, id)
	if err != nil {
		return err
	}
	if n < 1 || n > len(sp.Evidence) {
		return ui.ErrNotFound
	}
	sp.Evidence = append(sp.Evidence[:n-1:n-1], sp.Evidence[n:]...)
	return o.saveDraft(ctx, d, sp)
}
