// Package traceback builds the trace-back chain (docs: The trace-back
// chain): from an untagged change or red check back, step by step, to the
// request and source that caused it. It runs on the controller over
// mirrored agent events. When a link cannot be established, the timeline
// says which link is missing instead of guessing (docs: Where the chain
// breaks).
//
// The request link is the hardest part (design: Complexity flag). This
// package implements it two ways: attributable when the change event
// carries the writer process (the process that wrote the file is the
// service worker that was serving the connection), and a time-window
// fallback otherwise — requests to the same service port from
// non-platform sources in the window before the change, marked lower
// confidence (design: the fallback, when the request link misses).
package traceback

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// RequestWindow is how far back the request link looks (docs: requests
// from other sources before the change; 10 min matches the IR window used
// for "everything else from that source").
const RequestWindow = 10 * time.Minute

// Event is one mirrored agent event in the shape the store holds.
type Event struct {
	Host string
	TS   time.Time
	Type string
	Data map[string]any
}

// Change is the trigger of a trace-back: one untagged change to a scored
// service (or a red active check, which the caller maps to a Change on
// the check's service).
type Change struct {
	Host   string
	Path   string
	Op     string
	TS     time.Time
	SHA256 string
	Size   int64
	// Service and Port identify the scored service the path belongs to
	// (Port is the service's listening port, for the request link).
	Service string
	Port    int
}

// ChangeWriter is a Change plus the writing process, when the agent's
// file module recorded it (fanotify/audit on Linux, Sysmon 11 on
// Windows).
type ChangeWriter struct {
	Change
	PID  int
	Comm string
}

// ProcessLink is one process in a lineage.
type ProcessLink struct {
	PID  int    `json:"pid"`
	PPID int    `json:"ppid"`
	Comm string `json:"comm"`
	Exe  string `json:"exe,omitempty"`
}

// RequestLink is the request believed to have caused the change.
type RequestLink struct {
	Host       string `json:"host"`
	TS         string `json:"ts"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	HostHdr    string `json:"host_hdr,omitempty"`
	Body       string `json:"body,omitempty"`
	Resp       int    `json:"resp"`
	Src        string `json:"src"`
	Sport      int    `json:"sport"`
	Confidence string `json:"confidence"` // high | low
}

// EventRef is one other event from the same source (first contact,
// foothold).
type EventRef struct {
	Host    string `json:"host"`
	TS      string `json:"ts"`
	Type    string `json:"type"`
	Summary string `json:"summary"`
}

// Evidence is one attached artifact.
type Evidence struct {
	Kind   string `json:"kind"` // file | ring
	Path   string `json:"path,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Note   string `json:"note,omitempty"`
}

// Timeline is the finished chain. Missing lists the links that could not
// be established, named, so the IR drafter reports gaps instead of
// guesses.
type Timeline struct {
	Change      Change        `json:"change"`
	Writer      *ProcessLink  `json:"writer,omitempty"`
	Lineage     []ProcessLink `json:"lineage,omitempty"` // writer first, root last
	Request     *RequestLink  `json:"request,omitempty"`
	Source      string        `json:"source,omitempty"`
	SourceLabel string        `json:"source_label,omitempty"`
	FromSource  []EventRef    `json:"from_source,omitempty"`
	Evidence    []Evidence    `json:"evidence,omitempty"`
	Confidence  string        `json:"confidence"` // high | low
	Missing     []string      `json:"missing,omitempty"`
}

// Builder accumulates mirrored events and builds timelines. The
// controller feeds it from one goroutine.
type Builder struct {
	procs  map[int]ProcessLink // latest record per pid
	evs    []Event             // rolling window of everything
	maxEvs int
	us     map[string]bool     // platform sources: never trace-back sources
	label  func(ip string) string
	now    func() time.Time
}

// New builds a Builder.
func New() *Builder {
	return &Builder{
		procs:  map[int]ProcessLink{},
		maxEvs: 10000,
		us:     map[string]bool{},
		now:    time.Now,
	}
}

// ForTest sets the clock (tests).
func (b *Builder) ForTest(now func() time.Time) { b.now = now }

// SetLabeler wires the traffic labels (us/scorer/other) for the source
// link.
func (b *Builder) SetLabeler(fn func(ip string) string) { b.label = fn }

// AddUSSource marks one of the platform's own addresses: traffic from it
// is never a trace-back source.
func (b *Builder) AddUSSource(ip string) { b.us[ip] = true }

// AddEvent indexes one mirrored event. process_start events are kept in
// the pid table for the lineage link; everything else goes to the rolling
// window (oldest dropped past maxEvs).
func (b *Builder) AddEvent(e Event) {
	if e.Type == "process_start" {
		p := ProcessLink{
			PID:  intNum(e.Data["pid"]),
			PPID: intNum(e.Data["ppid"]),
			Comm: str(e.Data["comm"]),
			Exe:  str(e.Data["exe"]),
		}
		if p.PID != 0 {
			b.procs[p.PID] = p
		}
	}
	b.evs = append(b.evs, e)
	if len(b.evs) > b.maxEvs {
		b.evs = b.evs[len(b.evs)-b.maxEvs:]
	}
}

// Build traces a change back to its cause (time-window fallback only).
func (b *Builder) Build(ch Change) *Timeline {
	return b.build(ch, 0, "")
}

// BuildWithWriter traces a change back with a known writer process (the
// file event carries it).
func (b *Builder) BuildWithWriter(cw ChangeWriter) *Timeline {
	return b.build(cw.Change, cw.PID, cw.Comm)
}

func (b *Builder) build(ch Change, writerPID int, writerComm string) *Timeline {
	tl := &Timeline{Change: ch, Confidence: "high"}

	// 2-3. The writer and its lineage. The writer is taken from the change
	// event only — never guessed (docs: Where the chain breaks).
	if writerPID != 0 {
		p := ProcessLink{PID: writerPID, Comm: writerComm}
		if rec, ok := b.procs[writerPID]; ok {
			p = rec
		}
		tl.Writer = &p
		tl.Lineage = b.lineage(writerPID, 5)
		if len(tl.Lineage) < 2 {
			tl.Missing = append(tl.Missing, "lineage")
		}
	} else {
		tl.Missing = append(tl.Missing, "writer", "lineage")
	}

	// 4. The request: time-window correlation to this service's port from
	// non-platform sources shortly before the change; the most recent
	// candidate is the cause.
	type cand struct {
		ts  time.Time
		req RequestLink
	}
	var cands []cand
	lo := ch.TS.Add(-RequestWindow)
	for _, e := range b.evs {
		if e.Type != "http" || e.TS.Before(lo) || e.TS.After(ch.TS.Add(5*time.Second)) {
			continue
		}
		if ch.Host != "" && e.Host != ch.Host {
			continue
		}
		src := ipOf(e.Data)
		if src == "" || b.us[src] {
			continue
		}
		if ch.Port != 0 && intNum(e.Data["dport"]) != ch.Port {
			continue
		}
		cands = append(cands, cand{ts: e.TS, req: RequestLink{
			Host:    e.Host,
			TS:      e.TS.UTC().Format(time.RFC3339Nano),
			Method:  str(e.Data["method"]),
			Path:    str(e.Data["path"]),
			HostHdr: str(e.Data["host"]),
			Body:    str(e.Data["body"]),
			Resp:    intNum(e.Data["resp"]),
			Src:     src, Sport: intNum(e.Data["sport"]),
		}})
	}
	if len(cands) > 0 {
		sort.Slice(cands, func(i, j int) bool { return cands[i].ts.After(cands[j].ts) })
		req := cands[0].req
		// 5. The source.
		tl.Source = req.Src
		if b.label != nil {
			tl.SourceLabel = b.label(req.Src)
		}
		// 6. Everything else from that source, earlier (the request
		// itself is link 4, not part of "everything else").
		tl.FromSource = b.fromSource(req.Src, ch.TS, req.TS)
		if reqIsSuspicious(req) && tl.Writer != nil && len(tl.Lineage) >= 2 {
			// attributable: the writer is the service worker (lineage
			// verified) and the request is a write
			req.Confidence = "high"
		} else {
			// time-window fallback (docs: marked lower confidence)
			req.Confidence = "low"
			tl.Confidence = "low"
		}
		tl.Request = &req
	} else {
		tl.Confidence = "low"
		tl.Missing = append(tl.Missing, "request", "source")
	}

	// 7. Evidence: the file, and the ring window around the change (the
	// pull itself is a one-click UI action).
	if ch.Path != "" {
		tl.Evidence = append(tl.Evidence, Evidence{
			Kind: "file", Path: ch.Path, SHA256: ch.SHA256,
			Note: fmt.Sprintf("%s on %s", ch.Op, ch.Host),
		})
	}
	tl.Evidence = append(tl.Evidence, Evidence{
		Kind: "ring",
		Note: fmt.Sprintf("packet ring %s [%s, %s] — freeze and pull",
			ch.Host, ch.TS.Add(-RequestWindow).UTC().Format(time.RFC3339), ch.TS.UTC().Format(time.RFC3339)),
	})
	return tl
}

// lineage walks ppid from pid, bounded at depth.
func (b *Builder) lineage(pid, depth int) []ProcessLink {
	out := []ProcessLink{}
	seen := map[int]bool{}
	for i := 0; i < depth; i++ {
		p, ok := b.procs[pid]
		if !ok || seen[p.PID] {
			break
		}
		seen[p.PID] = true
		out = append(out, p)
		if p.PPID <= 1 {
			break
		}
		pid = p.PPID
	}
	return out
}


// reqIsSuspicious marks the requests a webshell-driven change comes from:
// a write-method request, or a body carrying a script payload.
func reqIsSuspicious(r RequestLink) bool {
	switch r.Method {
	case "POST", "PUT", "PATCH":
		return true
	}
	for _, sig := range []string{"<?php", "<?=", "eval(", "system(", "exec("} {
		if strings.Contains(r.Body, sig) {
			return true
		}
	}
	return false
}

// fromSource returns the other events from the same source in the IR
// window before the change (earlier transactions, scans, logins, decoy
// hits), newest first, capped.
func (b *Builder) fromSource(src string, at time.Time, excludeTS string) []EventRef {
	lo := at.Add(-RequestWindow)
	var out []EventRef
	for _, e := range b.evs {
		if e.TS.Before(lo) || e.TS.After(at) || e.Type == "process_start" {
			continue
		}
		ts := e.TS.UTC().Format(time.RFC3339Nano)
		if ts == excludeTS {
			continue
		}
		if ipOf(e.Data) != src {
			continue
		}
		out = append(out, EventRef{Host: e.Host, TS: ts, Type: e.Type, Summary: summary(e)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TS > out[j].TS })
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

// summary renders one line for the UI timeline.
func summary(e Event) string {
	switch e.Type {
	case "http":
		return fmt.Sprintf("%s %s -> %d", str(e.Data["method"]), str(e.Data["path"]), intNum(e.Data["resp"]))
	case "exchange":
		return fmt.Sprintf("%s %s %s", str(e.Data["proto"]), str(e.Data["cmd"]), str(e.Data["arg"]))
	case "dns":
		return fmt.Sprintf("dns %v", e.Data["names"])
	case "file_change":
		return fmt.Sprintf("%s %s", str(e.Data["op"]), str(e.Data["path"]))
	}
	return e.Type
}

// ipOf extracts the IPv4 at the end of the 16-byte src array a capture
// event carries (JSON: 16-element number array).
func ipOf(data map[string]any) string {
	arr, ok := data["src"].([]any)
	if !ok || len(arr) < 4 {
		return ""
	}
	var b [4]byte
	for i := 0; i < 4; i++ {
		b[i] = byte(numF(arr[len(arr)-4+i]))
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func intNum(v any) int { return int(numF(v)) }

func numF(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	}
	return 0
}
