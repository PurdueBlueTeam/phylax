package honeytokens

import (
	"context"
	"regexp"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// FieldAWSKeyID is the event field D15g tests (profile honeytoken.aws_keys).
const FieldAWSKeyID = "aws_access_key_id"

// FieldDerived marks an event produced by a scanner from another event; the
// scanner never rescans those.
const FieldDerived = "derived_from"

// akiaKinds are the event kinds whose payloads can carry a leaked key id:
// HTTP requests (egress proxy, sinkhole), sinkhole captures and DNS names.
var akiaKinds = map[string]bool{"http_request": true, "net.sinkhole_capture": true, "dns_query": true}

// akiaRE finds an access key id in a payload. Key ids are base32 (A-Z2-7)
// after AKIA; DNS names are lower-cased, so the match is case-insensitive and
// the result is upper-cased. The class boundary keeps a longer base32 run from
// matching in the middle.
var akiaRE = regexp.MustCompile(`(?i)(?:^|[^A-Za-z2-7])(AKIA[A-Za-z2-7]{16})(?:[^A-Za-z2-7]|$)`)

const (
	maxScanFieldLen = 64 << 10
	maxScanDepth    = 4
	maxScanKeys     = 8
)

// ScanAKIA returns the distinct AWS access key ids (AKIA + 16 base32) found in
// the string values of fields, upper-cased, at most maxScanKeys. It looks into
// nested maps and lists to a bounded depth and bounded string length.
func ScanAKIA(fields map[string]any) []string {
	var out []string
	seen := map[string]bool{}
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		if len(out) >= maxScanKeys || depth > maxScanDepth {
			return
		}
		switch x := v.(type) {
		case string:
			if len(x) > maxScanFieldLen {
				x = x[:maxScanFieldLen]
			}
			if !strings.Contains(strings.ToUpper(x), "AKIA") {
				return
			}
			for _, m := range akiaRE.FindAllStringSubmatch(x, -1) {
				id := strings.ToUpper(m[1])
				if !seen[id] && len(out) < maxScanKeys {
					seen[id] = true
					out = append(out, id)
				}
			}
		case map[string]any:
			for _, e := range x {
				walk(e, depth+1)
			}
		case []any:
			for _, e := range x {
				walk(e, depth+1)
			}
		case []string:
			for _, e := range x {
				walk(e, depth+1)
			}
		}
	}
	for k, v := range fields {
		if k == FieldAWSKeyID || k == FieldDerived {
			continue
		}
		walk(v, 0)
	}
	return out
}

// AKIAScanner is an agent module that watches the agent's own event stream for
// http_request, net.sinkhole_capture and dns_query events whose payload holds
// an AKIA-pattern key id, and emits a copy of the event (same kind, so rule
// D15g sees it) with aws_access_key_id set. The rule decides whether the key
// is one of our canaries; the scanner only extracts. Events that already carry
// the field (a producer that parses it itself) are left alone.
type AKIAScanner struct {
	Subscribe func(buf int) (<-chan event.Event, func())
}

// Name implements agent.Module.
func (*AKIAScanner) Name() string { return "akiascan" }

// Start implements agent.Module.
func (m *AKIAScanner) Start(ctx context.Context, emit agent.Emit) error {
	ch, unsub := m.Subscribe(1024)
	defer unsub()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-ch:
			for _, out := range AKIAEvents(ev) {
				_ = emit(out)
			}
		}
	}
}

// AKIAEvents returns the derived events for ev (none if ev is not a scanned
// kind, carries the field already, or holds no key id). One event per key id.
func AKIAEvents(ev event.Event) []event.Event {
	if !akiaKinds[ev.Kind] || ev.Fields == nil {
		return nil
	}
	if _, has := ev.Fields[FieldAWSKeyID]; has {
		return nil
	}
	if _, derived := ev.Fields[FieldDerived]; derived {
		return nil
	}
	var out []event.Event
	for _, id := range ScanAKIA(ev.Fields) {
		f := map[string]any{FieldAWSKeyID: id, FieldDerived: ev.Kind}
		for _, k := range []string{"source", "src", "src_ip", "dest", "dst", "dst_ip", "host", "domain", "method"} {
			if v, ok := ev.Fields[k]; ok {
				f[k] = v
			}
		}
		if _, ok := f["source"]; !ok {
			for _, k := range []string{"src_ip", "src"} {
				if v, ok := ev.Fields[k]; ok {
					f["source"] = v
					break
				}
			}
		}
		out = append(out, event.Event{Time: ev.Time, Kind: ev.Kind, Priority: event.PriorityCritical, Fields: f})
	}
	return out
}
