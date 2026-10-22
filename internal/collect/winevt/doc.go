// Package winevt is the Windows event-log telemetry module (design: Telemetry
// sources, Windows; Appendix A). It subscribes to event channels with
// EvtSubscribe (pull model with a signal event), renders each event to XML,
// parses it in Go and maps it to normalised internal/event records that the
// rule engine consumes (process_start, auth_success, auth_fail, sec_event,
// net_connect, ...). Per-channel bookmarks are persisted with atomicfile so a
// restart resumes where the previous run stopped.
//
// Everything except the wevtapi calls is platform independent and unit-tested
// on Linux with recorded event XML: record.go (parser), mapper.go (field
// mapping), filter.go (server-side XPath and client-side drops), bookmark.go,
// pipeline.go (bounded queue, backpressure, gap accounting) and module.go.
// The OS boundary is the Source interface; source_windows.go implements it
// over wevtapi.dll through golang.org/x/sys/windows (no cgo).
//
// The subscription design (signal event, EvtNext batches, EvtRender to XML,
// EvtUpdateBookmark/EvtRender for bookmarks, strict bookmark resume) follows
// Elastic Beats' winlogbeat/sys/wineventlog (Apache-2.0,
// https://github.com/elastic/beats). No code is copied from it.
package winevt
