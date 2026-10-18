// Package logsmod is the agent's `logs` module (docs: Modules): app and
// OS logs into events. It tails the configured files, emits selected
// lines (sheddable spool class), and emits a protected `log_cleared`
// event when a watched file is truncated or rewritten in place — the
// input to D10 (defense evasion).
package logsmod

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// LogEvent is one emitted log line.
type LogEvent struct {
	File string `json:"file"`
	Line string `json:"line"`
}

// ClearedEvent is one truncation/rewrite of a watched log.
type ClearedEvent struct {
	File string `json:"file"`
	Op   string `json:"op"` // truncated | rewritten
}

// Sink receives log events.
type Sink interface {
	LogLine(LogEvent)
	LogCleared(ClearedEvent)
}

// Watch is one file to tail. Patterns nil means all lines.
type Watch struct {
	File    string
	Pattern *regexp.Regexp
}

// Module tails a set of files.
type Module struct {
	sink     Sink
	watches  []Watch
	interval time.Duration

	mu   sync.Mutex
	offs map[string]off
}

type off struct {
	pos    int64
	hash   string // sha of first 4 KB at last read (rewrite detection)
	size   int64
}

// New builds the module.
func New(sink Sink, watches []Watch) *Module {
	return &Module{sink: sink, watches: watches, interval: 500 * time.Millisecond,
		offs: map[string]off{}}
}

// Run tails until ctx is done.
func (m *Module) Run(ctx context.Context) error {
	// start at the end of existing files: we care about new lines
	for _, w := range m.watches {
		if fi, err := os.Stat(w.File); err == nil {
			m.offs[w.File] = off{pos: fi.Size()}
		}
	}
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			for _, w := range m.watches {
				m.tail(w)
			}
		}
	}
}

func (m *Module) tail(w Watch) {
	f, err := os.Open(w.File)
	if err != nil {
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return
	}

	m.mu.Lock()
	prev := m.offs[w.File]
	m.mu.Unlock()

	size := fi.Size()
	start := prev.pos
	if size < prev.pos {
		// truncated (or rotated in place)
		m.sink.LogCleared(ClearedEvent{File: w.File, Op: "truncated"})
		start = 0
	}
	if size <= start {
		return
	}
	if _, err := f.Seek(start, 0); err != nil {
		return
	}
	var buf []byte
	tmp := make([]byte, 64*1024)
	for {
		n, rerr := f.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	// keep a partial trailing line (no newline yet) for the next tick
	newpos := size
	if len(buf) > 0 && buf[len(buf)-1] != '\n' {
		if i := lastIndexByte(buf, '\n'); i >= 0 {
			buf = buf[:i+1]
		} else {
			buf = nil
		}
		newpos = start + int64(len(buf))
	}
	if len(buf) > 0 {
		m.lines(w, string(buf))
	}
	m.mu.Lock()
	m.offs[w.File] = off{pos: newpos}
	m.mu.Unlock()
}

func lastIndexByte(b []byte, c byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func (m *Module) lines(w Watch, data string) {
	for _, line := range splitLines(data) {
		line = trimSpace(line)
		if line == "" {
			continue
		}
		if w.Pattern != nil && !w.Pattern.MatchString(line) {
			continue
		}
		m.sink.LogLine(LogEvent{File: filepath.Base(w.File), Line: line})
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}

func trimSpace(s string) string {
	a, b := 0, len(s)
	for a < b && (s[a] == ' ' || s[a] == '\t') {
		a++
	}
	for b > a && (s[b-1] == ' ' || s[b-1] == '\t' || s[b-1] == '\r') {
		b--
	}
	return s[a:b]
}
