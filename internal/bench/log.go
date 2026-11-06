package bench

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"
)

// readMaxLine bounds one line ReadFiles reads into memory: a longer line is an
// error naming the file, never an unbounded allocation.
const readMaxLine = 1 << 20

// markMaxBytes caps a marks file. Marks are one tiny record each, so 1 MiB
// holds a whole competition's worth even with a mark per load phase.
const markMaxBytes = 1 << 20

// Log is the bench's bounded JSONL file: one Record per line, appended under a
// mutex. When the next line would pass maxBytes the file is rotated to
// <path>.1 (replacing any older one), so the pair never holds more than
// 2*maxBytes; a single line larger than maxBytes is still written alone.
type Log struct {
	path     string
	maxBytes int64
	file     *os.File
	size     int64
	mu       sync.Mutex
}

// OpenLog opens path for appending (creating it mode 0600) and takes its
// current size as the rotation base.
func OpenLog(path string, maxBytes int64) (*Log, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("bench: log size bound must be positive, got %d", maxBytes)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("bench: open log: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("bench: stat log: %w", err)
	}
	return &Log{path: path, maxBytes: maxBytes, file: f, size: st.Size()}, nil
}

// Write appends r as one line, rotating first when the line would pass the
// size bound. Times are stored as UTC.
func (l *Log) Write(r Record) error {
	r.T = r.T.UTC()
	line, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("bench: encode record: %w", err)
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return os.ErrClosed
	}
	if l.size > 0 && l.size+int64(len(line)) > l.maxBytes {
		if err := l.rotate(); err != nil {
			return err
		}
	}
	n, err := l.file.Write(line)
	l.size += int64(n)
	if err != nil {
		return fmt.Errorf("bench: write log: %w", err)
	}
	return nil
}

// rotate closes the current file, renames it to <path>.1 and opens a fresh one.
// The log stays usable (with no file) if any step fails.
func (l *Log) rotate() error {
	if err := l.file.Close(); err != nil {
		l.file = nil
		return fmt.Errorf("bench: rotate log: %w", err)
	}
	l.file = nil
	if err := os.Rename(l.path, l.path+".1"); err != nil {
		return fmt.Errorf("bench: rotate log: %w", err)
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("bench: reopen log: %w", err)
	}
	l.file, l.size = f, 0
	return nil
}

// Close closes the file; a later Write returns an error.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	if err != nil {
		return fmt.Errorf("bench: close log: %w", err)
	}
	return nil
}

// AppendMark appends one mark record named name at now to the 1 MiB capped
// file at path.
func AppendMark(path, name string, now time.Time) error {
	l, err := OpenLog(path, markMaxBytes)
	if err != nil {
		return err
	}
	if err := l.Write(Record{T: now, Kind: KindMark, Mark: name}); err != nil {
		l.Close()
		return err
	}
	return l.Close()
}

// ReadFiles reads path+".1" and then path for each path, skips a missing file,
// and returns the records sorted by time. An unparsable last line of a file is
// skipped (the controller can die mid-line); an unparsable earlier line and a
// line over 1 MiB are errors.
func ReadFiles(paths ...string) ([]Record, error) {
	var all []Record
	for _, p := range paths {
		for _, f := range []string{p + ".1", p} {
			recs, err := readFile(f)
			if err != nil {
				return nil, err
			}
			all = append(all, recs...)
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].T.Before(all[j].T) })
	return all, nil
}

// readFile reads one JSONL file within the line bound. A line that does not
// parse is remembered and only skipped when it turns out to be the file's last
// line: anywhere earlier it is an error.
func readFile(path string) ([]Record, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("bench: read log: %w", err)
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, readMaxLine)
	var (
		out  []Record
		torn error
		last bool
	)
	for !last {
		chunk, err := br.ReadSlice('\n')
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			return nil, fmt.Errorf("%s: line over %d bytes", path, readMaxLine)
		case errors.Is(err, io.EOF):
			last = true
		case err != nil:
			return nil, fmt.Errorf("bench: read log: %w", err)
		}
		line := bytes.TrimSpace(chunk)
		if len(line) == 0 {
			continue
		}
		if torn != nil {
			return nil, torn
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			torn = fmt.Errorf("%s: %w", path, err)
			continue
		}
		out = append(out, r)
	}
	return out, nil
}
