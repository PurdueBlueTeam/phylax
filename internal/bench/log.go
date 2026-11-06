package bench

import (
	"os"
	"sync"
	"time"
)

// readMaxLine bounds one line ReadFiles reads into memory: a longer line is an
// error naming the file, never an unbounded allocation.
const readMaxLine = 1 << 20

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
	panic("unimplemented: W14 Task 3")
}

// Write appends r as one line, rotating first when the line would pass the
// size bound.
func (l *Log) Write(r Record) error {
	panic("unimplemented: W14 Task 3")
}

// Close closes the file; a later Write returns an error.
func (l *Log) Close() error {
	panic("unimplemented: W14 Task 3")
}

// AppendMark appends one mark record named name at now to the 1 MiB capped
// file at path.
func AppendMark(path, name string, now time.Time) error {
	panic("unimplemented: W14 Task 3")
}

// ReadFiles reads path and then path+".1" for each path, skips a missing file,
// and returns the records sorted by time. An unparsable last line of a file is
// skipped (the controller can die mid-line); an unparsable earlier line and a
// line over 1 MiB are errors.
func ReadFiles(paths ...string) ([]Record, error) {
	panic("unimplemented: W14 Task 3")
}
