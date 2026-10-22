// Package lines splits a byte stream into CRLF/LF terminated lines with a hard
// bound on buffering, for the text protocols (FTP, SMTP, IMAP, POP3).
package lines

// MaxLine is the longest line kept; longer lines are truncated to this length
// (the rest is discarded up to the terminator) and reported with long=true.
const MaxLine = 4096

// Splitter accumulates bytes and yields complete lines.
type Splitter struct {
	buf      []byte
	skipping bool
	long     bool
}

// Write feeds bytes; fn is called for each complete line without its
// terminator. long is true when the line exceeded MaxLine and was truncated.
// If fn returns false, splitting stops and Write returns the number of input
// bytes consumed so the caller can treat the remainder as raw data.
func (s *Splitter) Write(b []byte, fn func(line []byte, long bool) bool) (consumed int) {
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c == '\n' {
			line := s.buf
			if n := len(line); n > 0 && line[n-1] == '\r' {
				line = line[:n-1]
			}
			long := s.long
			cont := fn(line, long)
			s.buf = s.buf[:0]
			s.skipping, s.long = false, false
			if !cont {
				return i + 1
			}
			continue
		}
		if s.skipping {
			continue
		}
		if len(s.buf) >= MaxLine {
			s.skipping, s.long = true, true
			continue
		}
		s.buf = append(s.buf, c)
	}
	return len(b)
}

// Pending reports bytes of an unterminated line currently held.
func (s *Splitter) Pending() int { return len(s.buf) }

// Reset drops partial state.
func (s *Splitter) Reset() { s.buf, s.skipping, s.long = s.buf[:0], false, false }
