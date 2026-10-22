package decoys

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

// crlf converts shell output to terminal line endings.
func crlf(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }

var errClosedByClient = errors.New("decoys: client closed the session")

// readLine reads one line from a terminal-like stream, echoing printable input
// when echo is set and handling backspace, CR/LF and Ctrl-C/Ctrl-D. It never
// returns more than maxLineLen bytes (the rest of an over-long line is dropped).
func readLine(r *bufio.Reader, w io.Writer, echo bool) (string, error) {
	var line []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return string(line), err
		}
		switch b {
		case '\r', '\n':
			if b == '\r' {
				// swallow the LF or NUL of CRLF / CR NUL when already buffered
				if r.Buffered() > 0 {
					if nb, _ := r.Peek(1); len(nb) == 1 && (nb[0] == '\n' || nb[0] == 0) {
						_, _ = r.ReadByte()
					}
				}
			}
			if echo {
				_, _ = w.Write([]byte("\r\n"))
			}
			return string(line), nil
		case 0x03: // ^C
			if echo {
				_, _ = w.Write([]byte("^C\r\n"))
			}
			return "", nil
		case 0x04: // ^D
			if len(line) == 0 {
				return "", errClosedByClient
			}
		case 0x7f, 0x08:
			if len(line) > 0 {
				line = line[:len(line)-1]
				if echo {
					_, _ = w.Write([]byte("\b \b"))
				}
			}
		case 0x1b: // drop escape sequences (arrow keys): ESC [ x
			if nb, _ := r.Peek(2); len(nb) == 2 && nb[0] == '[' {
				_, _ = r.Discard(2)
			}
		default:
			if b < 0x20 {
				continue
			}
			if len(line) < maxLineLen {
				line = append(line, b)
				if echo {
					_, _ = w.Write([]byte{b})
				}
			}
		}
	}
}

// shellLoop runs the prompt loop over rw until exit, EOF or the command cap.
// Everything the client types is recorded and answered from the fake shell.
func (m *Module) shellLoop(s *sess, rw io.ReadWriter, sh *Shell) {
	r := bufio.NewReaderSize(rw, 4096)
	for {
		_, _ = io.WriteString(rw, sh.Prompt())
		s.idle()
		line, err := readLine(r, rw, true)
		if strings.TrimSpace(line) != "" {
			if !s.command(line) {
				_, _ = io.WriteString(rw, "Connection closed by remote host.\r\n")
				return
			}
			s.pause()
			out, exit := sh.Run(line)
			_, _ = io.WriteString(rw, crlf(out))
			if exit {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
