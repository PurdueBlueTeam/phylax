package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// EvidenceKind is what an evidence item is.
type EvidenceKind string

const (
	EvScreenshot EvidenceKind = "screenshot"
	EvLog        EvidenceKind = "log"      // a log excerpt pasted as text
	EvFile       EvidenceKind = "file"     // a collected artifact (hashed, not embedded)
	EvFirewall   EvidenceKind = "firewall" // a firewall log line or screenshot
	EvPacket     EvidenceKind = "packet"
)

// Evidence tags: which part of the report a figure supports.
const (
	TagRedActivity  = "red_activity" // shows the source IP / red-team use
	TagVuln         = "vuln"         // the vulnerable code or config
	TagDetection    = "detection"    // the alert / query that found it
	TagEradication  = "eradication"  // the command that removed their access
	TagRemediation  = "remediation"  // the fix
	TagVerification = "verification" // the failed retest / service green
	TagFirewall     = "firewall"     // a firewall log line for the connection
)

// Evidence is one figure or appendix item.
type Evidence struct {
	Kind    EvidenceKind
	Path    string // screenshot or collected file
	Host    string
	Caption string // what it proves, one line
	Taken   time.Time
	SHA256  string // computed from Path when empty and the file exists
	Excerpt string // log text (EvLog, EvFirewall, EvPacket)
	Tags    []string
	// HopLabel ties the figure to a hop ("H2" or "C1.H2") for the timeline.
	HopLabel string
	// Annotated is the operator's confirmation that arrows/boxes are drawn,
	// there is no cursor and no text is cropped. The drafter cannot see this.
	Annotated bool
}

// HasTag reports a tag.
func (e Evidence) HasTag(t string) bool {
	for _, x := range e.Tags {
		if x == t {
			return true
		}
	}
	return false
}

// Figure is an Evidence with its assigned number and resolved hash.
type Figure struct {
	Evidence
	N       int
	Missing bool // Path set but unreadable
	Caption string
	Hash    string
}

// maxHashBytes bounds a hashed file (screenshots and collected artifacts).
const maxHashBytes = 512 << 20

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxHashBytes)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// MakeFigures numbers the evidence in order, resolves hashes and builds the
// house-format captions:
//
//	Figure N: <what it proves> (<host>, taken <Central time>)
//
// Missing pieces become placeholders so the operator sees them.
func MakeFigures(ev []Evidence, baseDir string, ph func(string) string) []Figure {
	out := make([]Figure, 0, len(ev))
	for i, e := range ev {
		f := Figure{Evidence: e, N: i + 1}
		what := strings.TrimSpace(e.Caption)
		if what == "" {
			what = ph(fmt.Sprintf("caption for figure %d: what it proves", i+1))
		}
		host := e.Host
		if host == "" {
			host = ph(fmt.Sprintf("host for figure %d", i+1))
		}
		taken := Central(e.Taken)
		if taken == "" {
			taken = ph(fmt.Sprintf("time figure %d was taken", i+1))
		}
		f.Caption = fmt.Sprintf("Figure %d: %s (%s, taken %s)", f.N, what, host, taken)
		f.Hash = e.SHA256
		if e.Path != "" {
			full := e.Path
			if !filepath.IsAbs(full) && baseDir != "" {
				full = filepath.Join(baseDir, full)
			}
			if f.Hash == "" {
				h, err := hashFile(full)
				if err != nil {
					f.Missing = true
				} else {
					f.Hash = h
				}
			}
		} else if e.Excerpt != "" && f.Hash == "" {
			s := sha256.Sum256([]byte(e.Excerpt))
			f.Hash = hex.EncodeToString(s[:])
		}
		out = append(out, f)
	}
	return out
}
