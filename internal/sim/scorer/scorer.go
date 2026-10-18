// Package scorer is the scorer simulator: it performs the same checks a
// CTF scorer performs (HTTP/HTTPS content, SMTP-then-POP3, DNS, FTP, TFTP,
// NTP) from configurable source addresses, on an interval with jitter, and
// writes its own ground truth so check discovery can be tested against
// known answers (lab tests T14, T15).
//
// v0 (M0): HTTP/HTTPS content checks plus the ground-truth writer. v1 (M4)
// adds the remaining protocols, mid-run check add/change, and the
// round-participation / rhythm signals discovery uses.
//
// The simulator is strictly passive toward anything but its targets: it
// only performs the declared checks, like a real scorer.
package scorer

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Check is one scorer check.
type Check struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"` // http, https (v0); smtp_pop3, dns, ftp, tftp, ntp (v1)
	Target string `json:"target"`
	Path   string `json:"path,omitempty"`
	// ExpectFile points at a file whose content the response body must
	// match after normalization (v0: exact match on the raw body).
	ExpectFile string `json:"expect_file,omitempty"`
}

// Config drives a simulator run.
type Config struct {
	Checks      []Check `json:"checks"`
	Interval    time.Duration
	Jitter      time.Duration
	// Sources are the source addresses to rotate over. Empty = ephemeral
	// local addresses (the test harness binds a named socket per source
	// when it wants stable addresses).
	Sources []string
	// ClientUA is the User-Agent sent; part of the fingerprint ground truth
	// records so discovery can learn the scorer's client fingerprint.
	ClientUA string
	// Out is the ground-truth JSONL path.
	Out string
}

// Truth is one ground-truth record: what the simulator did, when, and what
// the scorer would have scored.
type Truth struct {
	Check       string    `json:"check"`
	Kind        string    `json:"kind"`
	Target      string    `json:"target"`
	Path        string    `json:"path,omitempty"`
	Started     time.Time `json:"started"`
	Finished    time.Time `json:"finished"`
	Source      string    `json:"source"`
	ClientFp    string    `json:"client_fp"`
	ExpectSHA256 string   `json:"expect_sha256,omitempty"`
	GotSHA256   string    `json:"got_sha256,omitempty"`
	Status      int       `json:"status,omitempty"`
	Pass        bool      `json:"pass"`
	Error       string    `json:"error,omitempty"`
}

// Run executes the checks on schedule until ctx is done, writing truth
// records to c.Out (JSONL, append). It returns the number of checks written.
func Run(ctx context.Context, c Config) (int, error) {
	if c.Interval <= 0 {
		c.Interval = 30 * time.Second
	}
	if c.ClientUA == "" {
		c.ClientUA = "phylax-scorer-sim/0.1"
	}
	truth, err := os.OpenFile(c.Out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return 0, fmt.Errorf("scorer: truth file: %w", err)
	}
	defer truth.Close()

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}
	fp := fingerprint(c.ClientUA)

	n := 0
	for {
		for i, ch := range c.Checks {
			if ctx.Err() != nil {
				return n, nil
			}
			src := ""
			if len(c.Sources) > 0 {
				src = c.Sources[i%len(c.Sources)]
			}
			t := Truth{Check: ch.ID, Kind: ch.Kind, Target: ch.Target, Path: ch.Path,
				Started: time.Now().UTC(), Source: src, ClientFp: fp}
			pass, err := runCheck(ctx, client, ch, &t)
			t.Finished = time.Now().UTC()
			t.Pass = pass
			if err != nil {
				t.Error = err.Error()
			}
			line, _ := json.Marshal(t)
			if _, werr := truth.Write(append(line, '\n')); werr != nil {
				return n, fmt.Errorf("scorer: truth write: %w", werr)
			}
			n++
			d := c.Interval + jitter(c.Jitter, t.Started.UnixNano(), ch.ID)
			if d > 0 {
				select {
				case <-time.After(d):
				case <-ctx.Done():
					return n, nil
				}
			}
		}
	}
}

func runCheck(ctx context.Context, client *http.Client, ch Check, t *Truth) (bool, error) {
	switch ch.Kind {
	case "http", "https":
		url := ch.Target
		if !strings.Contains(url, "://") {
			scheme := "http"
			if ch.Kind == "https" {
				scheme = "https"
			}
			url = scheme + "://" + url
		}
		if ch.Path != "" {
			url += ch.Path
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return false, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		if err != nil {
			return false, err
		}
		t.Status = resp.StatusCode
		t.GotSHA256 = sha256hex(body)
		if resp.StatusCode != 200 {
			return false, fmt.Errorf("status %d", resp.StatusCode)
		}
		if ch.ExpectFile != "" {
			want, err := os.ReadFile(ch.ExpectFile)
			if err != nil {
				return false, fmt.Errorf("expect file: %w", err)
			}
			t.ExpectSHA256 = sha256hex(want)
			return strings.TrimSpace(string(body)) == strings.TrimSpace(string(want)), nil
		}
		return true, nil
	default:
		return false, fmt.Errorf("scorer: kind %q not implemented in v0", ch.Kind)
	}
}

// fingerprint is the client fingerprint the ground truth records: a stable
// hash of the user agent and the TLS stack markers a passive observer sees.
func fingerprint(ua string) string {
	h := fnv.New64a()
	io.WriteString(h, ua)
	io.WriteString(h, "go-http/1.1")
	return strconv.FormatUint(h.Sum64(), 16)
}

func jitter(base time.Duration, seed int64, id string) time.Duration {
	if base <= 0 {
		return 0
	}
	h := fnv.New64a()
	io.WriteString(h, id)
	_, _ = h.Write([]byte(strconv.FormatInt(seed, 10)))
	return time.Duration(int64(h.Sum64()%uint64(base)))
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum)
}
