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
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Check is one scorer check.
type Check struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"` // http, https, smtp_pop3, dns, ftp, tftp, ntp
	Target string `json:"target"`
	Path   string `json:"path,omitempty"` // https path; dns name; tftp file
	// User is the account the check authenticates as (smtp_pop3 pop3
	// user, ftp user). Pop3Users rotates it per round (docs: rotating
	// POP3 users).
	User      string   `json:"user,omitempty"`
	Pop3Users []string `json:"pop3_users,omitempty"`
	// ExpectFile points at a file whose content the response body must
	// match after normalization (v0: exact match on the raw body).
	ExpectFile string `json:"expect_file,omitempty"`
}

// Config drives a simulator run.
type Config struct {
	Checks   []Check `json:"checks"` // v0: run every round
	Plan     [][]Check
	Interval time.Duration
	Jitter   time.Duration
	// Sources are the source addresses to rotate over. Empty = ephemeral
	// local addresses (the test harness binds a named socket per source
	// when it wants stable addresses).
	Sources []string
	// ClientUA is the User-Agent sent; part of the fingerprint ground truth
	// records so discovery can learn the scorer's client fingerprint.
	ClientUA string
	// Out is the ground-truth JSONL path.
	Out string
	// RoundDone is called with the 1-based round number after each round's
	// checks complete (the T15 E2E flushes captured requests and ticks the
	// discovery round at this boundary).
	RoundDone func(round int)
}

// Truth is one ground-truth record: what the simulator did, when, and what
// the scorer would have scored.
type Truth struct {
	Check        string    `json:"check"`
	Kind         string    `json:"kind"`
	Target       string    `json:"target"`
	Path         string    `json:"path,omitempty"`
	Started      time.Time `json:"started"`
	Finished     time.Time `json:"finished"`
	Source       string    `json:"source"`
	ClientFp     string    `json:"client_fp"`
	ExpectSHA256 string    `json:"expect_sha256,omitempty"`
	GotSHA256    string    `json:"got_sha256,omitempty"`
	Status       int       `json:"status,omitempty"`
	Pass         bool      `json:"pass"`
	Error        string    `json:"error,omitempty"`
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
	round := 0
	for {
		if ctx.Err() != nil {
			return n, nil
		}
		round++
		roundChecks := []Check(nil)
		if len(c.Plan) > 0 {
			if round <= len(c.Plan) {
				roundChecks = c.Plan[round-1]
			} else {
				roundChecks = c.Plan[len(c.Plan)-1]
			}
		}
		if len(roundChecks) == 0 {
			roundChecks = c.Checks
		}
		for i, ch := range roundChecks {
			if ctx.Err() != nil {
				return n, nil
			}
			src := ""
			if len(c.Sources) > 0 {
				src = c.Sources[i%len(c.Sources)]
			}
			// rotating POP3 user: a different account each round (docs:
			// rotating POP3 users become one check with a set of values)
			if ch.Kind == "smtp_pop3" && len(ch.Pop3Users) > 0 {
				ch.User = ch.Pop3Users[(round-1)%len(ch.Pop3Users)]
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
			if i < len(roundChecks)-1 {
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
		if c.RoundDone != nil {
			c.RoundDone(round)
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
	case "smtp_pop3":
		return runMailCheck(ctx, ch)
	case "dns":
		return runDNSCheck(ctx, ch)
	case "ftp":
		return runFTPCheck(ctx, ch)
	case "tftp":
		return runTFTPCheck(ctx, ch)
	case "ntp":
		return runNTPCheck(ctx, ch)
	default:
		return false, fmt.Errorf("scorer: kind %q not implemented", ch.Kind)
	}
}

func lineOK(line, prefix string) bool {
	return strings.HasPrefix(line, prefix)
}

// runMailCheck performs the scorer's mail check: queue one message via
// SMTP, then fetch it via POP3 as the check's user.
func runMailCheck(ctx context.Context, ch Check) (bool, error) {
	smtpC, err := net.DialTimeout("tcp", ch.Target, 5*time.Second)
	if err != nil {
		return false, err
	}
	defer smtpC.Close()
	rl := newBufReader(smtpC)
	if l, _ := rl.ReadString('\n'); !lineOK(l, "220") {
		return false, fmt.Errorf("smtp greeting %q", l)
	}
	user := ch.User
	if user == "" {
		user = "scoreruser"
	}
	// EHLO: drain the (possibly multi-line) reply
	smtpC.Write([]byte("EHLO scorer.phylax.test\r\n"))
	for {
		l, _ := rl.ReadString('\n')
		if lineOK(l, "250 ") {
			break
		}
		if !lineOK(l, "250") {
			return false, fmt.Errorf("smtp ehlo -> %q", l)
		}
	}
	for _, cmd := range []string{
		"MAIL FROM:<scorer@phylax.test>",
		"RCPT TO:<" + user + "@phylax.test>",
		"DATA",
	} {
		smtpC.Write([]byte(cmd + "\r\n"))
		l, _ := rl.ReadString('\n')
		want := "250"
		if cmd == "DATA" {
			want = "354"
		}
		if !lineOK(l, want) {
			// a server that answers "250 OK" to DATA (no body queued)
			// is accepted: the POP3 leg is what the check scores
			if cmd == "DATA" && lineOK(l, "250") {
				continue
			}
			return false, fmt.Errorf("smtp %q -> %q", cmd, l)
		}
		if cmd == "DATA" {
			smtpC.Write([]byte("Subject: scorer check\r\n\r\n.\r\n"))
			if l, _ := rl.ReadString('\n'); !lineOK(l, "250") {
				return false, fmt.Errorf("smtp data -> %q", l)
			}
		}
	}
	smtpC.Write([]byte("QUIT\r\n"))

	pop3 := ch.Target
	if ch.Path != "" {
		pop3 = ch.Path
	}
	p3, err := net.DialTimeout("tcp", pop3, 5*time.Second)
	if err != nil {
		return false, err
	}
	defer p3.Close()
	prl := newBufReader(p3)
	if l, _ := prl.ReadString('\n'); !lineOK(l, "+OK") {
		return false, fmt.Errorf("pop3 greeting %q", l)
	}
	p3.Write([]byte("USER " + user + "\r\n"))
	if l, _ := prl.ReadString('\n'); !lineOK(l, "+OK") {
		return false, fmt.Errorf("pop3 user -> %q", l)
	}
	p3.Write([]byte("RETR 1\r\n"))
	if l, _ := prl.ReadString('\n'); !lineOK(l, "+OK") {
		return false, fmt.Errorf("pop3 retr -> %q", l)
	}
	for {
		l, err := prl.ReadString('\n')
		if err != nil {
			return false, err
		}
		if strings.TrimSpace(l) == "." {
			break
		}
	}
	p3.Write([]byte("QUIT\r\n"))
	return true, nil
}

// runDNSCheck resolves the check's name and expects an answer.
func runDNSCheck(ctx context.Context, ch Check) (bool, error) {
	name := ch.Path
	if name == "" {
		name = "svc.phylax.test"
	}
	q := dnsQuery(name, 1)
	pc, err := net.DialTimeout("udp", ch.Target, 5*time.Second)
	if err != nil {
		return false, err
	}
	defer pc.Close()
	if err := pc.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return false, err
	}
	if _, err := pc.Write(q); err != nil {
		return false, err
	}
	buf := make([]byte, 512)
	n, err := pc.Read(buf)
	if err != nil {
		return false, err
	}
	if n < 16 {
		return false, fmt.Errorf("dns: short reply")
	}
	// answcount at 6:2
	return binary.BigEndian.Uint16(buf[6:8]) > 0, nil
}

// runFTPCheck logs in and lists.
func runFTPCheck(ctx context.Context, ch Check) (bool, error) {
	c, err := net.DialTimeout("tcp", ch.Target, 5*time.Second)
	if err != nil {
		return false, err
	}
	defer c.Close()
	rl := newBufReader(c)
	if l, _ := rl.ReadString('\n'); !lineOK(l, "220") {
		return false, fmt.Errorf("ftp greeting %q", l)
	}
	user := ch.User
	if user == "" {
		user = "ftpuser"
	}
	for _, cmd := range []string{"USER " + user, "PASS scorer"} {
		c.Write([]byte(cmd + "\r\n"))
		if l, _ := rl.ReadString('\n'); !lineOK(l, "331") && !lineOK(l, "230") {
			return false, fmt.Errorf("ftp %q -> %q", cmd, l)
		}
	}
	c.Write([]byte("LIST\r\n"))
	if l, _ := rl.ReadString('\n'); !lineOK(l, "150") {
		return false, fmt.Errorf("ftp list -> %q", l)
	}
	if l, _ := rl.ReadString('\n'); !lineOK(l, "226") {
		return false, fmt.Errorf("ftp list done -> %q", l)
	}
	c.Write([]byte("QUIT\r\n"))
	return true, nil
}

// runTFTPCheck issues an RRQ and reads the file.
func runTFTPCheck(ctx context.Context, ch Check) (bool, error) {
	file := ch.Path
	if file == "" {
		file = "file.dat"
	}
	req := append([]byte{0, 1}, append([]byte(file), 0)...)
	req = append(req, []byte("octet\x00")...)
	pc, err := net.DialTimeout("udp", ch.Target, 5*time.Second)
	if err != nil {
		return false, err
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := pc.Write(req); err != nil {
		return false, err
	}
	buf := make([]byte, 516)
	var got []byte
	for block := 1; ; block++ {
		n, err := pc.Read(buf)
		if err != nil {
			return false, err
		}
		if n < 4 || buf[0] != 0 || buf[1] != 3 {
			return false, fmt.Errorf("tftp: not a data packet")
		}
		if binary.BigEndian.Uint16(buf[2:4]) != uint16(block) {
			return false, fmt.Errorf("tftp: block %d, want %d", block, binary.BigEndian.Uint16(buf[2:4]))
		}
		got = append(got, buf[4:n]...)
		pc.Write([]byte{0, 4, byte(block >> 8), byte(block)})
		if n-4 < 512 {
			break
		}
	}
	return len(got) > 0, nil
}

// runNTPCheck sends a mode-3 query and expects a mode-4 reply.
func runNTPCheck(ctx context.Context, ch Check) (bool, error) {
	q := make([]byte, 48)
	q[0] = 0x1b // LI=0 VN=3 mode=3 (client)
	pc, err := net.DialTimeout("udp", ch.Target, 5*time.Second)
	if err != nil {
		return false, err
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := pc.Write(q); err != nil {
		return false, err
	}
	buf := make([]byte, 48)
	n, err := pc.Read(buf)
	if err != nil {
		return false, err
	}
	if n < 48 || buf[0]&0x07 != 4 {
		return false, fmt.Errorf("ntp: bad reply")
	}
	return true, nil
}

func newBufReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }

// dnsQuery builds a minimal A query for name.
func dnsQuery(name string, qtype uint16) []byte {
	b := []byte{0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = append(b, byte(qtype>>8), byte(qtype), 0, 1)
	return b
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
	return time.Duration(int64(h.Sum64() % uint64(base)))
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum)
}
