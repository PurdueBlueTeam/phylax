// Package checks is the probe library shared by the in-LAN check_runner and
// the Kali vantage point. Each probe reproduces the client behaviour of
// Quotient (the competition scorer) for one check type, byte for byte where
// that is observable, so "the probe is green" means "the scorer would pass".
//
// Two verdicts are computed. ScorerOK is what Quotient would conclude,
// including its blind spots (a web check with no status or regex passes on a
// 500; an MX DNS check can never pass). In Strict mode StrictOK is also
// computed: status, regex, file hash and MX are all verified, and Result.OK
// follows the strict verdict. Evidence: research/topics/quotient.md section 2.
//
// Nothing here scans: a probe talks to exactly the Host in its Spec. The
// caller (internal/vantage) enforces which hosts may be targeted.
package checks

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

// Type names a check type.
type Type string

// Check types.
const (
	HTTP   Type = "http"
	HTTPS  Type = "https"
	DNS    Type = "dns"
	Ping   Type = "ping"
	TCP    Type = "tcp"
	RDP    Type = "rdp"
	SSH    Type = "ssh"
	FTP    Type = "ftp"
	SMB    Type = "smb"
	SMTP   Type = "smtp"
	IMAP   Type = "imap"
	POP3   Type = "pop3"
	WinRM  Type = "winrm"
	LDAP   Type = "ldap"
	MSSQL  Type = "mssql"
	Splunk Type = "splunk"
)

// Types lists every supported type.
func Types() []Type {
	return []Type{HTTP, HTTPS, DNS, Ping, TCP, RDP, SSH, FTP, SMB, SMTP, IMAP, POP3, WinRM, LDAP, MSSQL, Splunk}
}

// NeedsCreds reports whether the type authenticates with a credential.
func (t Type) NeedsCreds() bool {
	switch t {
	case SSH, WinRM, LDAP, MSSQL, Splunk:
		return true
	}
	return false
}

// DefaultPort returns the type's usual port (0 for ping).
func (t Type) DefaultPort(encrypted bool) int {
	switch t {
	case HTTP:
		return 80
	case HTTPS:
		return 443
	case DNS:
		return 53
	case RDP:
		return 3389
	case SSH:
		return 22
	case FTP:
		return 21
	case SMB:
		return 445
	case SMTP:
		if encrypted {
			return 465
		}
		return 25
	case IMAP:
		if encrypted {
			return 993
		}
		return 143
	case POP3:
		if encrypted {
			return 995
		}
		return 110
	case WinRM:
		if encrypted {
			return 5986
		}
		return 5985
	case LDAP:
		if encrypted {
			return 636
		}
		return 389
	case MSSQL:
		return 1433
	case Splunk:
		return 8089
	}
	return 0
}

// Cred is one scored credential. The password never appears in a Result.
type Cred struct {
	User string
	Pass vault.Secret
}

// Item is one thing a check can ask for; which fields apply depends on the type.
type Item struct {
	// Web
	Path   string // default "/"
	Status int    // 0 = not checked (Quotient: any response passes)
	Regex  string // web body, ftp/smb file content
	// DNS
	Name    string
	Kind    string   // "A" or "MX"
	Answers []string // expected addresses (A) or exchanges (MX)
	// SSH / WinRM / SQL
	Command  string // ssh typed command, winrm command (default hostname)
	Output   string // expected output
	Contains bool   // ssh: stdout contains Output
	UseRegex bool   // ssh/winrm/sql: Output is a regex
	Query    string // mssql / splunk search
	// FTP / SMB
	File   string
	Share  string // smb
	SHA256 string // hex, case-insensitive
}

// Label is a short, credential-free description of the item for logs.
func (i Item) Label() string {
	switch {
	case i.Name != "":
		return i.Kind + " " + i.Name
	case i.File != "":
		if i.Share != "" {
			return i.Share + `\` + i.File
		}
		return i.File
	case i.Path != "":
		return i.Path
	case i.Command != "":
		return i.Command
	case i.Query != "":
		return i.Query
	}
	return ""
}

// Spec is one check against one address.
type Spec struct {
	ID          string
	Type        Type
	Host        string // the address probed; the caller vets it
	Port        int    // 0 = type default
	Encrypted   bool   // implicit TLS (smtp/imap/pop3/ldap) or https-style winrm/splunk
	Domain      string // appended as user@Domain (smtp/imap/ldap/ssh); empty = bare
	RequireAuth bool   // smtp: authenticate even if AUTH is not advertised
	Items       []Item // the learned item union; empty = one itemless run
	Creds       []Cred // the learned credential union
}

func (s Spec) port() int {
	if s.Port > 0 {
		return s.Port
	}
	return s.Type.DefaultPort(s.Encrypted)
}

func (s Spec) addr() string { return net.JoinHostPort(s.Host, strconv.Itoa(s.port())) }

// Options tune a run.
type Options struct {
	Timeout     time.Duration // per probe, default 10s (the scorer's Delay/2 is typical)
	Strict      bool
	BadAttempts int // ssh: failed logins before the real one; off (0) by default
	// Dial overrides the network dialer (tests, source binding).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	Rand *mrand.Rand // sampling and banner choice; default is randomly seeded
	// Sleep is used for the SSH Timeout/8 wait; default honours ctx.
	Sleep func(ctx context.Context, d time.Duration)
}

func (o Options) timeout() time.Duration {
	if o.Timeout <= 0 {
		return 10 * time.Second
	}
	return o.Timeout
}

func (o Options) rng() *mrand.Rand {
	if o.Rand != nil {
		return o.Rand
	}
	return mrand.New(mrand.NewPCG(cryptoSeed(), cryptoSeed()))
}

func cryptoSeed() uint64 {
	n, err := rand.Int(rand.Reader, new(big.Int).SetUint64(^uint64(0)>>1))
	if err != nil {
		return uint64(time.Now().UnixNano())
	}
	return n.Uint64()
}

// Class says why a probe failed, so "service unhealthy" and "scorer would
// fail on content" stay separate.
type Class string

// Failure classes.
const (
	ClassOK          Class = ""
	ClassUnreachable Class = "unreachable" // refused, reset, no route, DNS error
	ClassTimeout     Class = "timeout"
	ClassAuth        Class = "auth" // login refused
	ClassProtocol    Class = "protocol"
	ClassContent     Class = "content"      // status / regex / hash / output mismatch
	ClassScorerLimit Class = "scorer_limit" // Quotient cannot pass this regardless of the service (MX)
	ClassConfig      Class = "config"       // the spec is unusable (no credential, bad regex)
)

// Result is the typed outcome of one probe.
type Result struct {
	ID     string
	Type   Type
	Host   string
	Port   int
	Item   string // Item.Label
	User   string
	Mode   string // "faithful", "sweep", "auth"
	Strict bool
	OK     bool // the verdict for this mode (strict verdict when Strict)
	// ScorerOK is what Quotient would conclude. StrictOK equals ScorerOK
	// unless Strict was requested.
	ScorerOK     bool
	StrictOK     bool
	Class        Class
	Err          string   // short, scorer-style, credential-free
	StrictIssues []string // reasons StrictOK is false while ScorerOK is true
	Debug        string
	Start        time.Time
	Elapsed      time.Duration
	Steps        []Step // timing of protocol phases
}

// Step is one timed phase of a probe.
type Step struct {
	Name    string
	Elapsed time.Duration
}

// failure is the error type probes return for a hard failure.
type failure struct {
	class Class
	msg   string
	debug string
}

func (f *failure) Error() string { return f.msg }

func fail(class Class, format string, a ...any) error {
	return &failure{class: class, msg: fmt.Sprintf(format, a...)}
}

func failDebug(class Class, debug, format string, a ...any) error {
	return &failure{class: class, msg: fmt.Sprintf(format, a...), debug: debug}
}

// probe is the working state of one run.
type probe struct {
	spec   Spec
	item   Item
	hasIt  bool
	cred   Cred
	hasCr  bool
	opts   Options
	rng    *mrand.Rand
	res    *Result
	limit  string
	last   time.Time
	issues []string
}

func (p *probe) strict() bool { return p.opts.Strict }

// strictIssue records a strict-only failure.
func (p *probe) strictIssue(format string, a ...any) {
	if p.opts.Strict {
		p.issues = append(p.issues, fmt.Sprintf(format, a...))
	}
}

// scorerLimit marks a check Quotient itself cannot pass.
func (p *probe) scorerLimit(msg string) { p.limit = msg }

func (p *probe) step(name string) {
	now := time.Now()
	p.res.Steps = append(p.res.Steps, Step{name, now.Sub(p.last)})
	p.last = now
}

func (p *probe) userAt() string {
	if p.spec.Domain != "" && !strings.Contains(p.cred.User, "@") {
		return p.cred.User + "@" + p.spec.Domain
	}
	return p.cred.User
}

func (p *probe) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return p.dialWithin(ctx, 0, network, addr)
}

// dialWithin dials with its own connect timeout (0 = the probe's) while the
// connection itself lives as long as ctx.
func (p *probe) dialWithin(ctx context.Context, connect time.Duration, network, addr string) (net.Conn, error) {
	var c net.Conn
	var err error
	dctx := ctx
	if connect > 0 {
		var cancel context.CancelFunc
		dctx, cancel = context.WithTimeout(ctx, connect)
		defer cancel()
	}
	if p.opts.Dial != nil {
		c, err = p.opts.Dial(dctx, network, addr)
	} else {
		var d net.Dialer
		c, err = d.DialContext(dctx, network, addr)
	}
	if err != nil {
		return nil, classify(err, "connection error")
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	// Close on cancellation so a blocked read cannot outlive the probe.
	go func() { <-ctx.Done(); _ = c.Close() }()
	return c, nil
}

func (p *probe) dialSpec(ctx context.Context) (net.Conn, error) {
	return p.dial(ctx, "tcp", p.spec.addr())
}

func classify(err error, what string) error {
	if err == nil {
		return nil
	}
	var f *failure
	if errors.As(err, &f) {
		return f
	}
	var ne net.Error
	cls := ClassUnreachable
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		cls = ClassTimeout
	}
	return &failure{class: cls, msg: what, debug: err.Error()}
}

type probeFunc func(ctx context.Context, p *probe) error

var probes = map[Type]probeFunc{
	HTTP: probeWeb, HTTPS: probeWeb, DNS: probeDNS, Ping: probePing, TCP: probeTCP, RDP: probeRDP,
	SSH: probeSSH, FTP: probeFTP, SMB: probeSMB, SMTP: probeSMTP, IMAP: probeIMAP, POP3: probePOP3,
	WinRM: probeWinRM, LDAP: probeLDAP, MSSQL: probeMSSQL, Splunk: probeSplunk,
}

// Run executes one probe with an explicit item and credential (either may be
// nil). It always returns; ctx and Options.Timeout bound it.
func Run(ctx context.Context, spec Spec, item *Item, cred *Cred, opts Options) Result {
	res := Result{ID: spec.ID, Type: spec.Type, Host: spec.Host, Port: spec.port(), Strict: opts.Strict, Start: time.Now()}
	p := &probe{spec: spec, opts: opts, rng: opts.rng(), res: &res, last: res.Start}
	if item != nil {
		p.item, p.hasIt = *item, true
		res.Item = item.Label()
	}
	if cred != nil {
		p.cred, p.hasCr = *cred, true
		res.User = cred.User
	}
	fn := probes[spec.Type]
	var err error
	if fn == nil {
		err = fail(ClassConfig, "unknown check type %q", spec.Type)
	} else {
		cctx, cancel := context.WithTimeout(ctx, opts.timeout())
		func() {
			defer func() {
				if r := recover(); r != nil {
					err = fail(ClassProtocol, "probe panicked: %v", r)
				}
			}()
			err = fn(cctx, p)
		}()
		if err != nil && cctx.Err() != nil && ctx.Err() == nil {
			var f *failure
			if !errors.As(err, &f) || f.class == ClassUnreachable || f.class == ClassProtocol {
				err = &failure{class: ClassTimeout, msg: "check timeout exceeded", debug: err.Error()}
			}
		}
		cancel()
	}
	res.Elapsed = time.Since(res.Start)
	strictBase := false
	switch {
	case err != nil:
		var f *failure
		if !errors.As(err, &f) {
			f = &failure{class: ClassProtocol, msg: err.Error()}
		}
		res.Class, res.Err, res.Debug = f.class, f.msg, f.debug
	case p.limit != "":
		// Quotient cannot pass this regardless of the service; strict mode
		// judges the service on its merits.
		res.Class, res.Err = ClassScorerLimit, p.limit
		strictBase = opts.Strict
	default:
		res.ScorerOK, strictBase = true, true
	}
	res.StrictOK = strictBase && len(p.issues) == 0
	finish(&res, p)
	if opts.Strict {
		res.OK = res.StrictOK
	} else {
		res.OK = res.ScorerOK
	}
	return res
}

func finish(res *Result, p *probe) {
	res.StrictIssues = p.issues
	if p.hasCr {
		res.Err = vault.RedactString(res.Err, p.cred.Pass)
		res.Debug = vault.RedactString(res.Debug, p.cred.Pass)
	}
	if len(res.Debug) > 2048 {
		res.Debug = res.Debug[:2048]
	}
}

// Faithful runs one probe the way the scorer does in a round: one uniformly
// random item and one uniformly random credential from the learned unions.
func Faithful(ctx context.Context, spec Spec, opts Options) Result {
	rng := opts.rng()
	opts.Rand = rng
	item, cred := pick(rng, spec)
	r := Run(ctx, spec, item, cred, opts)
	r.Mode = "faithful"
	return r
}

// Sweep probes every learned item (each with a random credential), one after
// another, so one broken item cannot hide behind random sampling. gap is the
// pause between probes (the caller's rate limit).
func Sweep(ctx context.Context, spec Spec, opts Options, gap time.Duration) []Result {
	rng := opts.rng()
	opts.Rand = rng
	items := spec.Items
	var out []Result
	n := max(1, len(items))
	for i := range n {
		if ctx.Err() != nil {
			break
		}
		var it *Item
		if len(items) > 0 {
			it = &items[i]
		}
		var cr *Cred
		if len(spec.Creds) > 0 {
			cr = &spec.Creds[rng.IntN(len(spec.Creds))]
		}
		r := Run(ctx, spec, it, cr, opts)
		r.Mode = "sweep"
		out = append(out, r)
		if gap > 0 && i < n-1 {
			select {
			case <-ctx.Done():
			case <-time.After(gap):
			}
		}
	}
	return out
}

// AuthOnly logs in with one credential and asks for no item: the PCR
// verification probe.
func AuthOnly(ctx context.Context, spec Spec, cred Cred, opts Options) Result {
	spec.Items = nil
	r := Run(ctx, spec, nil, &cred, opts)
	r.Mode = "auth"
	return r
}

func pick(rng *mrand.Rand, spec Spec) (*Item, *Cred) {
	var it *Item
	var cr *Cred
	if len(spec.Items) > 0 {
		it = &spec.Items[rng.IntN(len(spec.Items))]
	}
	if len(spec.Creds) > 0 {
		cr = &spec.Creds[rng.IntN(len(spec.Creds))]
	}
	return it, cr
}

// needCred returns a config failure if the type requires a credential.
func (p *probe) needCred() error {
	if !p.hasCr {
		return fail(ClassConfig, "no credential for %s check", p.spec.Type)
	}
	return nil
}

func randHex(rng *mrand.Rand, nbytes int) string {
	const hexd = "0123456789abcdef"
	b := make([]byte, nbytes*2)
	for i := range b {
		b[i] = hexd[rng.IntN(16)]
	}
	return string(b)
}
