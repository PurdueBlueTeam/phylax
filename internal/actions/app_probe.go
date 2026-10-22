package actions

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Read-only probes: net.tcp_probe, net.http_probe, command.check.

type probeBase struct{}

func (probeBase) Locks(Params) []string  { return nil }
func (probeBase) Touches(Params) []Touch { return nil }
func (probeBase) Plan(context.Context, *Env, Params) (Plan, error) {
	return Plan{Diff: "read-only probe"}, nil
}
func (probeBase) Capture(context.Context, *Env, Params) (Rollback, error) { return Rollback{}, nil }
func (probeBase) Verify(context.Context, *Env, Params) error              { return nil }

var hostRe = regexp.MustCompile(`^[A-Za-z0-9._:\-\[\]%]{1,253}$`)

var retryParams = []ParamSpec{
	{Name: "retries", Type: Int, Check: func(v any) error {
		if n := v.(int); n < 0 || n > 20 {
			return errors.New("retries must be 0-20")
		}
		return nil
	}},
	{Name: "wait_ms", Type: Int, Default: 1000, Check: func(v any) error {
		if n := v.(int); n < 0 || n > 60000 {
			return errors.New("wait_ms must be 0-60000")
		}
		return nil
	}},
}

// retry runs f up to 1+retries times, waiting wait_ms between attempts.
func retry(ctx context.Context, p Params, f func() error) error {
	n, _ := p.Int("retries")
	w, _ := p.Int("wait_ms")
	var err error
	for i := 0; i <= n; i++ {
		if err = f(); err == nil {
			return nil
		}
		if i == n {
			break
		}
		select {
		case <-ctx.Done():
			return errors.Join(err, ctx.Err())
		case <-time.After(time.Duration(w) * time.Millisecond):
		}
	}
	return err
}

// ---- net.tcp_probe ----

type netTCPProbe struct{ probeBase }

func (netTCPProbe) Spec() Spec {
	return Spec{Name: "net.tcp_probe", Risk: RiskNone, ReadOnly: true, Doc: "TCP connect assertion.",
		Params: append([]ParamSpec{
			{Name: "host", Type: String, Required: true, Check: func(v any) error {
				if !hostRe.MatchString(v.(string)) {
					return errors.New("invalid host")
				}
				return nil
			}},
			{Name: "port", Type: Int, Required: true, Check: func(v any) error {
				if n := v.(int); n < 1 || n > 65535 {
					return errors.New("port must be 1-65535")
				}
				return nil
			}}}, retryParams...)}
}

func (netTCPProbe) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	port, _ := p.Int("port")
	addr := net.JoinHostPort(strings.Trim(p.Str("host"), "[]"), strconv.Itoa(port))
	dial := env.lx().Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	start := time.Now()
	err := retry(ctx, p, func() error {
		c, err := dial(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		return c.Close()
	})
	if err != nil {
		return nil, fmt.Errorf("tcp %s: %w", addr, err)
	}
	return Output{"addr": addr, "elapsed_ms": fmt.Sprint(time.Since(start).Milliseconds())}, nil
}

// ---- net.http_probe ----

type netHTTPProbe struct{ probeBase }

func (netHTTPProbe) Spec() Spec {
	return Spec{Name: "net.http_probe", Risk: RiskNone, ReadOnly: true,
		Doc: "HTTP GET asserting the status and/or a body regex (RE2). Without expect_status any status below 400 passes.",
		Params: append([]ParamSpec{
			{Name: "url", Type: String, Required: true, Max: 2048, Check: func(v any) error {
				u, err := url.Parse(v.(string))
				if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
					return errors.New("want an absolute http(s) URL")
				}
				return nil
			}},
			{Name: "expect_status", Type: Int, Check: func(v any) error {
				if n := v.(int); n < 100 || n > 599 {
					return errors.New("invalid status")
				}
				return nil
			}},
			{Name: "expect_regex", Type: String, Max: 512, Check: func(v any) error { _, err := regexp.Compile(v.(string)); return err }},
			{Name: "insecure", Type: Bool}}, retryParams...)}
}

func (netHTTPProbe) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	hc := env.lx().HTTP
	if hc == nil {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: p.Bool("insecure")}, // #nosec G402 -- explicit probe option
			DisableKeepAlives: true, ResponseHeaderTimeout: 10 * time.Second}
		hc = &http.Client{Timeout: 15 * time.Second, Transport: tr}
	}
	var re *regexp.Regexp
	if p.Has("expect_regex") {
		re = regexp.MustCompile(p.Str("expect_regex"))
	}
	want, hasWant := p.Int("expect_status")
	var out Output
	start := time.Now()
	err := retry(ctx, p, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Str("url"), nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "phylax-probe/1")
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		out = Output{"status": fmt.Sprint(resp.StatusCode), "bytes": fmt.Sprint(len(body))}
		if hasWant && resp.StatusCode != want || !hasWant && resp.StatusCode >= 400 {
			return fmt.Errorf("status %d, want %s", resp.StatusCode, map[bool]string{true: fmt.Sprint(want), false: "<400"}[hasWant])
		}
		if re != nil && !re.Match(body) {
			return fmt.Errorf("body does not match %q", p.Str("expect_regex"))
		}
		return nil
	})
	if out != nil {
		out["elapsed_ms"] = fmt.Sprint(time.Since(start).Milliseconds())
	}
	if err != nil {
		return out, fmt.Errorf("probe %s: %w", p.Str("url"), err)
	}
	return out, nil
}

// ---- command.check ----

type commandCheck struct{ probeBase }

var probeNames = []string{"sudo_version", "pkexec_version", "ssh_version", "kernel_release", "userns_check"}

func (commandCheck) Spec() Spec {
	return Spec{Name: "command.check", Risk: RiskNone, ReadOnly: true,
		Doc: "Run an allowlisted read-only probe (sudo_version, pkexec_version, ssh_version, kernel_release, userns_check) and report the version and known-vulnerable ranges. fail_if_vulnerable fails the node on a finding.",
		Params: []ParamSpec{{Name: "probe", Type: Enum, Required: true, Enum: probeNames},
			{Name: "fail_if_vulnerable", Type: Bool}}}
}

// ver is a comparable program version such as 1.9.16p2 or 9.6p1.
type ver struct {
	n []int
	p int
}

var verRe = regexp.MustCompile(`(\d+(?:\.\d+)*)(?:p(\d+))?`)

func parseVer(s string) (ver, bool) {
	m := verRe.FindStringSubmatch(s)
	if m == nil {
		return ver{}, false
	}
	var v ver
	for _, f := range strings.Split(m[1], ".") {
		n, _ := strconv.Atoi(f)
		v.n = append(v.n, n)
	}
	v.p, _ = strconv.Atoi(m[2])
	return v, true
}

func (a ver) cmp(b ver) int {
	for i := 0; i < len(a.n) || i < len(b.n); i++ {
		x, y := 0, 0
		if i < len(a.n) {
			x = a.n[i]
		}
		if i < len(b.n) {
			y = b.n[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case a.p < b.p:
		return -1
	case a.p > b.p:
		return 1
	}
	return 0
}

func inRange(v ver, lo, hi string) bool { // lo <= v < hi
	l, _ := parseVer(lo)
	h, _ := parseVer(hi)
	return v.cmp(l) >= 0 && v.cmp(h) < 0
}

func sudoFindings(v ver) []string {
	var f []string
	if inRange(v, "1.8.2", "1.8.32") || inRange(v, "1.9.0", "1.9.5p2") {
		f = append(f, "CVE-2021-3156 (Baron Samedit heap overflow); fixed in 1.9.5p2")
	}
	if inRange(v, "1.8.8", "1.9.17p1") {
		f = append(f, "CVE-2025-32462 (sudo -h host option); fixed in 1.9.17p1")
	}
	if inRange(v, "1.9.14", "1.9.17p1") {
		f = append(f, "CVE-2025-32463 (sudo --chroot local root); fixed in 1.9.17p1")
	}
	return f
}

func sshFindings(v ver) []string {
	var f []string
	if inRange(v, "8.5p1", "9.8p1") {
		f = append(f, "CVE-2024-6387 (regreSSHion); use LoginGraceTime 20 and patch (distro builds may carry a backport)")
	}
	return f
}

func (commandCheck) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	run := func(argv ...string) (string, error) {
		res, err := env.lx().runner().Run(ctx, Cmd{Argv: argv, Timeout: 20 * time.Second})
		if err != nil {
			return "", err
		}
		if res.ExitCode != 0 {
			return "", fmt.Errorf("%s exited %d: %s", argv[0], res.ExitCode, strings.TrimSpace(res.Stderr))
		}
		return res.Stdout + res.Stderr, nil
	}
	out := Output{"probe": p.Str("probe")}
	var findings []string
	switch p.Str("probe") {
	case "sudo_version":
		s, err := run("/usr/bin/sudo", "-V")
		if err != nil {
			return nil, err
		}
		line := strings.SplitN(strings.TrimSpace(s), "\n", 1)[0]
		v, ok := parseVer(strings.TrimPrefix(strings.ToLower(line), "sudo version"))
		if !ok {
			return nil, fmt.Errorf("cannot parse sudo version from %q", line)
		}
		out["version"] = strings.TrimSpace(strings.TrimPrefix(line, "Sudo version"))
		findings = sudoFindings(v)
	case "pkexec_version":
		s, err := run("/usr/bin/pkexec", "--version")
		if err != nil {
			return nil, err
		}
		out["version"] = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "pkexec version"))
		if st, err := os.Stat(env.Resolve("/usr/bin/pkexec")); err == nil {
			out["mode"] = fmt.Sprintf("%04o", st.Mode().Perm())
			if st.Mode()&os.ModeSetuid != 0 {
				out["setuid"] = "true"
			} else {
				out["setuid"] = "false"
			}
		}
	case "ssh_version":
		s, err := run("/usr/bin/ssh", "-V")
		if err != nil {
			return nil, err
		}
		s = strings.TrimSpace(s)
		out["version"] = strings.SplitN(s, ",", 2)[0]
		if v, ok := parseVer(strings.TrimPrefix(strings.SplitN(s, ",", 2)[0], "OpenSSH_")); ok {
			findings = sshFindings(v)
		}
	case "kernel_release":
		b, err := os.ReadFile(env.Resolve("/proc/sys/kernel/osrelease"))
		if err != nil {
			return nil, err
		}
		out["release"] = strings.TrimSpace(string(b))
	case "userns_check":
		b, err := os.ReadFile(env.Resolve("/proc/sys/user/max_user_namespaces"))
		if err != nil {
			return nil, err
		}
		out["max_user_namespaces"] = strings.TrimSpace(string(b))
		out["enabled"] = fmt.Sprint(strings.TrimSpace(string(b)) != "0")
		if rb, err := os.ReadFile(env.Resolve("/proc/self/uid_map")); err == nil {
			out["in_user_namespace"] = fmt.Sprint(!strings.Contains(string(rb), "4294967295"))
		}
	}
	out["findings"] = strings.Join(findings, "\n")
	out["vulnerable"] = fmt.Sprint(len(findings) > 0)
	if len(findings) > 0 && p.Bool("fail_if_vulnerable") {
		return out, fmt.Errorf("vulnerable: %s", strings.Join(findings, "; "))
	}
	return out, nil
}
