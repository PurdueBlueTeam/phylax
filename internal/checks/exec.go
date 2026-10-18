package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// executor runs one probe and returns the observed values. A non-nil error
// is a failed run; actual may still carry observed values for the diff.
type executor func(ctx context.Context, ck Check) (map[string]any, error)

var executors = map[string]executor{
	"http": runHTTP,
	"smtp": runSMTP,
	"dns":  runDNS,
	"ftp":  runFTP,
	"tftp": runTFTP,
	"ntp":  runNTP,
	"tcp":  runTCP,
}

func execute(ctx context.Context, ck Check) (map[string]any, error) {
	exec, ok := executors[ck.Type]
	if !ok {
		return nil, fmt.Errorf("unknown check type %q", ck.Type)
	}
	return exec(ctx, ck)
}

// compare reports why the actual values do not match the expected values;
// an empty string means the check passed.
func compare(ck Check, actual map[string]any) string {
	keys := make([]string, 0, len(ck.Expected))
	for k := range ck.Expected {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var bad []string
	for _, k := range keys {
		ev := ck.Expected[k]
		av, present := actual[k]
		switch {
		case ck.Type == "dns" && k == "answers":
			want := toStringSet(ev)
			got, _ := actual["answers"].([]string)
			if !setsEqual(want, toStringSet(got)) {
				bad = append(bad, fmt.Sprintf("answers: expected %v, got %v", sortedStrings(want), sortedStrings(toStringSet(got))))
			}
		case ck.Type == "tcp" && k == "banner_re":
			banner, _ := actual["banner"].(string)
			re, cerr := regexp.Compile(asString(ev))
			if cerr != nil {
				bad = append(bad, fmt.Sprintf("banner_re: %v", cerr))
			} else if !re.MatchString(banner) {
				bad = append(bad, fmt.Sprintf("banner_re %q: no match in banner %q", asString(ev), banner))
			}
		case ck.Type == "ntp" && k == "reachable":
			want, ok := asBool(ev)
			got, _ := actual["reachable"].(bool)
			if !ok || got != want {
				bad = append(bad, fmt.Sprintf("reachable: expected %v, got %v", want, got))
			}
		case ck.Type == "tcp":
			// banner_re is the only supported expected key for tcp.
		default:
			if !present {
				bad = append(bad, fmt.Sprintf("%s: missing in actual", k))
			} else if !looseEqual(ev, av) {
				bad = append(bad, fmt.Sprintf("%s: expected %v, got %v", k, ev, av))
			}
		}
	}
	if ck.Type == "ntp" {
		if _, explicit := ck.Expected["reachable"]; !explicit {
			if got, _ := actual["reachable"].(bool); !got {
				bad = append(bad, "reachable: expected true, got false")
			}
		}
	}
	return strings.Join(bad, "; ")
}

func looseEqual(a, b any) bool {
	if af, ok := toFloat(a); ok {
		bf, ok := toFloat(b)
		return ok && af == bf
	}
	if ab, ok := asBool(a); ok {
		bb, ok := asBool(b)
		return ok && ab == bb
	}
	return asString(a) == asString(b)
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		return f, err == nil
	}
	return 0, false
}

func asBool(v any) (bool, bool) {
	switch b := v.(type) {
	case bool:
		return b, true
	case string:
		p, err := strconv.ParseBool(strings.TrimSpace(b))
		return p, err == nil
	}
	return false, false
}

func asString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

func toStringSet(v any) map[string]struct{} {
	set := make(map[string]struct{})
	switch vs := v.(type) {
	case []string:
		for _, s := range vs {
			set[s] = struct{}{}
		}
	case []any:
		for _, s := range vs {
			set[asString(s)] = struct{}{}
		}
	case string:
		set[vs] = struct{}{}
	}
	return set
}

func setsEqual(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func sortedStrings(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- parameter helpers -----------------------------------------------------

func pstr(p map[string]any, key string) (string, error) {
	v, ok := p[key]
	if !ok || asString(v) == "" {
		return "", fmt.Errorf("missing param %q", key)
	}
	return asString(v), nil
}

func pstrOpt(p map[string]any, key string) string {
	if v, ok := p[key]; ok {
		return asString(v)
	}
	return ""
}

func pstrs(p map[string]any, key string) []string {
	v, ok := p[key]
	if !ok {
		return nil
	}
	switch vs := v.(type) {
	case string:
		return []string{vs}
	case []string:
		return vs
	case []any:
		out := make([]string, 0, len(vs))
		for _, s := range vs {
			out = append(out, asString(s))
		}
		return out
	}
	return nil
}

func pnum(p map[string]any, key string) (float64, bool) {
	v, ok := p[key]
	if !ok {
		return 0, false
	}
	f, ok := toFloat(v)
	return f, ok
}

// defaultPort is the port used when the host param has none.
func defaultPort(ck Check) int {
	switch ck.Type {
	case "smtp", "pop3":
		return 25
	case "dns":
		return 53
	case "ftp":
		return 21
	case "tftp":
		return 69
	case "ntp":
		return 123
	default:
		return 80
	}
}

// addrWithDefaultPort returns "host:port", filling in the type's default
// port when the host has none.
func addrWithDefaultPort(host string, ck Check) (string, error) {
	if host == "" {
		return "", fmt.Errorf("missing host")
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host, nil
	}
	if strings.Contains(host, ":") {
		return "", fmt.Errorf("bad host %q", host)
	}
	return net.JoinHostPort(host, strconv.Itoa(defaultPort(ck))), nil
}

// --- shared plumbing ---------------------------------------------------------

// sha256Hex of the bytes.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// dialTimeout is the connect timeout: the time left on the context, capped
// at 5s, or 5s when the context has no deadline.
func dialTimeout(ctx context.Context) time.Duration {
	const cap = 5 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d > 0 && d < cap {
			return d
		}
	}
	return cap
}

// setConnDeadline bounds a connected socket with the context deadline.
func setConnDeadline(conn net.Conn, ctx context.Context) error {
	if dl, ok := ctx.Deadline(); ok {
		return conn.SetDeadline(dl)
	}
	return nil
}
