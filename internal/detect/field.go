package detect

import (
	"net/netip"
	"strconv"
	"strings"
)

// aliases map a canonical dotted field to the flat names producers emit when
// the nested form is absent. image falls back to exe (Windows producers).
var aliases = map[string][]string{
	"image":          {"exe"},
	"parent.exe":     {"pexe"},
	"parent.comm":    {"pcomm"},
	"parent.cmdline": {"pcmdline"},
}

// fieldRef is a compiled field path.
type fieldRef struct {
	name  string
	parts []string
	alts  []string
	// netBits/base derive an address prefix field: "raddr_net16" is the /16
	// network of raddr (IPv6: twice the bits, so net16 is a /32). Used to key
	// counts by source network (rotating-source scanners). An event that
	// carries the flat key itself wins.
	netBits int
	base    *fieldRef
}

var netSuffixes = map[string]int{"_net8": 8, "_net16": 16, "_net24": 24}

func newFieldRef(name string) fieldRef {
	r := fieldRef{name: name, alts: aliases[name]}
	for suf, bits := range netSuffixes {
		if b, ok := strings.CutSuffix(name, suf); ok && b != "" {
			br := newFieldRef(b)
			r.netBits, r.base = bits, &br
		}
	}
	if strings.Contains(name, ".") {
		r.parts = strings.Split(name, ".")
	}
	return r
}

// get resolves the field in an event: the flat key, then the nested path,
// then the flat aliases. Pseudo fields agent and kind come from the event.
func (r fieldRef) get(c *evalCtx) (any, bool) {
	switch r.name {
	case "agent":
		return c.ev.Agent, c.ev.Agent != ""
	case "kind":
		return c.ev.Kind, true
	}
	f := c.ev.Fields
	if v, ok := f[r.name]; ok {
		return v, v != nil
	}
	if r.parts != nil {
		var cur any = f
		for _, p := range r.parts {
			m, ok := cur.(map[string]any)
			if !ok {
				cur = nil
				break
			}
			cur, ok = m[p]
			if !ok {
				cur = nil
				break
			}
		}
		if cur != nil {
			return cur, true
		}
	}
	for _, a := range r.alts {
		if v, ok := f[a]; ok && v != nil {
			return v, true
		}
	}
	if r.base != nil {
		if v, ok := r.base.get(c); ok {
			if str, ok := toStr(v); ok {
				if a, err := netip.ParseAddr(str); err == nil {
					a = a.Unmap()
					bits := r.netBits
					if a.Is6() {
						bits *= 2
					}
					if p, err := a.Prefix(bits); err == nil {
						return p.String(), true
					}
				}
			}
		}
	}
	return nil, false
}

// toStr renders scalar event values for string comparison.
func toStr(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		return strconv.FormatBool(x), true
	case int:
		return strconv.Itoa(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	case uint64:
		return strconv.FormatUint(x, 10), true
	case uint32:
		return strconv.FormatUint(uint64(x), 10), true
	case int32:
		return strconv.FormatInt(int64(x), 10), true
	case uint:
		return strconv.FormatUint(uint64(x), 10), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	}
	return "", false
}

func toNum(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case int32:
		return float64(x), true
	case uint:
		return float64(x), true
	case uint32:
		return float64(x), true
	case uint64:
		return float64(x), true
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case string:
		s := strings.TrimSpace(x)
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			n, err := strconv.ParseInt(s[2:], 16, 64)
			return float64(n), err == nil
		}
		n, err := strconv.ParseFloat(s, 64)
		return n, err == nil
	}
	return 0, false
}

// anyElem applies f to the value, or to each element if it is a list; true
// when any application is true.
func anyElem(v any, f func(any) bool) bool {
	switch x := v.(type) {
	case []string:
		for _, e := range x {
			if f(e) {
				return true
			}
		}
		return false
	case []any:
		for _, e := range x {
			if f(e) {
				return true
			}
		}
		return false
	}
	return f(v)
}

func lower(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + 32
	}
	return b
}

// Case-insensitive helpers: needle must already be lower case. ASCII folding
// only, which is all the rule corpus needs and keeps matching allocation free.
func hasPrefixFold(s, needle string) bool {
	if len(s) < len(needle) {
		return false
	}
	for i := 0; i < len(needle); i++ {
		if lower(s[i]) != needle[i] {
			return false
		}
	}
	return true
}

func hasSuffixFold(s, needle string) bool {
	if len(s) < len(needle) {
		return false
	}
	return hasPrefixFold(s[len(s)-len(needle):], needle)
}

func containsFold(s, needle string) bool {
	n := len(needle)
	if n == 0 {
		return true
	}
	c0 := needle[0]
	for i := 0; i+n <= len(s); i++ {
		if lower(s[i]) == c0 && hasPrefixFold(s[i:], needle) {
			return true
		}
	}
	return false
}

func eqFold(s, needle string) bool { return len(s) == len(needle) && hasPrefixFold(s, needle) }
