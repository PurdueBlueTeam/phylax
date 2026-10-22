package actions

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Comment- and order-preserving key/value editing for the config dialects
// the plans touch: INI-with-stanzas (php.ini, Splunk .conf), "key = value"
// at top level with optional brace blocks and indented continuation lines
// (Postfix main.cf, dovecot.conf), and whitespace-separated (sshd_config).

type confStyle int

const (
	styleAuto confStyle = iota
	styleINI
	styleSpace
	styleEquals
)

var styleNames = map[string]confStyle{"auto": styleAuto, "ini": styleINI, "space": styleSpace, "equals": styleEquals}

var (
	confKeyRe   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:\-\[\]]{0,127}$`)
	sectionRe   = regexp.MustCompile(`^\s*\[([^\]\r\n]+)\]\s*$`)
	matchLineRe = regexp.MustCompile(`(?i)^\s*Match\s`)
)

func checkConfText(what, s string) error {
	if strings.ContainsAny(s, "\x00\r\n") {
		return fmt.Errorf("%s must be a single line without NUL", what)
	}
	return nil
}

// detectStyle picks a dialect from the path.
func detectStyle(path string) confStyle {
	p := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	base := p[strings.LastIndex(p, "/")+1:]
	switch {
	case base == "sshd_config" || base == "ssh_config" || strings.Contains(p, "/sshd_config.d/") || strings.Contains(p, "/ssh_config.d/"):
		return styleSpace
	case base == "main.cf" || base == "master.cf" || strings.HasPrefix(base, "dovecot") || strings.Contains(p, "/dovecot/"):
		return styleEquals
	}
	return styleINI
}

type confLine struct {
	text string
	eol  string
}

func splitConf(s string) ([]confLine, string) {
	eol := "\n"
	if strings.Contains(s, "\r\n") {
		eol = "\r\n"
	}
	if s == "" {
		return nil, eol
	}
	raw := strings.Split(s, "\n")
	if raw[len(raw)-1] == "" {
		raw = raw[:len(raw)-1]
	}
	out := make([]confLine, len(raw))
	for i, l := range raw {
		out[i] = confLine{text: strings.TrimSuffix(l, "\r")}
	}
	return out, eol
}

func joinConf(ls []confLine, eol string) string {
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(l.text)
		b.WriteString(eol)
	}
	return b.String()
}

func isComment(t string) bool {
	t = strings.TrimSpace(t)
	return t == "" || t[0] == '#' || t[0] == ';'
}

// editConf sets key to value in src. For styleINI the key lives in stanza
// ("" = before the first section). It returns the new text; changed is false
// when the key already has that value everywhere it is active.
func editConf(src string, style confStyle, stanza, key, value string) (out string, changed bool, err error) {
	if !confKeyRe.MatchString(key) {
		return "", false, fmt.Errorf("invalid key %q", key)
	}
	if err := checkConfText("value", value); err != nil {
		return "", false, err
	}
	if err := checkConfText("stanza", stanza); err != nil {
		return "", false, err
	}
	lines, eol := splitConf(src)
	insertAt := -1 // index to insert a new line at
	found := false
	section := ""
	depth := 0
	matchStart := -1 // sshd: first Match line
	var keyRe *regexp.Regexp
	switch style {
	case styleSpace:
		keyRe = regexp.MustCompile(`(?i)^(\s*)(` + regexp.QuoteMeta(key) + `)(\s*=\s*|\s+)(.*?)\s*$`)
	default:
		keyRe = regexp.MustCompile(`^(\s*)(` + regexp.QuoteMeta(key) + `)(\s*=\s*)(.*?)\s*$`)
	}
	lastInSection := -1
	sectionSeen := stanza == ""
	var drop []int
	for i := 0; i < len(lines); i++ {
		t := lines[i].text
		if style == styleSpace && matchLineRe.MatchString(t) {
			matchStart = i
			break
		}
		if style == styleINI {
			if m := sectionRe.FindStringSubmatch(t); m != nil {
				section = strings.TrimSpace(m[1])
				if section == stanza {
					sectionSeen = true
					lastInSection = i
				}
				continue
			}
		}
		if style == styleEquals {
			trim := strings.TrimSpace(t)
			if !isComment(t) {
				if strings.HasSuffix(trim, "{") {
					depth++
					continue
				}
				if trim == "}" {
					if depth > 0 {
						depth--
					}
					continue
				}
			}
			if depth > 0 {
				continue
			}
		}
		if style == styleINI && section != stanza {
			continue
		}
		if !isComment(t) {
			lastInSection = i
		}
		if isComment(t) {
			continue
		}
		m := keyRe.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		found = true
		if m[4] == value {
			continue
		}
		lines[i].text = m[1] + m[2] + m[3] + value
		changed = true
		if style == styleEquals { // drop Postfix continuation lines of the old value
			for j := i + 1; j < len(lines); j++ {
				c := lines[j].text
				if c != "" && (c[0] == ' ' || c[0] == '\t') && !isComment(c) {
					drop = append(drop, j)
					continue
				}
				break
			}
		}
	}
	if len(drop) > 0 {
		dm := map[int]bool{}
		for _, d := range drop {
			dm[d] = true
		}
		nl := lines[:0:0]
		for i, l := range lines {
			if !dm[i] {
				nl = append(nl, l)
			}
		}
		lines = nl
	}
	if !found {
		changed = true
		sep := " = "
		if style == styleSpace {
			sep = " "
		}
		nl := confLine{text: key + sep + value}
		switch style {
		case styleSpace:
			insertAt = len(lines)
			if matchStart >= 0 {
				insertAt = matchStart
			}
		case styleINI:
			if !sectionSeen {
				if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1].text) != "" {
					lines = append(lines, confLine{})
				}
				lines = append(lines, confLine{text: "[" + stanza + "]"}, nl)
				return joinConf(lines, eol), true, nil
			}
			insertAt = lastInSection + 1
			if stanza == "" && lastInSection < 0 {
				insertAt = 0
			}
		default:
			insertAt = len(lines)
		}
		lines = append(lines[:insertAt], append([]confLine{nl}, lines[insertAt:]...)...)
	}
	if style == styleEquals && depth != 0 {
		return "", false, errors.New("unbalanced braces in config; refusing to edit")
	}
	return joinConf(lines, eol), changed, nil
}

// getConf returns the active values of key (top-level or in stanza).
func getConf(src string, style confStyle, stanza, key string) []string {
	lines, _ := splitConf(src)
	section := ""
	depth := 0
	var keyRe *regexp.Regexp
	if style == styleSpace {
		keyRe = regexp.MustCompile(`(?i)^\s*` + regexp.QuoteMeta(key) + `(?:\s*=\s*|\s+)(.*?)\s*$`)
	} else {
		keyRe = regexp.MustCompile(`^\s*` + regexp.QuoteMeta(key) + `\s*=\s*(.*?)\s*$`)
	}
	var out []string
	for _, l := range lines {
		t := l.text
		if style == styleSpace && matchLineRe.MatchString(t) {
			break
		}
		if style == styleINI {
			if m := sectionRe.FindStringSubmatch(t); m != nil {
				section = strings.TrimSpace(m[1])
				continue
			}
			if section != stanza {
				continue
			}
		}
		if style == styleEquals && !isComment(t) {
			trim := strings.TrimSpace(t)
			if strings.HasSuffix(trim, "{") {
				depth++
				continue
			}
			if trim == "}" {
				depth--
				continue
			}
			if depth > 0 {
				continue
			}
		}
		if isComment(t) {
			continue
		}
		if m := keyRe.FindStringSubmatch(t); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}
