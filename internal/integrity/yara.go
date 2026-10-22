package integrity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// RuleMatch is one rule hit.
type RuleMatch struct {
	Rule    string
	Tags    []string
	Meta    map[string]string
	Strings []StringMatch
}

// StringMatch records how often a rule string matched.
type StringMatch struct {
	ID     string // "$a"
	Count  int
	Offset int64 // first match offset (file offset; region-relative for memory)
}

// Scanner is the scheduled-scan engine interface. Implementations: GoScanner
// (this package, simple string/hex rules) and, when lab testing settles the
// open question, a YARA-X wrapper that runs the pinned static binary
// (see ExternalScanner). Process memory is read by the agent, not the engine.
type Scanner interface {
	ScanFile(ctx context.Context, path string) ([]RuleMatch, error)
	ScanReader(ctx context.Context, name string, r io.Reader) ([]RuleMatch, error)
	ScanProcess(ctx context.Context, pid int) ([]RuleMatch, error)
}

// ErrYaraXUnavailable is returned by the YARA-X wrapper stub.
var ErrYaraXUnavailable = errors.New("integrity: YARA-X scanner not available in this build")

// ErrCorpusNotBundled is returned by BundledC2Corpus: the C2 rule corpus
// (Sliver, Mythic, Realm, Sentinel, chisel, ligolo, pamspy, sshsnake,
// watershell, Cobalt Strike and Metasploit stagers) is not shipped yet. Rule
// licences must be checked before bundling (design: YARA, scheduled).
var ErrCorpusNotBundled = errors.New("integrity: C2 YARA corpus not bundled; use LoadCorpusDir")

// ExternalScanner is the stub for the pinned YARA-X binary. It has the hash
// pin and rules path the real one will need, and fails closed.
type ExternalScanner struct {
	Binary    string // path to the pinned yara-x binary
	SHA256    string // expected hash of Binary (pinned)
	RulesPath string
}

func (ExternalScanner) ScanFile(context.Context, string) ([]RuleMatch, error) {
	return nil, ErrYaraXUnavailable
}
func (ExternalScanner) ScanReader(context.Context, string, io.Reader) ([]RuleMatch, error) {
	return nil, ErrYaraXUnavailable
}
func (ExternalScanner) ScanProcess(context.Context, int) ([]RuleMatch, error) {
	return nil, ErrYaraXUnavailable
}

// BundledC2Corpus is the stubbed loader for the shipped C2 corpus.
func BundledC2Corpus() (*Matcher, error) { return &Matcher{}, ErrCorpusNotBundled }

// LoadCorpusDir parses every *.yar / *.yara file under dir. Rules using
// unsupported YARA features are skipped and listed in Matcher.Skipped rather
// than failing the load.
func LoadCorpusDir(dir string) (*Matcher, error) {
	m := &Matcher{}
	var files []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(p, ".yar") || strings.HasSuffix(p, ".yara")) {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		pm, err := ParseRules(string(b))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		m.Rules = append(m.Rules, pm.Rules...)
		m.Skipped = append(m.Skipped, pm.Skipped...)
	}
	return m, nil
}

// ---- rule model ----

// Matcher is a minimal pure-Go matcher for a subset of YARA: text strings
// (ascii, wide, nocase), hex strings with ?? wildcards, and conditions made of
// $id, "any|all|N of them", and/or/not, parentheses, true/false, filesize
// comparisons and uintNN(offset) comparisons within the first 4 KiB. Regular
// expressions, jumps, modules, fullword/xor/base64 are unsupported; rules using
// them are reported in Skipped, never silently matched or ignored.
type Matcher struct {
	Rules   []*Rule
	Skipped []SkippedRule
}

// SkippedRule is a rule the matcher could not compile.
type SkippedRule struct{ Name, Reason string }

// Rule is a compiled rule.
type Rule struct {
	Name     string
	Tags     []string
	Meta     map[string]string
	patterns []*pattern
	cond     cnode
}

type pattern struct {
	id      string
	bytes   []byte
	mask    []bool // true = wildcard byte (hex only)
	nocase  bool
	hasMask bool
}

type cnode interface{}
type (
	cStr struct{ id string }
	cOf  struct {
		n   int
		all bool
	} // n==0&&!all => any
	cAnd  struct{ a, b cnode }
	cOr   struct{ a, b cnode }
	cNot  struct{ a cnode }
	cBool bool
	cSize struct {
		op string
		v  int64
	}
	cUint struct {
		bits int
		off  int
		op   string
		v    uint64
	}
)

// ---- parsing ----

type lexer struct {
	s   string
	pos int
}

func stripComments(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		switch {
		case strings.HasPrefix(s[i:], "//"):
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case strings.HasPrefix(s[i:], "/*"):
			j := strings.Index(s[i+2:], "*/")
			if j < 0 {
				return b.String()
			}
			i += j + 4
		case s[i] == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(s) {
				j = len(s) - 1
			}
			b.WriteString(s[i : j+1])
			i = j + 1
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}

// ParseRules compiles YARA-subset source.
func ParseRules(src string) (*Matcher, error) {
	s := stripComments(src)
	m := &Matcher{}
	for {
		i := indexWord(s, "rule")
		if i < 0 {
			break
		}
		s = s[i+4:]
		ob := strings.IndexByte(s, '{')
		if ob < 0 {
			return nil, errors.New("yara: rule without body")
		}
		head := strings.TrimSpace(s[:ob])
		name, tagStr, _ := strings.Cut(head, ":")
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, errors.New("yara: rule without name")
		}
		end, err := matchBrace(s, ob)
		if err != nil {
			return nil, fmt.Errorf("yara: rule %s: %w", name, err)
		}
		body := s[ob+1 : end]
		s = s[end+1:]
		r := &Rule{Name: name, Tags: strings.Fields(tagStr), Meta: map[string]string{}}
		if err := compileRule(r, body); err != nil {
			var u unsupportedErr
			if errors.As(err, &u) {
				m.Skipped = append(m.Skipped, SkippedRule{name, string(u)})
				continue
			}
			return nil, fmt.Errorf("yara: rule %s: %w", name, err)
		}
		m.Rules = append(m.Rules, r)
	}
	return m, nil
}

type unsupportedErr string

func (u unsupportedErr) Error() string { return "unsupported: " + string(u) }

func indexWord(s, w string) int {
	for i := 0; ; {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return -1
		}
		j += i
		before := j == 0 || !isIdent(s[j-1])
		after := j+len(w) >= len(s) || !isIdent(s[j+len(w)])
		if before && after {
			return j
		}
		i = j + len(w)
	}
}

func isIdent(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// matchBrace finds the closing brace for the one at s[open], skipping strings
// and hex blocks.
func matchBrace(s string, open int) (int, error) {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '"':
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' {
					i++
				}
			}
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, errors.New("unbalanced braces")
}

func compileRule(r *Rule, body string) error {
	sec := splitSections(body)
	for _, line := range strings.Split(sec["meta"], "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			r.Meta[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	ids := map[string]bool{}
	if err := parseStrings(r, sec["strings"], ids); err != nil {
		return err
	}
	cond := strings.TrimSpace(sec["condition"])
	if cond == "" {
		return errors.New("no condition")
	}
	p := &condParser{toks: tokenizeCond(cond), ids: ids}
	n, err := p.parseOr()
	if err != nil {
		return err
	}
	if p.i != len(p.toks) {
		return fmt.Errorf("unexpected %q in condition", p.toks[p.i])
	}
	r.cond = n
	return nil
}

func splitSections(body string) map[string]string {
	out := map[string]string{}
	type pos struct {
		name string
		at   int
		end  int
	}
	var ps []pos
	for _, n := range []string{"meta", "strings", "condition"} {
		for i := 0; ; {
			j := strings.Index(body[i:], n+":")
			if j < 0 {
				break
			}
			j += i
			if j == 0 || !isIdent(body[j-1]) {
				ps = append(ps, pos{n, j, j + len(n) + 1})
				break
			}
			i = j + 1
		}
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].at < ps[j].at })
	for i, p := range ps {
		e := len(body)
		if i+1 < len(ps) {
			e = ps[i+1].at
		}
		out[p.name] = body[p.end:e]
	}
	return out
}

func parseStrings(r *Rule, sec string, ids map[string]bool) error {
	s := strings.TrimSpace(sec)
	for s != "" {
		if s[0] != '$' {
			return fmt.Errorf("bad string definition near %q", clip(s))
		}
		eq := strings.IndexByte(s, '=')
		if eq < 0 {
			return errors.New("string without '='")
		}
		id := strings.TrimSpace(s[:eq])
		s = strings.TrimSpace(s[eq+1:])
		pt := &pattern{id: id}
		var mods string
		switch {
		case strings.HasPrefix(s, `"`):
			j := 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(s) {
				return errors.New("unterminated string")
			}
			b, err := unescape(s[1:j])
			if err != nil {
				return err
			}
			pt.bytes = b
			s = s[j+1:]
			mods, s = takeMods(s)
		case strings.HasPrefix(s, "{"):
			j := strings.IndexByte(s, '}')
			if j < 0 {
				return errors.New("unterminated hex string")
			}
			if err := parseHex(pt, s[1:j]); err != nil {
				return err
			}
			s = s[j+1:]
			mods, s = takeMods(s)
		case strings.HasPrefix(s, "/"):
			return unsupportedErr("regular expression strings")
		default:
			return fmt.Errorf("bad string value near %q", clip(s))
		}
		wide, ascii := false, false
		for _, m := range strings.Fields(mods) {
			switch m {
			case "nocase":
				pt.nocase = true
			case "wide":
				wide = true
			case "ascii":
				ascii = true
			default:
				return unsupportedErr("string modifier " + m)
			}
		}
		if len(pt.bytes) == 0 {
			return errors.New("empty string")
		}
		if pt.nocase {
			pt.bytes = bytes.ToLower(pt.bytes)
		}
		ids[id] = true
		if wide && !pt.hasMask {
			w := widen(pt.bytes)
			if ascii {
				r.patterns = append(r.patterns, &pattern{id: id, bytes: pt.bytes, nocase: pt.nocase})
			}
			pt = &pattern{id: id, bytes: w, nocase: pt.nocase}
		}
		r.patterns = append(r.patterns, pt)
		s = strings.TrimSpace(s)
	}
	return nil
}

func clip(s string) string {
	if len(s) > 20 {
		return s[:20]
	}
	return s
}

// takeMods consumes modifier words that follow a string value, stopping at the
// next "$id" definition or the end of the section.
func takeMods(s string) (string, string) {
	var mods []string
	for {
		t := strings.TrimLeft(s, " \t\r\n")
		if t == "" || t[0] == '$' {
			return strings.Join(mods, " "), t
		}
		j := 0
		for j < len(t) && isIdent(t[j]) {
			j++
		}
		if j == 0 {
			return strings.Join(mods, " "), t // let the caller report garbage
		}
		mods = append(mods, t[:j])
		s = t[j:]
		if strings.HasPrefix(strings.TrimLeft(s, " "), "(") { // xor(1-2), base64("..."): unsupported anyway
			return strings.Join(mods, " ") + " (", s
		}
	}
}

func widen(b []byte) []byte {
	u := utf16.Encode([]rune(string(b)))
	out := make([]byte, 0, 2*len(u))
	for _, c := range u {
		out = append(out, byte(c), byte(c>>8))
	}
	return out
}

func unescape(s string) ([]byte, error) {
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			out = append(out, s[i])
			continue
		}
		i++
		if i >= len(s) {
			return nil, errors.New("bad escape")
		}
		switch s[i] {
		case 'n':
			out = append(out, '\n')
		case 't':
			out = append(out, '\t')
		case 'r':
			out = append(out, '\r')
		case '\\', '"':
			out = append(out, s[i])
		case 'x':
			if i+2 >= len(s)+0 && i+2 > len(s)-1+1 {
				return nil, errors.New("bad \\x escape")
			}
			if i+2 >= len(s)+1 {
				return nil, errors.New("bad \\x escape")
			}
			v, err := strconv.ParseUint(s[i+1:min(i+3, len(s))], 16, 8)
			if err != nil {
				return nil, errors.New("bad \\x escape")
			}
			out = append(out, byte(v))
			i += 2
		default:
			return nil, fmt.Errorf("unsupported escape \\%c", s[i])
		}
	}
	return out, nil
}

func parseHex(pt *pattern, s string) error {
	for _, tok := range strings.Fields(s) {
		switch {
		case tok == "??":
			pt.bytes = append(pt.bytes, 0)
			pt.mask = append(pt.mask, true)
			pt.hasMask = true
		case len(tok) == 2:
			v, err := strconv.ParseUint(tok, 16, 8)
			if err != nil {
				if strings.Contains(tok, "?") {
					return unsupportedErr("nibble wildcards in hex strings")
				}
				return fmt.Errorf("bad hex byte %q", tok)
			}
			pt.bytes = append(pt.bytes, byte(v))
			pt.mask = append(pt.mask, false)
		case strings.ContainsAny(tok, "[]|()"):
			return unsupportedErr("hex jumps/alternatives")
		default:
			return fmt.Errorf("bad hex token %q", tok)
		}
	}
	return nil
}

// ---- condition ----

func tokenizeCond(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(' || c == ')':
			out = append(out, string(c))
			i++
		case c == '=' || c == '<' || c == '>' || c == '!':
			if i+1 < len(s) && s[i+1] == '=' {
				out = append(out, s[i:i+2])
				i += 2
			} else {
				out = append(out, string(c))
				i++
			}
		default:
			j := i
			for j < len(s) && !strings.ContainsRune(" \t\n\r()=<>!", rune(s[j])) {
				j++
			}
			if j == i {
				j++
			}
			out = append(out, s[i:j])
			i = j
		}
	}
	return out
}

type condParser struct {
	toks []string
	i    int
	ids  map[string]bool
}

func (p *condParser) peek() string {
	if p.i < len(p.toks) {
		return p.toks[p.i]
	}
	return ""
}
func (p *condParser) next() string { t := p.peek(); p.i++; return t }

func (p *condParser) parseOr() (cnode, error) {
	a, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek() == "or" {
		p.next()
		b, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		a = cOr{a, b}
	}
	return a, nil
}

func (p *condParser) parseAnd() (cnode, error) {
	a, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.peek() == "and" {
		p.next()
		b, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		a = cAnd{a, b}
	}
	return a, nil
}

func (p *condParser) parseNot() (cnode, error) {
	if p.peek() == "not" {
		p.next()
		a, err := p.parseNot()
		return cNot{a}, err
	}
	return p.parsePrimary()
}

func (p *condParser) parsePrimary() (cnode, error) {
	t := p.next()
	switch {
	case t == "":
		return nil, errors.New("condition ends early")
	case t == "(":
		n, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.next() != ")" {
			return nil, errors.New("missing )")
		}
		return n, nil
	case t == "true":
		return cBool(true), nil
	case t == "false":
		return cBool(false), nil
	case t[0] == '$':
		if !p.ids[t] {
			return nil, fmt.Errorf("undefined string %s", t)
		}
		return cStr{t}, nil
	case t == "any" || t == "all" || isNumber(t):
		if p.next() != "of" || p.next() != "them" {
			return nil, unsupportedErr("only 'of them' string sets")
		}
		switch {
		case t == "any":
			return cOf{}, nil
		case t == "all":
			return cOf{all: true}, nil
		}
		n, _ := strconv.Atoi(t)
		return cOf{n: n}, nil
	case t == "filesize":
		op := p.next()
		v, err := parseSize(p.next())
		if err != nil {
			return nil, err
		}
		return cSize{op, v}, nil
	case t == "uint8" || t == "uint16" || t == "uint32":
		bits := map[string]int{"uint8": 8, "uint16": 16, "uint32": 32}[t]
		if p.next() != "(" {
			return nil, errors.New("expected ( after " + t)
		}
		offTok := p.next()
		if p.next() != ")" {
			return nil, errors.New("expected ) in " + t)
		}
		off, err := strconv.ParseInt(offTok, 0, 32)
		if err != nil || off < 0 || off+int64(bits/8) > headLen {
			return nil, unsupportedErr("integer read offset beyond first 4 KiB")
		}
		op := p.next()
		v, err := strconv.ParseUint(p.next(), 0, 64)
		if err != nil {
			return nil, errors.New("bad integer in condition")
		}
		return cUint{bits, int(off), op, v}, nil
	}
	return nil, unsupportedErr("condition token " + t)
}

func isNumber(s string) bool { _, err := strconv.Atoi(s); return err == nil }

func parseSize(s string) (int64, error) {
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "KB"):
		mult, s = 1<<10, strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "MB"):
		mult, s = 1<<20, strings.TrimSuffix(s, "MB")
	}
	v, err := strconv.ParseInt(s, 0, 64)
	return v * mult, err
}

const headLen = 4096

// ---- matching ----

type scanState struct {
	counts map[string]int
	first  map[string]int64
	size   int64
	head   []byte
}

func (m *Matcher) maxPat() int {
	n := 1
	for _, r := range m.Rules {
		for _, p := range r.patterns {
			if len(p.bytes) > n {
				n = len(p.bytes)
			}
		}
	}
	return n
}

// ScanReader scans a stream in 1 MiB chunks with overlap, so patterns that
// span chunks are found and counted once.
func (m *Matcher) ScanReader(ctx context.Context, name string, r io.Reader) ([]RuleMatch, error) {
	st := &scanState{counts: map[string]int{}, first: map[string]int64{}}
	overlap := m.maxPat() - 1
	const chunk = 1 << 20
	buf := make([]byte, 0, chunk+overlap)
	carry := 0
	var base int64 // absolute offset of buf[0]
	tmp := make([]byte, chunk)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := io.ReadFull(r, tmp)
		if n > 0 {
			buf = append(buf[:carry], tmp[:n]...)
			if len(st.head) < headLen {
				need := headLen - len(st.head)
				if need > n {
					need = n
				}
				st.head = append(st.head, tmp[:need]...)
			}
			m.scanWindow(buf, carry, base, st)
			st.size += int64(n)
			keep := overlap
			if keep > len(buf) {
				keep = len(buf)
			}
			copy(buf, buf[len(buf)-keep:])
			base += int64(len(buf) - keep)
			buf = buf[:keep]
			carry = keep
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return m.evaluate(st), nil
}

// ScanBytes scans an in-memory buffer.
func (m *Matcher) ScanBytes(ctx context.Context, name string, b []byte) ([]RuleMatch, error) {
	return m.ScanReader(ctx, name, bytes.NewReader(b))
}

func (m *Matcher) scanWindow(w []byte, carry int, base int64, st *scanState) {
	var lower []byte
	for _, r := range m.Rules {
		for _, p := range r.patterns {
			hay := w
			if p.nocase {
				if lower == nil {
					lower = bytes.ToLower(w)
				}
				hay = lower
			}
			for from := 0; from+len(p.bytes) <= len(hay); {
				i := p.find(hay[from:])
				if i < 0 {
					break
				}
				i += from
				from = i + 1
				if i+len(p.bytes) <= carry { // entirely inside the overlap: counted last window
					continue
				}
				k := r.Name + "\x00" + p.id
				st.counts[k]++
				if _, ok := st.first[k]; !ok {
					st.first[k] = base + int64(i)
				}
			}
		}
	}
}

func (p *pattern) find(h []byte) int {
	if !p.hasMask {
		return bytes.Index(h, p.bytes)
	}
	n := len(p.bytes)
outer:
	for i := 0; i+n <= len(h); i++ {
		for j := 0; j < n; j++ {
			if !p.mask[j] && h[i+j] != p.bytes[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}

func (m *Matcher) evaluate(st *scanState) []RuleMatch {
	var out []RuleMatch
	for _, r := range m.Rules {
		ids := map[string]bool{}
		var ordered []string
		for _, p := range r.patterns {
			if !ids[p.id] {
				ids[p.id] = true
				ordered = append(ordered, p.id)
			}
		}
		hit := func(id string) bool { return st.counts[r.Name+"\x00"+id] > 0 }
		if !evalCond(r.cond, ordered, hit, st) {
			continue
		}
		mt := RuleMatch{Rule: r.Name, Tags: r.Tags, Meta: r.Meta}
		for _, id := range ordered {
			if c := st.counts[r.Name+"\x00"+id]; c > 0 {
				mt.Strings = append(mt.Strings, StringMatch{ID: id, Count: c, Offset: st.first[r.Name+"\x00"+id]})
			}
		}
		out = append(out, mt)
	}
	return out
}

func evalCond(n cnode, ids []string, hit func(string) bool, st *scanState) bool {
	switch v := n.(type) {
	case cBool:
		return bool(v)
	case cStr:
		return hit(v.id)
	case cAnd:
		return evalCond(v.a, ids, hit, st) && evalCond(v.b, ids, hit, st)
	case cOr:
		return evalCond(v.a, ids, hit, st) || evalCond(v.b, ids, hit, st)
	case cNot:
		return !evalCond(v.a, ids, hit, st)
	case cOf:
		c := 0
		for _, id := range ids {
			if hit(id) {
				c++
			}
		}
		switch {
		case v.all:
			return c == len(ids) && c > 0
		case v.n > 0:
			return c >= v.n
		}
		return c > 0
	case cSize:
		return cmp(st.size, v.op, int64(v.v))
	case cUint:
		w := v.bits / 8
		if v.off+w > len(st.head) {
			return false
		}
		var x uint64
		for i := w - 1; i >= 0; i-- { // little endian, as YARA
			x = x<<8 | uint64(st.head[v.off+i])
		}
		return cmp(int64(x), v.op, int64(v.v))
	}
	return false
}

func cmp(a int64, op string, b int64) bool {
	switch op {
	case "<":
		return a < b
	case "<=":
		return a <= b
	case ">":
		return a > b
	case ">=":
		return a >= b
	case "==":
		return a == b
	case "!=":
		return a != b
	}
	return false
}

// ---- GoScanner ----

// GoScanner adapts a Matcher to the Scanner interface.
type GoScanner struct {
	M *Matcher
	// MaxFileBytes caps a file scan (default 256 MiB).
	MaxFileBytes int64
}

func (g GoScanner) ScanReader(ctx context.Context, name string, r io.Reader) ([]RuleMatch, error) {
	return g.M.ScanReader(ctx, name, r)
}

func (g GoScanner) ScanFile(ctx context.Context, path string) ([]RuleMatch, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	lim := g.MaxFileBytes
	if lim <= 0 {
		lim = 256 << 20
	}
	return g.M.ScanReader(ctx, path, io.LimitReader(f, lim))
}

// ---- schedule ----

// YaraSchedule runs a Scanner over files and process memory on an interval
// (design: every 5 minutes, deduplicated by inode, low priority). It emits
// "integrity.yara" events; it never touches the scanned files.
type YaraSchedule struct {
	Scanner  Scanner
	Interval time.Duration // default 5 minutes
	Files    func() []string
	PIDs     func() []int
	Agent    string
	Emit     func(event.Event)
	Now      func() time.Time
	// Pause between items keeps CPU use low (default 5 ms).
	Pause time.Duration

	seen map[fileID]bool
}

// YaraEventKind is the kind of events from a YaraSchedule.
const YaraEventKind = "integrity.yara"

// RunOnce performs one pass and returns the number of detections.
func (y *YaraSchedule) RunOnce(ctx context.Context) (int, error) {
	if y.seen == nil {
		y.seen = map[fileID]bool{}
	}
	if len(y.seen) > 200000 {
		y.seen = map[fileID]bool{}
	}
	now := time.Now
	if y.Now != nil {
		now = y.Now
	}
	pause := y.Pause
	if pause == 0 {
		pause = 5 * time.Millisecond
	}
	n := 0
	report := func(target string, pid int, ms []RuleMatch) {
		for _, m := range ms {
			n++
			f := map[string]any{"rule": m.Rule, "tags": m.Tags, "target": target}
			if pid > 0 {
				f["pid"] = pid
			}
			sm := make([]any, 0, len(m.Strings))
			for _, s := range m.Strings {
				sm = append(sm, map[string]any{"id": s.ID, "count": s.Count, "offset": s.Offset})
			}
			f["strings"] = sm
			if len(m.Meta) > 0 {
				f["meta"] = m.Meta
			}
			if y.Emit != nil {
				y.Emit(event.Event{Agent: y.Agent, Time: now().UTC(), Kind: YaraEventKind, Priority: event.PriorityCritical, Fields: f})
			}
		}
	}
	sleep := func() error {
		t := time.NewTimer(pause)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
	if y.Files != nil {
		for _, p := range y.Files() {
			fi, err := os.Stat(p)
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			id := idOf(fi, p)
			if y.seen[id] {
				continue
			}
			ms, err := y.Scanner.ScanFile(ctx, p)
			if err != nil {
				if ctx.Err() != nil {
					return n, ctx.Err()
				}
				continue
			}
			y.seen[id] = true
			report(p, 0, ms)
			if err := sleep(); err != nil {
				return n, err
			}
		}
	}
	if y.PIDs != nil {
		for _, pid := range y.PIDs() {
			ms, err := y.Scanner.ScanProcess(ctx, pid)
			if err != nil {
				if ctx.Err() != nil {
					return n, ctx.Err()
				}
				continue
			}
			report("pid:"+strconv.Itoa(pid), pid, ms)
			if err := sleep(); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

// Run loops RunOnce every Interval until ctx ends.
func (y *YaraSchedule) Run(ctx context.Context) error {
	iv := y.Interval
	if iv <= 0 {
		iv = 5 * time.Minute
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		if _, err := y.RunOnce(ctx); err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}
