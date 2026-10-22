package actions

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
)

// xml.set edits element text in place without re-serialising the document, so
// comments, attribute order, whitespace and multiple top-level elements
// (Wazuh's ossec.conf has several <ossec_config>) survive byte for byte.

type xmlSeg struct {
	name     string
	attrName string // predicate [@a='v']
	attrVal  string
	index    int // predicate [n], 1-based; 0 = none
}

var segRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_.\-]*)(?:\[(?:(\d+)|@([A-Za-z_][A-Za-z0-9_.\-:]*)\s*=\s*(?:'([^']*)'|"([^"]*)"))\])?$`)

// parseXPath accepts /a/b, //a/b, a/b with name, [n] and [@attr='v'] steps.
func parseXPath(x string) (segs []xmlSeg, anywhere bool, err error) {
	if x == "" || len(x) > 512 {
		return nil, false, errors.New("invalid xpath")
	}
	switch {
	case strings.HasPrefix(x, "//"):
		anywhere, x = true, x[2:]
	case strings.HasPrefix(x, "/"):
		x = x[1:]
	default:
		anywhere = true
	}
	for _, part := range strings.Split(x, "/") {
		m := segRe.FindStringSubmatch(part)
		if m == nil {
			return nil, false, fmt.Errorf("unsupported xpath step %q (only names, [n] and [@a='v'])", part)
		}
		s := xmlSeg{name: m[1]}
		if m[2] != "" {
			s.index, _ = strconv.Atoi(m[2])
			if s.index < 1 {
				return nil, false, errors.New("xpath index starts at 1")
			}
		}
		if m[3] != "" {
			s.attrName, s.attrVal = m[3], m[4]+m[5]
		}
		segs = append(segs, s)
	}
	return segs, anywhere, nil
}

type xmlFrame struct {
	name  string
	attrs []xml.Attr
	idx   int // 1-based among same-named siblings
	kids  map[string]int
	begin int // offset of '<'
	body  int // offset after the start tag
	self  bool
	child bool // has element children
}

func segMatches(s xmlSeg, f *xmlFrame) bool {
	if s.name != f.name {
		return false
	}
	if s.index > 0 && s.index != f.idx {
		return false
	}
	if s.attrName != "" {
		for _, a := range f.attrs {
			if a.Name.Local == s.attrName && a.Value == s.attrVal {
				return true
			}
		}
		return false
	}
	return true
}

func stackMatches(segs []xmlSeg, anywhere bool, st []*xmlFrame) bool {
	if len(st) < len(segs) || (!anywhere && len(st) != len(segs)) {
		return false
	}
	off := len(st) - len(segs)
	for i, s := range segs {
		if !segMatches(s, st[off+i]) {
			return false
		}
	}
	return true
}

type xmlHit struct {
	begin, body, end int // end: offset of '</' (or after '/>' when self)
	endTag           int // offset after the closing tag
	self             bool
	child            bool
	text             string
	name             string
	indent           string
}

// scanXML returns the matches of the xpath, and the closing-tag offset of the
// first match of the parent path (for creation).
func scanXML(src []byte, segs []xmlSeg, anywhere bool) (hits []xmlHit, parent *xmlHit, err error) {
	dec := xml.NewDecoder(bytes.NewReader(src))
	dec.Strict = true
	var st []*xmlFrame
	root := &xmlFrame{kids: map[string]int{}}
	var psegs []xmlSeg
	if len(segs) > 1 {
		psegs = segs[:len(segs)-1]
	}
	for {
		before := int(dec.InputOffset())
		tok, terr := dec.RawToken()
		if terr == io.EOF {
			break
		}
		if terr != nil {
			return nil, nil, fmt.Errorf("xml: %w", terr)
		}
		after := int(dec.InputOffset())
		switch t := tok.(type) {
		case xml.StartElement:
			sib := root
			if len(st) > 0 {
				sib = st[len(st)-1]
				sib.child = true
			}
			sib.kids[t.Name.Local]++
			f := &xmlFrame{name: t.Name.Local, attrs: t.Attr, idx: sib.kids[t.Name.Local], kids: map[string]int{},
				begin: before, body: after, self: bytes.HasSuffix(src[before:after], []byte("/>"))}
			st = append(st, f)
			if f.self { // RawToken still emits the End; handled below
				continue
			}
		case xml.EndElement:
			if len(st) == 0 {
				return nil, nil, errors.New("xml: unbalanced end tag")
			}
			f := st[len(st)-1]
			full := stackMatches(segs, anywhere, st)
			isParent := parent == nil && len(psegs) > 0 && stackMatches(psegs, anywhere, st)
			h := xmlHit{begin: f.begin, body: f.body, self: f.self, child: f.child, name: f.name}
			if f.self {
				h.end, h.endTag = f.body, f.body
			} else {
				h.end, h.endTag = before, after
				h.text = string(src[f.body:before])
			}
			if full {
				hits = append(hits, h)
			}
			if isParent {
				hh := h
				// indentation of the parent's start tag
				ls := bytes.LastIndexByte(src[:f.begin], '\n') + 1
				hh.indent = string(src[ls:f.begin])
				if strings.TrimSpace(hh.indent) != "" {
					hh.indent = ""
				}
				parent = &hh
			}
			st = st[:len(st)-1]
		}
	}
	if len(st) != 0 {
		return nil, nil, errors.New("xml: unclosed element")
	}
	return hits, parent, nil
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// editXML returns the document with every match set to value.
func editXML(src []byte, xpath, value string) (out []byte, changed bool, matches int, err error) {
	segs, anywhere, err := parseXPath(xpath)
	if err != nil {
		return nil, false, 0, err
	}
	hits, parent, err := scanXML(src, segs, anywhere)
	if err != nil {
		return nil, false, 0, err
	}
	esc := xmlEscape(value)
	type edit struct {
		from, to int
		repl     string
	}
	var edits []edit
	for _, h := range hits {
		if h.child {
			return nil, false, 0, fmt.Errorf("<%s> has child elements; refusing to overwrite", h.name)
		}
		if h.self {
			open := string(src[h.begin : h.body-2])
			edits = append(edits, edit{h.begin, h.body, strings.TrimRight(open, " ") + ">" + esc + "</" + h.name + ">"})
			continue
		}
		if strings.TrimSpace(h.text) == esc {
			continue
		}
		edits = append(edits, edit{h.body, h.end, esc})
	}
	if len(hits) == 0 {
		last := segs[len(segs)-1]
		if parent == nil || last.index > 0 || last.attrName != "" {
			return nil, false, 0, fmt.Errorf("xpath %q matches nothing and its element cannot be created", xpath)
		}
		if parent.self {
			return nil, false, 0, errors.New("cannot create under a self-closing parent")
		}
		ins := parent.indent + "  <" + last.name + ">" + esc + "</" + last.name + ">\n" + parent.indent
		// put it on its own line if the parent body ends with a newline+indent
		body := string(src[parent.body:parent.end])
		if strings.HasSuffix(strings.TrimRight(body, " \t"), "\n") {
			edits = append(edits, edit{parent.end - len(body) + len(strings.TrimRight(body, " \t")), parent.end, ins})
		} else {
			edits = append(edits, edit{parent.end, parent.end, "<" + last.name + ">" + esc + "</" + last.name + ">"})
		}
	}
	if len(edits) == 0 {
		return src, false, len(hits), nil
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].from > edits[j].from })
	out = append([]byte(nil), src...)
	for _, e := range edits {
		out = append(out[:e.from], append([]byte(e.repl), out[e.to:]...)...)
	}
	if _, _, err := scanXML(out, segs, anywhere); err != nil {
		return nil, false, 0, fmt.Errorf("edit would produce invalid XML: %w", err)
	}
	return out, true, len(hits), nil
}

type xmlSet struct{}

func (xmlSet) Spec() Spec {
	return Spec{Name: "xml.set", Risk: RiskService,
		Doc: "Set element text at an xpath (names, [n], [@a='v']; // for any depth) in place, keeping comments and layout.",
		Params: []ParamSpec{osPathParam,
			{Name: "xpath", Type: String, Required: true, Max: 512, Check: func(v any) error { _, _, err := parseXPath(v.(string)); return err }},
			{Name: "value", Type: String, Required: true, Max: 4096, Check: func(v any) error {
				if strings.ContainsRune(v.(string), 0) {
					return errors.New("NUL in value")
				}
				return nil
			}}}}
}
func (xmlSet) Locks(Params) []string    { return nil }
func (xmlSet) Touches(p Params) []Touch { return []Touch{pathTouch(p.Str("path"), OpModify)} }
func (xmlSet) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	old, _, err := readBounded(env.resolveAny(p.Str("path")))
	if err != nil {
		return Plan{}, err
	}
	out, changed, _, err := editXML(old, p.Str("xpath"), p.Str("value"))
	if err != nil {
		return Plan{}, err
	}
	if !changed {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: renderDiff(old, out)}, nil
}
func (xmlSet) Capture(_ context.Context, env *Env, p Params) (Rollback, error) {
	return snapshotRollback(env.resolveAny(p.Str("path")))
}
func (xmlSet) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	return nil, atomicfile.Modify(env.resolveAny(p.Str("path")), 0o640, func(old []byte, exists bool) ([]byte, error) {
		if !exists {
			return nil, errors.New("file does not exist")
		}
		out, _, _, err := editXML(old, p.Str("xpath"), p.Str("value"))
		return out, err
	})
}
func (xmlSet) Verify(_ context.Context, env *Env, p Params) error {
	b, _, err := readBounded(env.resolveAny(p.Str("path")))
	if err != nil {
		return err
	}
	_, changed, n, err := editXML(b, p.Str("xpath"), p.Str("value"))
	if err != nil {
		return err
	}
	if changed || n == 0 {
		return errors.New("value not present after write")
	}
	return nil
}
