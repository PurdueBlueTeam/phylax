// Package xmlapi is a thin client for the PAN-OS XML API plus the small XML
// tree it needs (parse, xpath select, canonical form, flatten). The fake PAN-OS
// server in palotest stores its configuration in the same tree.
package xmlapi

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Attr is an XML attribute.
type Attr struct{ Name, Value string }

// Node is an XML element.
type Node struct {
	Name     string
	Attrs    []Attr
	Text     string
	Children []*Node
}

// maxDepth bounds parsing so hostile XML cannot exhaust the stack.
const maxDepth = 128

// ParseNode parses a document with exactly one root element.
func ParseNode(b []byte) (*Node, error) {
	ns, err := ParseFragment(b)
	if err != nil {
		return nil, err
	}
	if len(ns) != 1 {
		return nil, fmt.Errorf("xmlapi: want one root element, got %d", len(ns))
	}
	return ns[0], nil
}

// ParseFragment parses zero or more sibling elements.
func ParseFragment(b []byte) ([]*Node, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = false
	root := &Node{}
	stack := []*Node{root}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("xmlapi: parse: %w", err)
		}
		cur := stack[len(stack)-1]
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) > maxDepth {
				return nil, errors.New("xmlapi: nesting too deep")
			}
			n := &Node{Name: t.Name.Local}
			for _, a := range t.Attr {
				n.Attrs = append(n.Attrs, Attr{a.Name.Local, a.Value})
			}
			cur.Children = append(cur.Children, n)
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			cur.Text += string(t)
		}
	}
	if len(stack) != 1 {
		return nil, errors.New("xmlapi: unclosed element")
	}
	for _, n := range root.Children {
		n.trim()
	}
	return root.Children, nil
}

func (n *Node) trim() {
	n.Text = strings.TrimSpace(n.Text)
	for _, c := range n.Children {
		c.trim()
	}
}

// Attr returns an attribute value or "".
func (n *Node) Attr(name string) string {
	for _, a := range n.Attrs {
		if a.Name == name {
			return a.Value
		}
	}
	return ""
}

// SetAttr sets or adds an attribute.
func (n *Node) SetAttr(name, v string) {
	for i := range n.Attrs {
		if n.Attrs[i].Name == name {
			n.Attrs[i].Value = v
			return
		}
	}
	n.Attrs = append(n.Attrs, Attr{name, v})
}

// Child returns the first child named name.
func (n *Node) Child(name string) *Node {
	if n == nil {
		return nil
	}
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// ChildText is Child(name).Text or "".
func (n *Node) ChildText(name string) string {
	if c := n.Child(name); c != nil {
		return c.Text
	}
	return ""
}

// Clone deep-copies the node.
func (n *Node) Clone() *Node {
	if n == nil {
		return nil
	}
	c := &Node{Name: n.Name, Text: n.Text, Attrs: append([]Attr(nil), n.Attrs...)}
	for _, ch := range n.Children {
		c.Children = append(c.Children, ch.Clone())
	}
	return c
}

// Marshal serialises the node.
func (n *Node) Marshal() []byte {
	var b bytes.Buffer
	n.write(&b)
	return b.Bytes()
}

func (n *Node) String() string { return string(n.Marshal()) }

func (n *Node) write(b *bytes.Buffer) {
	b.WriteByte('<')
	b.WriteString(n.Name)
	for _, a := range n.Attrs {
		b.WriteByte(' ')
		b.WriteString(a.Name)
		b.WriteString(`="`)
		_ = xml.EscapeText(b, []byte(a.Value))
		b.WriteByte('"')
	}
	if len(n.Children) == 0 && n.Text == "" {
		b.WriteString("/>")
		return
	}
	b.WriteByte('>')
	_ = xml.EscapeText(b, []byte(n.Text))
	for _, c := range n.Children {
		c.write(b)
	}
	b.WriteString("</")
	b.WriteString(n.Name)
	b.WriteByte('>')
}

// ---- xpath ----

// Step is one xpath step: name and, for entry[@name='x'], the entry name.
type Step struct{ Name, Entry string }

// ParseXPath parses /a/b/entry[@name='x']/c. '/' inside a quoted entry name
// (an IP prefix) does not split the path.
func ParseXPath(x string) ([]Step, error) {
	if !strings.HasPrefix(x, "/") {
		return nil, fmt.Errorf("xmlapi: xpath %q must be absolute", x)
	}
	var parts []string
	depth := 0
	var quote byte
	start := 1
	for i := 1; i < len(x); i++ {
		ch := x[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '\'' || ch == '"':
			quote = ch
		case ch == '[':
			depth++
		case ch == ']':
			depth--
		case ch == '/' && depth == 0:
			parts = append(parts, x[start:i])
			start = i + 1
		}
	}
	parts = append(parts, x[start:])
	var steps []Step
	for _, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("xmlapi: empty step in %q", x)
		}
		name, pred, has := strings.Cut(p, "[")
		st := Step{Name: name}
		if has {
			pred = strings.TrimSuffix(pred, "]")
			v, ok := strings.CutPrefix(pred, "@name=")
			if !ok || len(v) < 2 {
				return nil, fmt.Errorf("xmlapi: unsupported predicate %q", p)
			}
			st.Entry = v[1 : len(v)-1]
		}
		steps = append(steps, st)
	}
	return steps, nil
}

// EntryXPath appends entry[@name='name'] to parent.
func EntryXPath(parent, name string) string {
	return parent + "/entry[@name='" + name + "']"
}

func (s Step) match(n *Node) bool {
	return n.Name == s.Name && (s.Entry == "" || n.Attr("name") == s.Entry)
}

// Select finds the node at steps; the first step names the root itself.
func (n *Node) Select(steps []Step) *Node {
	if len(steps) == 0 || !steps[0].match(n) {
		return nil
	}
	cur := n
	for _, st := range steps[1:] {
		var next *Node
		for _, c := range cur.Children {
			if st.match(c) {
				next = c
				break
			}
		}
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}

// SelectParent returns the parent of the node at steps and the last step.
func (n *Node) SelectParent(steps []Step) (*Node, Step) {
	if len(steps) < 2 {
		return nil, Step{}
	}
	return n.Select(steps[:len(steps)-1]), steps[len(steps)-1]
}

// EnsurePath creates the nodes along steps (after the root) and returns the last.
func (n *Node) EnsurePath(steps []Step) *Node {
	if len(steps) == 0 || steps[0].Name != n.Name {
		return nil
	}
	cur := n
	for _, st := range steps[1:] {
		var next *Node
		for _, c := range cur.Children {
			if st.match(c) {
				next = c
				break
			}
		}
		if next == nil {
			next = &Node{Name: st.Name}
			if st.Entry != "" {
				next.SetAttr("name", st.Entry)
			}
			cur.Children = append(cur.Children, next)
		}
		cur = next
	}
	return cur
}

// Remove deletes the child matching the step.
func (n *Node) Remove(st Step) bool {
	for i, c := range n.Children {
		if st.match(c) {
			n.Children = append(n.Children[:i], n.Children[i+1:]...)
			return true
		}
	}
	return false
}

// Merge merges src into n like the XML API "set": entries and members with the
// same identity merge, other children append.
func (n *Node) Merge(src *Node) {
	if src.Text != "" {
		n.Text = src.Text
	}
	for _, a := range src.Attrs {
		n.SetAttr(a.Name, a.Value)
	}
	for _, sc := range src.Children {
		var dst *Node
		for _, c := range n.Children {
			if c.Name != sc.Name {
				continue
			}
			if sc.Attr("name") != "" && c.Attr("name") == sc.Attr("name") {
				dst = c
				break
			}
			if sc.Attr("name") == "" && len(sc.Children) == 0 && c.Text == sc.Text && len(c.Children) == 0 {
				dst = c // same member
				break
			}
			if sc.Attr("name") == "" && len(sc.Children) > 0 {
				dst = c
				break
			}
		}
		if dst == nil {
			n.Children = append(n.Children, sc.Clone())
			continue
		}
		dst.Merge(sc)
	}
}

// ---- canonical form ----

// volatileAttrs change without the configuration changing.
var volatileAttrs = map[string]bool{"admin": true, "dirtyId": true, "time": true}

// Strip removes volatile attributes in place.
func (n *Node) Strip() {
	kept := n.Attrs[:0]
	for _, a := range n.Attrs {
		if !volatileAttrs[a.Name] {
			kept = append(kept, a)
		}
	}
	n.Attrs = kept
	for _, c := range n.Children {
		c.Strip()
	}
}

// Canonical is a deterministic serialisation without volatile attributes.
func Canonical(n *Node) []byte {
	c := n.Clone()
	c.Strip()
	c.sortAttrs()
	return c.Marshal()
}

func (n *Node) sortAttrs() {
	sort.Slice(n.Attrs, func(i, j int) bool { return n.Attrs[i].Name < n.Attrs[j].Name })
	for _, c := range n.Children {
		c.sortAttrs()
	}
}

// Flatten turns the tree into path -> text. Repeated plain members become
// path[member]=""; entries become entry[@name='x'].
func Flatten(n *Node) map[string]string {
	out := map[string]string{}
	n.flatten("", out)
	return out
}

func (n *Node) flatten(prefix string, out map[string]string) {
	p := prefix + "/" + n.Name
	if nm := n.Attr("name"); nm != "" {
		p += "[@name='" + nm + "']"
	}
	if n.Name == "member" && len(n.Children) == 0 {
		out[prefix+"/member["+n.Text+"]"] = ""
		return
	}
	if len(n.Children) == 0 {
		out[p] = n.Text
		return
	}
	for _, c := range n.Children {
		c.flatten(p, out)
	}
}
