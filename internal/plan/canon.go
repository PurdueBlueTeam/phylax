// Package plan models change plans (a DAG of typed action nodes), schedules
// them, and defines the signed Step / StepResult messages exchanged with agents.
package plan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"unicode/utf16"
)

const (
	maxCanonDepth = 64
	maxSafeInt    = 1 << 53
)

// Canonicalize re-encodes JSON per RFC 8785 (JCS), restricted to the subset
// Phylax uses: numbers must be integers within +-2^53 (no floats, so no
// number-formatting ambiguity), objects must not repeat keys, and the input
// must be exactly one value. Output is byte-identical for equal values.
func Canonicalize(in []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.UseNumber()
	v, err := parseValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("canon: trailing data after value")
	}
	var out bytes.Buffer
	if err := emit(&out, v); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func parseValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxCanonDepth {
		return nil, errors.New("canon: nesting too deep")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("canon: %w", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			m := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("canon: %w", err)
				}
				k, ok := kt.(string)
				if !ok {
					return nil, errors.New("canon: non-string key")
				}
				if _, dup := m[k]; dup {
					return nil, fmt.Errorf("canon: duplicate key %q", k)
				}
				v, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			if _, err := dec.Token(); err != nil {
				return nil, fmt.Errorf("canon: %w", err)
			}
			return m, nil
		case '[':
			arr := []any{}
			for dec.More() {
				v, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, fmt.Errorf("canon: %w", err)
			}
			return arr, nil
		}
		return nil, errors.New("canon: unexpected delimiter")
	case json.Number:
		bi, ok := new(big.Int).SetString(t.String(), 10)
		if !ok {
			return nil, fmt.Errorf("canon: non-integer number %q", t.String())
		}
		if bi.CmpAbs(big.NewInt(maxSafeInt)) > 0 {
			return nil, fmt.Errorf("canon: integer %s out of safe range", t.String())
		}
		return numStr(bi.String()), nil
	default:
		return tok, nil // string, bool, nil
	}
}

// numStr is a validated canonical integer literal.
type numStr string

func emit(b *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case numStr:
		b.WriteString(string(t))
	case string:
		emitString(b, t)
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := emit(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			emitString(b, k)
			b.WriteByte(':')
			if err := emit(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("canon: unsupported type %T", v)
	}
	return nil
}

func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func emitString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}
