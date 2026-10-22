package lines

import (
	"bytes"
	"encoding/base64"
	"strings"
)

// MaxList bounds every per-session list a text parser keeps.
const MaxList = 256

// DecodePlain decodes a SASL PLAIN initial response (base64 of
// authzid NUL authcid NUL passwd).
func DecodePlain(b64 string) (user, pass string, ok bool) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", "", false
	}
	parts := bytes.Split(raw, []byte{0})
	if len(parts) != 3 {
		return "", "", false
	}
	return string(parts[1]), string(parts[2]), true
}

// DecodeB64 decodes one SASL LOGIN line.
func DecodeB64(b64 string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", false
	}
	return string(raw), true
}

// Verb splits "VERB args" and upper-cases the verb.
func Verb(line string) (verb, arg string) {
	line = strings.TrimLeft(line, " \t")
	v, a, _ := strings.Cut(line, " ")
	return strings.ToUpper(v), strings.TrimSpace(a)
}

// Push appends to a bounded list.
func Push(l []string, s string) []string {
	if len(l) >= MaxList {
		return l
	}
	return append(l, s)
}
