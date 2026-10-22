package vault

import (
	"fmt"
	"log/slog"
	"runtime"
)

// Redacted is what every textual rendering of a Secret produces.
const Redacted = "[REDACTED]"

// Secret holds sensitive bytes. Every formatting path (fmt verbs, JSON, text,
// slog) prints Redacted; the only way to read the value is Reveal/Bytes, which
// makes leaks greppable. Zero wipes the buffer.
type Secret struct{ b []byte }

// NewSecret copies v into a new Secret.
func NewSecret(v []byte) Secret { return Secret{b: append([]byte(nil), v...)} }

// NewSecretString copies s into a new Secret.
func NewSecretString(s string) Secret { return Secret{b: []byte(s)} }

// Reveal returns the value as a string (a copy the caller cannot wipe).
func (s Secret) Reveal() string { return string(s.b) }

// Bytes returns a copy of the value; the caller should wipe it with Wipe.
func (s Secret) Bytes() []byte { return append([]byte(nil), s.b...) }

// Len is the value length in bytes.
func (s Secret) Len() int { return len(s.b) }

// IsZero reports whether the secret is empty.
func (s Secret) IsZero() bool { return len(s.b) == 0 }

// Equal compares two secrets in constant time with respect to content.
func (s Secret) Equal(o Secret) bool { return ctEqual(s.b, o.b) }

// Zero wipes the underlying buffer. Copies made by Bytes/Reveal are unaffected.
func (s *Secret) Zero() { Wipe(s.b); s.b = nil }

func (Secret) String() string               { return Redacted }
func (Secret) GoString() string             { return "vault.Secret(" + Redacted + ")" }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte(Redacted), nil }
func (Secret) LogValue() slog.Value         { return slog.StringValue(Redacted) }

// Format implements fmt.Formatter so that no verb (%v %+v %#v %s %q %x %d)
// can print the contents.
func (Secret) Format(f fmt.State, verb rune) { _, _ = f.Write([]byte(Redacted)) }

// UnmarshalJSON refuses to load a secret from JSON: persistence goes through
// the vault's own encrypted format, never through Secret's marshalers.
func (*Secret) UnmarshalJSON([]byte) error {
	return fmt.Errorf("vault: Secret cannot be unmarshaled; use vault.Get")
}

// Wipe zeroes b (best effort; the compiler is told b is still live).
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func ctEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// RedactString masks every occurrence of the given secret values in s. Use it
// on free text (error messages, command lines) before logging.
func RedactString(s string, secrets ...Secret) string {
	for _, sec := range secrets {
		if sec.Len() < 4 { // too short to redact meaningfully without mangling text
			continue
		}
		s = replaceAll(s, sec.Reveal(), Redacted)
	}
	return s
}

func replaceAll(s, old, new string) string {
	if old == "" {
		return s
	}
	var out []byte
	for i := 0; i < len(s); {
		if len(s)-i >= len(old) && s[i:i+len(old)] == old {
			out = append(out, new...)
			i += len(old)
			continue
		}
		out = append(out, s[i])
		i++
	}
	return string(out)
}
