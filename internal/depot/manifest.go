// Package depot is the trusted tool depot: a signed manifest of known-good
// command binaries, a content-addressed store, deployment to a hidden
// directory on a host, and hash-verified execution with a sanitised
// environment. Operators and Phylax must not trust host tools during a
// response (the red team replaces them), so tools come from here.
// See phylax_design.md, "Trusted tool depot".
package depot

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/integrity"
)

// Entry describes one tool binary for one OS and architecture.
type Entry struct {
	Name     string   `json:"name"`               // tool name, e.g. "busybox"
	Version  string   `json:"version"`            // upstream version
	OS       string   `json:"os"`                 // GOOS value
	Arch     string   `json:"arch"`               // GOARCH value
	SHA256   string   `json:"sha256"`             // hex; empty only for FetchAtInit pins before first fetch
	Size     int64    `json:"size"`               // bytes
	URL      string   `json:"url,omitempty"`      // vendor download (FetchAtInit) or upstream source tarball
	License  string   `json:"license"`            // SPDX identifier
	Recipe   string   `json:"recipe,omitempty"`   // build recipe, relative to depot/recipes
	Source   string   `json:"source,omitempty"`   // source reference (required for copyleft tools)
	Provides []string `json:"provides,omitempty"` // multi-call applet names (busybox)
	// FetchAtInit marks tools that may not be redistributed (Sysinternals):
	// the manifest carries a pinned hash and URL, and `phylax init` fetches
	// the file from the vendor into the controller cache.
	FetchAtInit bool `json:"fetch_at_init,omitempty"`
}

// File is the on-disk name of the tool.
func (e Entry) File() string {
	if e.OS == "windows" && !strings.HasSuffix(e.Name, ".exe") {
		return e.Name + ".exe"
	}
	return e.Name
}

// Manifest is the signed body.
type Manifest struct {
	Format  int     `json:"format"`
	Created string  `json:"created,omitempty"` // RFC 3339, informational
	Tools   []Entry `json:"tools"`
}

const formatVersion = 1

var (
	ErrNotFound = errors.New("depot: tool not found")
	ErrNoSig    = errors.New("depot: manifest is unsigned")
)

// Validate checks structural invariants. A manifest that fails is never used.
func (m *Manifest) Validate() error {
	if m.Format != formatVersion {
		return fmt.Errorf("depot: unsupported manifest format %d", m.Format)
	}
	seen := map[string]bool{}
	for i, e := range m.Tools {
		if e.Name == "" || strings.ContainsAny(e.Name, "/\\\x00") || e.Name == "." || e.Name == ".." {
			return fmt.Errorf("depot: tool %d: bad name %q", i, e.Name)
		}
		if e.OS == "" || e.Arch == "" || e.License == "" || e.Version == "" {
			return fmt.Errorf("depot: tool %q: os, arch, version and license are required", e.Name)
		}
		if e.SHA256 != "" {
			if b, err := hex.DecodeString(e.SHA256); err != nil || len(b) != sha256.Size {
				return fmt.Errorf("depot: tool %q: bad sha256", e.Name)
			}
		} else if !e.FetchAtInit {
			return fmt.Errorf("depot: tool %q: sha256 required", e.Name)
		}
		for _, p := range e.Provides {
			if p == "" || strings.ContainsAny(p, "/\\\x00") || p == "." || p == ".." {
				return fmt.Errorf("depot: tool %q: bad applet %q", e.Name, p)
			}
		}
		k := e.OS + "/" + e.Arch + "/" + e.Name
		if seen[k] {
			return fmt.Errorf("depot: duplicate tool %s", k)
		}
		seen[k] = true
	}
	return nil
}

// For returns the entries for one platform, sorted by name.
func (m *Manifest) For(goos, goarch string) []Entry {
	var out []Entry
	for _, e := range m.Tools {
		if e.OS == goos && e.Arch == goarch {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Lookup resolves a command name on a platform: an exact tool name first, then
// a multi-call applet. applet is the name to use as argv[0].
func (m *Manifest) Lookup(goos, goarch, name string) (e Entry, applet string, err error) {
	es := m.For(goos, goarch)
	for _, c := range es {
		if c.Name == name {
			return c, name, nil
		}
	}
	for _, c := range es {
		for _, p := range c.Provides {
			if p == name {
				return c, name, nil
			}
		}
	}
	return Entry{}, "", fmt.Errorf("%w: %s (%s/%s)", ErrNotFound, name, goos, goarch)
}

// Signed is the manifest file: the exact body bytes plus a signature over them.
type Signed struct {
	Body json.RawMessage `json:"body"`
	Sig  string          `json:"sig,omitempty"` // base64 ed25519 over domain || body
}

const sigDomain = "phylax-depot-manifest-v1\n"

func signedMessage(body []byte) []byte { return append([]byte(sigDomain), body...) }

// Sign encodes and signs the manifest with the release key.
func Sign(m *Manifest, sg integrity.Signer) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	body, err := marshal(m)
	if err != nil {
		return nil, err
	}
	sig, err := sg.Sign(signedMessage(body))
	if err != nil {
		return nil, err
	}
	return marshal(Signed{Body: body, Sig: base64.StdEncoding.EncodeToString(sig)})
}

// marshal encodes without HTML escaping, so the signed body bytes survive
// being embedded in the outer document unchanged (URLs contain '&').
func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// Parse verifies the signature (v must be non-nil; an unsigned or tampered
// manifest is refused) and decodes the body.
func Parse(data []byte, v integrity.Verifier) (*Manifest, error) {
	if v == nil {
		return nil, errors.New("depot: a verifier is required")
	}
	var s Signed
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("depot: manifest: %w", err)
	}
	if s.Sig == "" {
		return nil, ErrNoSig
	}
	sig, err := base64.StdEncoding.DecodeString(s.Sig)
	if err != nil {
		return nil, fmt.Errorf("depot: manifest signature: %w", err)
	}
	if err := v.Verify(signedMessage(s.Body), sig); err != nil {
		return nil, err
	}
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(s.Body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("depot: manifest body: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}
