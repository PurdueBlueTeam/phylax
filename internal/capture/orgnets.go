package capture

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
)

// The network lists ship in the repository as orgnets.json (embedded, so the
// agent needs no network access) and can be replaced per host by an
// orgnets.json in the agent state directory. See docs/capture.md, "Updating
// the network lists", for how to regenerate the file (cmd/orgnetgen).

//go:embed orgnets.json
var embeddedOrgNets []byte

// OrgNetFile is the on-disk format.
type OrgNetFile struct {
	Comment   string   `json:"comment,omitempty"`
	Generated string   `json:"generated,omitempty"`
	Sources   []string `json:"sources,omitempty"`
	Nets      []struct {
		Org   string   `json:"org"`
		Cloud bool     `json:"cloud,omitempty"`
		CIDRs []string `json:"cidrs"`
	} `json:"nets"`
}

// maxOrgCIDRs bounds a list file, so a bad regeneration cannot make every
// HTTP event scan a huge slice.
const maxOrgCIDRs = 60000

// ParseOrgNets reads and validates a list file.
func ParseOrgNets(r io.Reader) ([]OrgNet, error) {
	var f OrgNetFile
	dec := json.NewDecoder(io.LimitReader(r, 32<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("capture: org nets: %w", err)
	}
	var out []OrgNet
	total := 0
	for _, n := range f.Nets {
		for _, c := range n.CIDRs {
			if _, err := netip.ParsePrefix(c); err != nil {
				return nil, fmt.Errorf("capture: org nets: %q: bad CIDR %q", n.Org, c)
			}
		}
		total += len(n.CIDRs)
		out = append(out, OrgNet{Org: n.Org, Cloud: n.Cloud, CIDRs: n.CIDRs})
	}
	if total > maxOrgCIDRs {
		return nil, fmt.Errorf("capture: org nets: %d prefixes exceeds %d", total, maxOrgCIDRs)
	}
	if _, err := NewHTTPEvents(out); err != nil { // org names, prefix syntax
		return nil, err
	}
	return out, nil
}

// DefaultOrgNets returns the lists shipped in the repository.
func DefaultOrgNets() []OrgNet {
	var out []OrgNet
	f := OrgNetFile{}
	if err := json.Unmarshal(embeddedOrgNets, &f); err != nil {
		panic("capture: embedded orgnets.json: " + err.Error())
	}
	for _, n := range f.Nets {
		out = append(out, OrgNet{Org: n.Org, Cloud: n.Cloud, CIDRs: n.CIDRs})
	}
	return out
}

// LoadOrgNets reads path, falling back to the shipped lists when the file
// does not exist. A file that exists but is invalid is an error (a silent
// fallback would hide a broken regeneration).
func LoadOrgNets(path string) ([]OrgNet, error) {
	fh, err := os.Open(path)
	if os.IsNotExist(err) {
		return DefaultOrgNets(), nil
	}
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	return ParseOrgNets(fh)
}

// WriteOrgNets writes a list file with stable ordering (used by cmd/orgnetgen).
func WriteOrgNets(w io.Writer, f OrgNetFile) error {
	sort.SliceStable(f.Nets, func(i, j int) bool { return f.Nets[i].Org < f.Nets[j].Org })
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(f)
}
