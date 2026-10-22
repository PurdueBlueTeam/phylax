package detect

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"gopkg.in/yaml.v3"
)

// RuleSet is a validated, compiled set of rules and profile declarations.
type RuleSet struct {
	Rules    []*Rule
	profiles map[string]*profileDef
}

// LoadOptions tune loading.
type LoadOptions struct {
	// AllowUntested accepts rules with no tests (used for rules/pending).
	AllowUntested bool
}

type rawDoc struct {
	d    ruleDoc
	file string
	idx  int
}

// Parse loads rule documents from one YAML stream; name is used in errors.
func Parse(name string, data []byte, o LoadOptions) (*RuleSet, error) {
	return load([]namedData{{name, data}}, o)
}

type namedData struct {
	name string
	data []byte
}

// LoadDir loads every *.yml / *.yaml file directly in dir (not subdirectories;
// pending rules live in a subdirectory and are loaded explicitly).
func LoadDir(dir string, o LoadOptions) (*RuleSet, error) {
	var files []string
	for _, pat := range []string{"*.yml", "*.yaml"} {
		m, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			return nil, err
		}
		files = append(files, m...)
	}
	sort.Strings(files)
	var nd []namedData
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		nd = append(nd, namedData{f, b})
	}
	return load(nd, o)
}

func load(files []namedData, o LoadOptions) (*RuleSet, error) {
	var errs []error
	var docs []rawDoc
	for _, f := range files {
		dec := yaml.NewDecoder(bytes.NewReader(f.data))
		dec.KnownFields(true)
		for i := 0; ; i++ {
			var d ruleDoc
			err := dec.Decode(&d)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: document %d: %w", f.name, i+1, err))
				break
			}
			docs = append(docs, rawDoc{d, f.name, i + 1})
		}
	}
	env := &compileEnv{profiles: map[string]*profileDef{}}
	for i := range docs {
		for j := range docs[i].d.Profiles {
			pd, err := env.compileProfile(&docs[i].d.Profiles[j])
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", docs[i].file, err))
				continue
			}
			if _, dup := env.profiles[pd.Name]; dup {
				errs = append(errs, fmt.Errorf("%s: duplicate profile %q", docs[i].file, pd.Name))
				continue
			}
			env.profiles[pd.Name] = pd
		}
	}
	rs := &RuleSet{profiles: env.profiles}
	ids := map[string]string{}
	for i := range docs {
		d := &docs[i].d
		if d.ID == "" {
			if len(d.Profiles) == 0 {
				errs = append(errs, fmt.Errorf("%s: document %d has neither id nor profiles", docs[i].file, docs[i].idx))
			}
			continue
		}
		if prev, dup := ids[d.ID]; dup {
			errs = append(errs, fmt.Errorf("%s: duplicate rule id %s (also in %s)", docs[i].file, d.ID, prev))
			continue
		}
		ids[d.ID] = docs[i].file
		r, err := env.compileRule(d, docs[i].file)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", docs[i].file, err))
			continue
		}
		if err := compileTests(r, d.Tests, env, o); err != nil {
			errs = append(errs, fmt.Errorf("%s: rule %s: %w", docs[i].file, r.ID, err))
			continue
		}
		rs.Rules = append(rs.Rules, r)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return rs, nil
}

func compileTests(r *Rule, ts []testDoc, env *compileEnv, o LoadOptions) error {
	var pos, neg int
	for i, t := range ts {
		if t.Name == "" || t.ShouldMatch == nil {
			return fmt.Errorf("tests[%d]: name and should_match are required", i)
		}
		tc := TestCase{Name: t.Name, ShouldMatch: *t.ShouldMatch}
		evs := t.Events
		if t.Event != nil {
			evs = append([]testEvent{*t.Event}, evs...)
		}
		if len(evs) == 0 {
			return fmt.Errorf("test %q: no events", t.Name)
		}
		for j, te := range evs {
			if te.Kind == "" {
				return fmt.Errorf("test %q event %d: kind is required", t.Name, j)
			}
			var at time.Duration
			if te.At != "" {
				d, err := time.ParseDuration(te.At)
				if err != nil {
					return fmt.Errorf("test %q event %d: bad at %q", t.Name, j, te.At)
				}
				at = d
			}
			tc.Events = append(tc.Events, event.Event{Agent: te.Agent, Kind: te.Kind, Fields: normFields(te.Fields)})
			tc.Offsets = append(tc.Offsets, at)
		}
		if t.Seed.Kind != 0 {
			var m map[string]any
			if err := t.Seed.Decode(&m); err != nil {
				return fmt.Errorf("test %q seed: %v", t.Name, err)
			}
			for prof, v := range m {
				if _, ok := env.profiles[prof]; !ok {
					return fmt.Errorf("test %q seed: unknown profile %q", t.Name, prof)
				}
				switch x := v.(type) {
				case []any:
					tc.Seed = append(tc.Seed, seedSpec{Profile: prof, Values: strs(x)})
				case map[string]any: // key -> values; composite keys joined with "|"
					for k, vv := range x {
						l, _ := vv.([]any)
						tc.Seed = append(tc.Seed, seedSpec{Profile: prof, Key: splitKey(k), Values: strs(l)})
					}
				default:
					return fmt.Errorf("test %q seed %q: want a list or a key map", t.Name, prof)
				}
			}
		}
		if tc.ShouldMatch {
			pos++
		} else {
			neg++
		}
		r.Tests = append(r.Tests, tc)
	}
	if !o.AllowUntested && (pos == 0 || neg == 0) {
		return fmt.Errorf("needs at least one should_match true and one false test (has %d/%d)", pos, neg)
	}
	return nil
}

func splitKey(k string) []string {
	var out []string
	cur := ""
	for _, c := range k {
		if c == '|' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	return append(out, cur)
}

func strs(l []any) []string {
	var out []string
	for _, x := range l {
		s, _ := toStr(x)
		out = append(out, s)
	}
	return out
}

// normFields makes YAML-decoded test fields look like producer fields: nested
// maps stay maps; ints stay ints.
func normFields(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// TestResult is the outcome of one inline test.
type TestResult struct {
	Rule, Test string
	Err        error
}

// RunTests runs every rule's inline tests, each on a fresh engine containing
// only that rule (plus all profiles).
func (rs *RuleSet) RunTests() []TestResult {
	var out []TestResult
	base := time.Date(2027, 2, 6, 12, 0, 0, 0, time.UTC)
	for _, r := range rs.Rules {
		for _, tc := range r.Tests {
			sub := &RuleSet{Rules: []*Rule{r}, profiles: rs.profiles}
			eng := NewEngine(sub, Options{})
			for _, s := range tc.Seed {
				if err := eng.Seed(s.Profile, append([]string(nil), s.Key...), s.Values...); err != nil {
					out = append(out, TestResult{r.ID, tc.Name, err})
				}
			}
			fired := 0
			for i, ev := range tc.Events {
				ev.Time = base.Add(tc.Offsets[i])
				for _, a := range eng.Process(ev) {
					if a.RuleID == r.ID {
						fired++
					}
				}
			}
			var err error
			if tc.ShouldMatch && fired == 0 {
				err = fmt.Errorf("expected an alert, got none")
			} else if !tc.ShouldMatch && fired > 0 {
				err = fmt.Errorf("expected no alert, got %d", fired)
			}
			out = append(out, TestResult{r.ID, tc.Name, err})
		}
	}
	return out
}
