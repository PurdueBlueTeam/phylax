package creds

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

func TestGeneratorPolicy(t *testing.T) {
	g := NewGenerator()
	for _, c := range []Class{Scored, Unscored, Admin} {
		min, max := c.LengthRange()
		lens := map[int]bool{}
		for i := 0; i < 500; i++ {
			s, err := g.Generate(c, "sysadmin")
			if err != nil {
				t.Fatal(err)
			}
			pw := s.Reveal()
			if len(pw) < min || len(pw) > max {
				t.Fatalf("%v: len %d", c, len(pw))
			}
			lens[len(pw)] = true
			if err := c.Check(pw); err != nil {
				t.Fatalf("%v %q: %v", c, pw, err)
			}
			if err := PCRSafe("alice", pw); err != nil {
				t.Fatalf("%v %q not PCR safe: %v", c, pw, err)
			}
			if strings.ContainsAny(pw, "@:/,\"'\\ $`;&|<>()!*~{}[]") {
				t.Fatalf("%v unsafe char in %q", c, pw)
			}
			if strings.Contains(strings.ToLower(pw), "sysadmin") {
				t.Fatal("contains account name")
			}
			if c == Scored && strings.ContainsAny(pw, "#%^") {
				t.Fatalf("scored uses extended symbols: %q", pw)
			}
		}
		if len(lens) < (max-min)/2 {
			t.Fatalf("%v: length does not vary: %v", c, lens)
		}
	}
}

func TestGeneratorUniqueness(t *testing.T) {
	g := NewGenerator()
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		s, _ := g.Generate(Scored)
		k := strings.ToLower(s.Reveal())
		if seen[k] {
			t.Fatal("duplicate")
		}
		seen[k] = true
	}
	if err := g.Reserve("Abc.def-123.XYZ.pq9"); err != nil {
		t.Fatal(err)
	}
	if err := g.Reserve("abc.DEF-123.xyz.PQ9"); !errors.Is(err, ErrDuplicate) {
		t.Fatal("case-insensitive duplicate must be refused")
	}
	g.Release("abc.def-123.xyz.pq9")
	if err := g.Reserve("Abc.def-123.XYZ.pq9"); err != nil {
		t.Fatal(err)
	}
}

func TestGeneratorCharDistributionRoughlyUniform(t *testing.T) {
	g := NewGenerator()
	cnt := map[byte]int{}
	total := 0
	for i := 0; i < 3000; i++ {
		s, _ := g.Generate(Scored)
		for _, b := range []byte(s.Reveal()) {
			cnt[b]++
			total++
		}
	}
	set := Scored.Charset()
	exp := float64(total) / float64(len(set))
	for _, ch := range []byte(set) {
		if f := float64(cnt[ch]); f < exp*0.75 || f > exp*1.35 {
			t.Fatalf("char %q count %v vs expected %.0f", ch, f, exp)
		}
	}
}

func TestCheckRejects(t *testing.T) {
	bad := []string{
		"Short1.a",                 // too short
		"Abcdefghij1234567.",       // ends with symbol
		"-Abcdefghij12345678",      // starts with symbol
		"Abcdefghij 12345678.a",    // space
		"Abcdefghij,12345678.a",    // comma
		"Abcdefghij@12345678.a",    // @
		"abcdefghijklmnop1234.5",   // no upper
		"ABCDEFGHIJKLMNOP1234.5",   // no lower
		"Abcdefghijklmnopqrst.-+",  // no digit... and ends w/ symbol
		"Abcdefghijklmnop12345678", // no symbol
		"Abcdefghij'1234567.a",
	}
	for _, p := range bad {
		if Scored.Check(p) == nil {
			t.Errorf("accepted %q", p)
		}
	}
	if err := Scored.Check("Abcdefghij.1234567z"); err != nil {
		t.Fatal(err)
	}
}

func TestPCRSafe(t *testing.T) {
	for _, pw := range []string{"a,b", `a"b`, "a'b", `a\b`, " ab", "ab ", "a\nb", "", "pässword", "a\tb"} {
		if PCRSafe("alice", pw) == nil {
			t.Errorf("accepted %q", pw)
		}
	}
	if PCRSafe("al,ice", "pw.ok-1") == nil || PCRSafe(" alice", "pw") == nil || PCRSafe("", "pw") == nil {
		t.Error("username not validated")
	}
	if err := PCRSafe("Alice", "Pw.ok-1+="); err != nil {
		t.Fatal(err)
	}
}

const bgSecret = "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY-Z2345"

func TestBreakGlassDeterministicAndPolicy(t *testing.T) {
	a, err := DeriveBreakGlass(bgSecret, "web01", "root", 1)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := DeriveBreakGlass(strings.ToLower(strings.ReplaceAll(bgSecret, "-", " ")), "WEB01", "Root", 1)
	if a.Reveal() != b.Reveal() {
		t.Fatal("not deterministic / normalisation")
	}
	pw := a.Reveal()
	if len(pw) != BreakGlassLength {
		t.Fatal(len(pw))
	}
	if err := Scored.Check(pw); err != nil {
		t.Fatal(err)
	}
	if err := PCRSafe("root", pw); err != nil {
		t.Fatal(err)
	}
	// Known-answer regression: the derivation is a stable external contract
	// (printed sheets must keep working), so pin it.
	if pw != knownAnswer {
		t.Fatalf("derivation changed: got %q", pw)
	}
}

const knownAnswer = "Te+37=ghSGxb0IdkayydCtCX"

func TestBreakGlassIndependence(t *testing.T) {
	seen := map[string]string{}
	add := func(label, secret string, host, user string, epoch uint32) {
		s, err := DeriveBreakGlass(secret, host, user, epoch)
		if err != nil {
			t.Fatal(err)
		}
		if prev, dup := seen[s.Reveal()]; dup {
			t.Fatalf("%s collides with %s", label, prev)
		}
		seen[s.Reveal()] = label
	}
	hosts := []string{"web01", "web02", "dc01", "db01"}
	users := []string{"root", "administrator", "sysadmin", "mysql"}
	for _, h := range hosts {
		for _, u := range users {
			add(h+"/"+u, bgSecret, h, u, 1)
		}
	}
	add("epoch2", bgSecret, "web01", "root", 2)
	add("othersecret", "ZZZZZ-FGHIJ-KLMNO-PQRST-UVWXY-Z2345", "web01", "root", 1)
	// Field boundaries are length-prefixed: ("ab","c") != ("a","bc").
	add("ab|c", bgSecret, "ab", "c", 1)
	add("a|bc", bgSecret, "a", "bc", 1)
}

func TestBreakGlassSecretHandling(t *testing.T) {
	if _, err := DeriveBreakGlass("SHORT", "h", "u", 1); err == nil {
		t.Fatal("short secret accepted")
	}
	if _, err := DeriveBreakGlass(bgSecret, "", "u", 1); err == nil {
		t.Fatal("empty host accepted")
	}
	s1, _ := NewBreakGlassSecret()
	s2, _ := NewBreakGlassSecret()
	if s1 == s2 || len(strings.ReplaceAll(s1, "-", "")) != 32 {
		t.Fatal(s1, s2)
	}
	if _, err := DeriveBreakGlass(s1, "h", "u", 1); err != nil {
		t.Fatal(err)
	}
}

func TestBreakGlassAlwaysCompliant(t *testing.T) {
	for i := 0; i < 2000; i++ {
		s, err := DeriveBreakGlass(bgSecret, fmt.Sprintf("host%d", i), "u", uint32(i))
		if err != nil {
			t.Fatal(err)
		}
		if err := Scored.Check(s.Reveal()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRecordModel(t *testing.T) {
	r := Record{Account: "Alice", Host: "WEB01", Scored: true, Credlist: "web.credlist", PCRState: PCRStable}
	if r.VaultKey() != "cred/web01/Alice" || r.Class() != Scored {
		t.Fatal(r.VaultKey())
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	r.CurrentVersion = "v1"
	r.MarkRotated("v2", time.Unix(5, 0))
	if r.CurrentVersion != "v2" || r.PreviousVersion != "v1" || r.LastRotated.Unix() != 5 {
		t.Fatal(r)
	}
	if err := r.MarkRolledBack(); err != nil || r.CurrentVersion != "v1" || r.PreviousVersion != "v2" {
		t.Fatal(r)
	}
	for _, bad := range []Record{
		{Host: "h"}, {Account: "a"},
		{Account: "a", Host: "h", Scored: true},
		{Account: "a", Host: "h", PCRState: PCRStable},
		{Account: "a,b", Host: "h"},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if (&Record{}).MarkRolledBack() == nil {
		t.Fatal("rollback without previous")
	}
	if (Record{Role: RoleDomainAdmin}).Class() != Admin || (Record{Role: RoleService}).Class() != Unscored {
		t.Fatal("class")
	}
}

// Integration with the vault: generated secrets round-trip and a Record's
// version ids match what the vault returns.
func TestRotationAgainstVault(t *testing.T) {
	v, err := vault.Create(t.TempDir()+"/v.age", []byte("pp"), vault.Options{WorkFactor: 10})
	if err != nil {
		t.Fatal(err)
	}
	g := NewGenerator()
	r := Record{Account: "root", Host: "web01", Role: RoleLocalAdmin}
	for i := 0; i < 2; i++ {
		s, _ := g.Generate(r.Class(), r.Account)
		id, err := v.Put(r.VaultKey(), s, "rotation")
		if err != nil {
			t.Fatal(err)
		}
		r.MarkRotated(id, time.Now())
	}
	if r.CurrentVersion != "v2" || r.PreviousVersion != "v1" {
		t.Fatal(r)
	}
	r.MarkRolledBack()
	if err := v.Rollback(r.VaultKey(), r.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	_, id, _ := v.Get(r.VaultKey())
	if id != "v1" {
		t.Fatal(id)
	}
}

func TestPlanRotationOrder(t *testing.T) {
	recs := []Record{
		{Account: "alice", Host: "web01", Scored: true, Credlist: "web.cl", Role: RoleLocalAdmin},
		{Account: "mysql", Host: "db01", Role: RoleService},
		{Account: "Administrator", Host: "dc01", Role: RoleDomainAdmin, Domain: true},
		{Account: "root", Host: "web01", Role: RoleLocalAdmin},
		{Account: "admin", Host: "palo", Role: RoleDeviceAdmin},
		{Account: "admin", Host: "vyos", Role: RoleDeviceAdmin},
		{Account: "svc", Host: "app", Role: RoleService},
		{Account: "bob", Host: "dc01", Role: RoleService, Domain: true, Scored: true, Credlist: "ad.cl"},
	}
	p, err := PlanRotation(recs, PlanOptions{DCs: []string{"DC01"}, PCRListChecked: true})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	last := Stage(-1)
	for _, s := range p.Steps {
		if s.Stage < last {
			t.Fatalf("stage went backwards at %v", s)
		}
		last = s.Stage
		acct := "-"
		if s.Record != nil {
			acct = s.Record.Account
		}
		got = append(got, fmt.Sprintf("%v:%s/%s", s.Stage, s.Host, acct))
		switch {
		case s.Record != nil && s.Record.Scored && s.Method != MethodPCR:
			t.Fatal("scored account not PCR")
		case s.Record != nil && !s.Record.Scored && s.Method != MethodDirect:
			t.Fatal("unscored not direct")
		}
		if s.Record != nil && s.Record.Domain && (len(s.After) != 1 || s.After[0] != "DC01") {
			t.Fatalf("domain account missing zerologon gate: %+v", s)
		}
	}
	want := []string{
		"zerologon-mitigation:DC01/-",
		"device-admin:palo/admin", "device-admin:vyos/admin",
		"admin:dc01/Administrator", "admin:web01/root",
		"unscored:app/svc", "unscored:db01/mysql",
		"scored-pcr:dc01/bob", "scored-pcr:web01/alice",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("order:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Deterministic under input permutation.
	rev := append([]Record(nil), recs...)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	p2, _ := PlanRotation(rev, PlanOptions{DCs: []string{"DC01"}, PCRListChecked: true})
	for i := range p.Steps {
		if p.Steps[i].Host != p2.Steps[i].Host || p.Steps[i].Stage != p2.Steps[i].Stage {
			t.Fatal("order depends on input order")
		}
	}
}

func TestPlanHoldsSysadminAndRejectsBadInput(t *testing.T) {
	recs := []Record{{Account: "sysadmin", Host: "web01", Role: RoleLocalAdmin}, {Account: "root", Host: "web01", Role: RoleLocalAdmin}}
	p, _ := PlanRotation(recs, PlanOptions{})
	if len(p.Held) != 1 || len(p.Steps) != 1 || p.Steps[0].Record.Account != "root" {
		t.Fatalf("%+v", p)
	}
	p, _ = PlanRotation(recs, PlanOptions{PCRListChecked: true})
	if len(p.Held) != 0 || len(p.Steps) != 2 {
		t.Fatal("released after PCR check")
	}
	if _, err := PlanRotation([]Record{recs[1], recs[1]}, PlanOptions{}); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err := PlanRotation([]Record{{Account: "a", Host: "dc", Domain: true}}, PlanOptions{}); err == nil {
		t.Fatal("domain account without DC accepted")
	}
	if _, err := PlanRotation([]Record{{Account: "a"}}, PlanOptions{}); err == nil {
		t.Fatal("invalid record accepted")
	}
}
