package scorer

import (
	"fmt"
	"math"
	"math/rand"
	"testing"
)

var web = ServiceKey{"10.0.21.10", 80, "tcp"}

func TestServiceLearnedWithin3Rounds(t *testing.T) {
	d := NewDiscovery(DiscoveryConfig{})
	var learned int
	for r := 1; r <= 3; r++ {
		for _, ev := range d.Observe(Observation{Time: t0, Round: r, Key: web, Kind: "url", Item: "/"}) {
			if ev.Kind == EventServiceLearned {
				learned = r
			}
		}
	}
	if learned == 0 || learned > 3 {
		t.Fatalf("learned at round %d", learned)
	}
}

func TestItemCoverageSimulation(t *testing.T) {
	const k = 5
	var rounds []int
	for seed := int64(0); seed < 400; seed++ {
		rng := rand.New(rand.NewSource(seed))
		d := NewDiscovery(DiscoveryConfig{})
		seen := map[int]bool{}
		for r := 1; len(seen) < k && r < 1000; r++ {
			i := rng.Intn(k)
			seen[i] = true
			d.Observe(Observation{Time: t0, Round: r, Key: web, Kind: "url", Item: fmt.Sprintf("/p%d", i)})
			if len(seen) == k {
				rounds = append(rounds, r)
			}
		}
	}
	sum := 0
	for _, r := range rounds {
		sum += r
	}
	mean := float64(sum) / float64(len(rounds))
	if want := ExpectedRoundsToSeeAll(k); math.Abs(mean-want) > 1.0 || math.Abs(want-11.4) > 0.1 {
		t.Fatalf("mean rounds to see %d items %.2f, k*H_k %.2f (~11)", k, mean, want)
	}
	if math.Abs(ExpectedRoundsToSeeAll(3)-5.5) > 0.01 || math.Abs(ExpectedRoundsToSeeAll(10)-29.29) > 0.01 {
		t.Fatal("k*H_k wrong")
	}
}

func TestCoverageEstimateConverges(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	d := NewDiscovery(DiscoveryConfig{})
	const k = 8
	var early, late Coverage
	for r := 1; r <= 120; r++ {
		d.Observe(Observation{Round: r, Key: web, Kind: "url", Item: fmt.Sprintf("/p%d", rng.Intn(k))})
		if r == 6 {
			early, _ = d.Coverage(web)
		}
	}
	late, _ = d.Coverage(web)
	if !early.Partial || early.Coverage > 0.9 {
		t.Fatalf("early coverage should be partial: %+v", early)
	}
	if late.Observed != k || late.Coverage < 0.95 || late.Partial || math.Abs(late.EstTotal-k) > 0.5 {
		t.Fatalf("late coverage: %+v", late)
	}
	if early.RoundsLeft <= 0 {
		t.Fatalf("early estimate should expect more rounds: %+v", early)
	}
}

func TestCompareProposalsAndStale(t *testing.T) {
	d := NewDiscovery(DiscoveryConfig{})
	ssh := ServiceKey{"10.0.21.15", 22, "tcp"}
	dns := ServiceKey{"10.0.21.100", 53, "udp"}
	for r := 1; r <= 3; r++ {
		d.Observe(Observation{Round: r, Key: web, Kind: "url", Item: []string{"/", "/a", "/b"}[r-1]})
		d.Observe(Observation{Round: r, Key: ssh, Kind: "command", Item: "id"})
	}
	actives := []ActiveCheck{
		{ID: "web", Key: web, Items: []string{"/"}, Active: true, Since: 1},
		{ID: "dnsold", Key: dns, Active: true, Since: 1},
	}
	props := d.Compare(3, actives)
	got := map[ProposalKind]Proposal{}
	for _, p := range props {
		got[p.Kind] = p
	}
	if p := got[ProposeNew]; p.Service != ssh {
		t.Fatalf("new check for ssh missing: %+v", props)
	}
	if p := got[ProposeUpdate]; p.CheckID != "web" || len(p.Items) != 2 {
		t.Fatalf("update proposal: %+v", props)
	}
	if _, ok := got[FlagStale]; ok {
		t.Fatalf("stale flagged too early: %+v", props)
	}
	props = d.Compare(7, actives)
	stale := 0
	for _, p := range props {
		if p.Kind == FlagStale {
			stale++
		}
	}
	if stale != 3 { // dnsold never seen; web and ssh silent since round 3 (4 rounds < 5 -> not)
		// web/ssh: 7-3=4 <5 so only dnsold
		if stale != 1 {
			t.Fatalf("stale = %d: %+v", stale, props)
		}
	}
	if props = d.Compare(9, actives); countKind(props, FlagStale) != 2 {
		t.Fatalf("web and dnsold should be stale at round 9: %+v", props)
	}
}

func countKind(ps []Proposal, k ProposalKind) (n int) {
	for _, p := range ps {
		if p.Kind == k {
			n++
		}
	}
	return
}

func TestBlockedAndSilent(t *testing.T) {
	d := NewDiscovery(DiscoveryConfig{})
	ssh := ServiceKey{"10.0.21.15", 22, "tcp"}
	for r := 1; r <= 2; r++ {
		d.Observe(Observation{Round: r, Key: web, Item: "/"})
		d.Observe(Observation{Round: r, Key: ssh, Item: "id"})
		d.CloseRound(r)
	}
	var kinds []EventKind
	for r := 3; r <= 8; r++ {
		d.Observe(Observation{Round: r, Key: web, Item: "/"}) // ssh goes missing
		for _, ev := range d.CloseRound(r) {
			if ev.Service == ssh {
				kinds = append(kinds, ev.Kind)
			}
		}
	}
	if len(kinds) != 2 || kinds[0] != EventBlockedSuspect || kinds[1] != EventScorerSilent {
		t.Fatalf("events: %v", kinds)
	}
	// A whole-team gap (no traffic) counts against nobody.
	d2 := NewDiscovery(DiscoveryConfig{})
	d2.Observe(Observation{Round: 1, Key: web, Item: "/"})
	d2.Observe(Observation{Round: 2, Key: web, Item: "/"})
	for r := 3; r < 20; r++ {
		if ev := d2.CloseRound(r); len(ev) != 0 {
			t.Fatalf("empty round produced events: %v", ev)
		}
	}
	// Resume.
	evs := d.Observe(Observation{Round: 9, Key: ssh, Item: "id"})
	if len(evs) == 0 || evs[0].Kind != EventServiceResumed {
		t.Fatalf("resume event: %v", evs)
	}
}

func TestScoredAccounts(t *testing.T) {
	d := NewDiscovery(DiscoveryConfig{})
	ssh := ServiceKey{"10.0.21.15", 22, "tcp"}
	evs := d.Observe(Observation{Round: 1, Key: ssh, User: "alice", Auth: AuthOK})
	if len(evs) == 0 || evs[0].Kind != EventAccountLearned {
		t.Fatalf("%v", evs)
	}
	// BadAttempts failures are not credentials.
	d.Observe(Observation{Round: 1, Key: ssh, User: "mallory", Auth: AuthFailed, BadAttempt: true})
	if d.IsScored("mallory") {
		t.Fatal("BadAttempts-only user learned as scored")
	}
	if !d.IsScored("alice") || !d.IsScored("sysadmin") || d.IsScored("bob") {
		t.Fatal("scored set wrong")
	}
	if err := d.GuardRotation("alice"); err == nil {
		t.Fatal("unilateral rotation of a scored account allowed")
	}
	if err := d.GuardRotation("bob"); err != nil {
		t.Fatal(err)
	}
	d.MarkNotScored("sysadmin")
	if d.IsScored("sysadmin") || d.GuardRotation("sysadmin") != nil {
		t.Fatal("sysadmin should be free once shown not scored")
	}
	if a := d.ScoredAccounts(); len(a) != 1 || a[0].User != "alice" {
		t.Fatalf("%+v", a)
	}
}

func TestCustomServiceKeepsSamples(t *testing.T) {
	d := NewDiscovery(DiscoveryConfig{})
	k := ServiceKey{"10.0.21.120", 1433, "tcp"}
	for r := 1; r <= 6; r++ {
		d.Observe(Observation{Round: r, Key: k, Sample: []byte{0x12, 0x01, byte(r)}})
	}
	s, _ := d.Service(k)
	if len(s.Samples) != 3 {
		t.Fatalf("samples bounded to 3, have %d", len(s.Samples))
	}
}
