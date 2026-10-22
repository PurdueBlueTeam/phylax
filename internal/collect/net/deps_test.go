package netmod

import (
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/deps"
)

type parentProcs struct {
	fakeProcs
	ppid map[int]int
}

func (p parentProcs) Parent(pid int) int { return p.ppid[pid] }

// A worker (child of the listener's master) opens an outbound connection while
// an inbound client is connected: the tracker emits a request-driven deps.edge
// attributed to the listening service.
func TestTrackerEmitsDependencyEdge(t *testing.T) {
	src := &fakeSocks{}
	procs := parentProcs{fakeProcs{
		1: {PID: 100, Comm: "master", Exe: "/usr/lib/postfix/sbin/master"},
		2: {PID: 101, Comm: "smtpd", Exe: "/usr/lib/postfix/sbin/smtpd"},
		3: {PID: 101, Comm: "smtpd", Exe: "/usr/lib/postfix/sbin/smtpd"},
	}, map[int]int{101: 100}}
	tr := NewTracker(TrackerConfig{Services: map[string]string{"25": "email-mail"}, Deps: deps.NewCollector(deps.Config{})}, src, procs)
	now := time.Unix(1000, 0)
	src.s = []Sock{lsn("tcp", "0.0.0.0:25", 1)}
	if _, err := tr.Poll(now); err != nil {
		t.Fatal(err)
	}
	src.add(est("tcp", "10.0.0.15:25", "198.51.100.7:4444", 2)) // inbound client
	src.add(est("tcp", "10.0.0.15:41000", "10.0.0.5:389", 3))   // worker -> LDAP
	evs, err := tr.Poll(now.Add(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var edge map[string]any
	for _, e := range evs {
		if e.Kind == deps.KindEdge {
			edge = e.Fields
		}
	}
	if edge == nil {
		t.Fatalf("no deps.edge in %v", kinds(evs))
	}
	if edge["service"] != "email-mail" || edge["dst_addr"] != "10.0.0.5" || edge["dst_port"] != 389 || edge["strength"] != deps.StrengthStrong {
		t.Fatalf("edge %v", edge)
	}
}
