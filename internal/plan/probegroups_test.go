package plan

import (
	"reflect"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

func TestScoredTouchUsesManifestHealthBeforeDiscovery(t *testing.T) {
	m := &manifest.Manifest{Services: map[string]manifest.Service{
		"ecom-http": {Host: "h1", Scored: true, Health: []manifest.Health{{TCPConnect: 443}},
			Content: &manifest.Content{Roots: []string{"/etc/ecom"}}},
		"unscored": {Host: "h1", Scored: false, Health: []manifest.Health{{TCPConnect: 80}}},
	}}
	n := Node{ID: "n", Target: "h1"}
	if got := ScoredTouch(m, n, []actions.Touch{{Kind: actions.TouchPath, Name: "/etc/ecom/app.conf", Op: actions.OpModify}}); !reflect.DeepEqual(got, []string{"ecom-http"}) {
		t.Fatalf("config path: %v", got)
	}
	if got := ScoredTouch(m, n, []actions.Touch{{Kind: actions.TouchPath, Name: "/tmp/x", Op: actions.OpModify}}); len(got) != 0 {
		t.Fatalf("unscored path: %v", got)
	}
}

func TestProbeGroupsShareLocks(t *testing.T) {
	p := Plan{Nodes: []Node{
		{ID: "a", Target: "h1"},
		{ID: "b", Target: "h1"},
		{ID: "c", Target: "h1"},
		{ID: "d", Target: "h2"},
	}}
	scored := map[string][]string{"a": {"web"}, "b": {"web"}, "c": {"sshd"}, "d": {"web"}}
	locks := map[string][]string{
		"a": {"content:web"},
		"b": {"content:web", "path:x"},
		"c": {"sshd"},
		"d": {"content:web"},
	}
	want := []ProbeGroup{
		{Host: "h1", Services: []string{"web"}, Nodes: []string{"a", "b"}},
		{Host: "h1", Services: []string{"sshd"}, Nodes: []string{"c"}},
		{Host: "h2", Services: []string{"web"}, Nodes: []string{"d"}},
	}
	if got := ProbeGroups(p, scored, locks); !reflect.DeepEqual(got, want) {
		t.Fatalf("groups %+v, want %+v", got, want)
	}
}

func TestProbeGroupDeadmanIsAlone(t *testing.T) {
	p := Plan{Nodes: []Node{
		{ID: "a", Target: "h1"},
		{ID: "b", Target: "h1", DeadmanSec: 90},
	}}
	scored := map[string][]string{"a": {"web"}, "b": {"web"}}
	locks := map[string][]string{"a": {"content:web"}, "b": {"content:web"}}
	want := []ProbeGroup{
		{Host: "h1", Services: []string{"web"}, Nodes: []string{"a"}},
		{Host: "h1", Services: []string{"web"}, Nodes: []string{"b"}},
	}
	if got := ProbeGroups(p, scored, locks); !reflect.DeepEqual(got, want) {
		t.Fatalf("groups %+v, want %+v", got, want)
	}
}
