package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/controller"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

// A deception deploy plan end to end: the controller generates the honeytokens
// into its vault, issues signed steps whose params hold only vault references,
// ships the secret content in the step's secrets blob, and a real agent plants
// the bait. The secret value appears on the wire only in that blob, never in a
// plan, a step's signed params, a stored plan body, an agent event or a result.
func TestDeceptionPlanPlantsBaitWithoutLeakingSecrets(t *testing.T) {
	v, err := vault.Create(filepath.Join(t.TempDir(), "vault.age"), []byte("pw"), vault.Options{WorkFactor: 10})
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	h.stopController()
	h.vault = v
	h.m = &manifest.Manifest{
		Hosts: map[string]manifest.Host{"h1": {Segment: "lan", IP: "10.0.0.5", OS: manifest.OS{Family: "debian"}, Roles: []string{manifest.RoleDecoys}}},
		Decoys: map[string]manifest.HostDecoys{"h1": {
			Listeners:   []manifest.DecoyListener{{Kind: "redis", Port: 6390}},
			HoneyFiles:  []string{"/root/finance.xlsx"},
			Honeytokens: []manifest.Honeytoken{{Kind: "aws_key"}, {Kind: "shell_history"}, {Kind: "db_cred"}},
		}},
	}
	h.startController()
	ctx := context.Background()
	if err := h.c.SetConfigInputs(ctx, controller.ConfigInputs{Manifest: h.m}); err != nil {
		t.Fatal(err)
	}
	th := h.addHost("h1")
	// A real history file that must survive.
	if err := os.MkdirAll(th.path("root"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(th.path("root/.bash_history"), []byte("ls\nwho\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := h.c.DeceptionPlan(ctx, "deception-e2e")
	if err != nil {
		t.Fatal(err)
	}
	// The decoy listeners are the agent module's business (and need the mods
	// package); here we exercise the planting.
	var nodes []plan.Node
	for _, n := range p.Nodes {
		if n.Action != "deception.decoy_check" {
			nodes = append(nodes, n)
		}
	}
	p.Nodes = nodes
	if err := h.c.CreatePlan(ctx, p, "operator"); err != nil {
		t.Fatal(err)
	}
	st := h.mustApproveAndRun(p.ID, "approve-deception")
	if st.State != "succeeded" {
		t.Fatalf("plan state %q", st.State)
	}

	var secrets []string
	for _, s := range h.c.HoneytokenSteps() {
		for _, ref := range s.SecretRefs {
			sec, _, err := v.Get(ref)
			if err != nil {
				t.Fatal(err)
			}
			secrets = append(secrets, sec.Reveal())
		}
	}
	if len(secrets) < 3 {
		t.Fatalf("secrets: %d", len(secrets))
	}

	// The bait is on the host.
	aws := th.read(t, "root/.aws/credentials")
	if !strings.Contains(aws, "aws_access_key_id = AKIA") || !strings.Contains(aws, "aws_secret_access_key = ") {
		t.Errorf("aws bait: %q", aws)
	}
	if got := th.read(t, "root/.bash_history"); got != "ls\nwho\n" {
		t.Errorf("real history clobbered: %q", got)
	}
	if !th.exists("root/finance.xlsx") || !th.exists("var/www/html/.env.bak") {
		t.Error("honey files missing")
	}
	if st, _ := os.Stat(th.path("root/.aws/credentials")); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}

	// Leak audit: signed step params, secrets only in the blob, stored plan,
	// results and agent events.
	h.mu.Lock()
	steps := append([]*link.Step(nil), h.steps...)
	h.mu.Unlock()
	blobs := 0
	for _, s := range steps {
		if s.Plan != p.ID {
			continue
		}
		for _, sec := range secrets {
			if leaks(string(s.Params), sec) {
				t.Fatalf("step %s/%s params carry a secret", s.Node, s.Phase)
			}
		}
		var m map[string]string
		if len(s.Secrets) > 0 && json.Unmarshal(s.Secrets, &m) == nil {
			for _, v := range m {
				for _, sec := range secrets {
					if v == sec {
						blobs++
					}
				}
			}
		}
	}
	if blobs == 0 {
		t.Fatal("no step carried secrets in its secrets blob")
	}
	rows, _ := h.c.StoredPlans(ctx)
	for _, r := range rows {
		for _, sec := range secrets {
			if leaks(r.Body, sec) {
				t.Fatalf("stored plan %s holds a secret", r.ID)
			}
		}
	}
	d, err := h.c.PlanDetail(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	dj, _ := json.Marshal(d)
	h.mu.Lock()
	evj, _ := json.Marshal(h.events)
	h.mu.Unlock()
	all := string(dj) + string(evj)
	for _, k := range []string{"agent.step", "agent.step_refused", "agent.step_result"} {
		all += strings.Join(h.agentEvents("h1", k), "\n")
	}
	for _, sec := range secrets {
		if leaks(all, sec) {
			t.Fatal("a result, plan detail or agent event holds a secret")
		}
	}
}

// leaks reports whether hay holds sec verbatim or JSON-escaped (file contents
// have newlines, so a JSON document carries them as \n).
func leaks(hay, sec string) bool {
	esc, _ := json.Marshal(sec)
	return strings.Contains(hay, sec) || strings.Contains(hay, strings.Trim(string(esc), `"`))
}
