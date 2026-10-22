//go:build linux

package firewall

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
)

// Real-kernel tests. They change nftables state, so they NEVER run against the
// machine's own network namespace. TestKernelInDocker (PHYLAX_FW_DOCKER=1)
// builds this package's test binary statically and runs the TestKernel_* tests
// inside a throwaway container with its own network namespace
// (--network none, --cap-add=NET_ADMIN, not privileged). The inner run is
// selected by PHYLAX_FW_INNER=1 and additionally requires /.dockerenv.

func TestKernelInDocker(t *testing.T) {
	if os.Getenv("PHYLAX_FW_INNER") == "1" {
		t.Skip("inside the container")
	}
	if os.Getenv("PHYLAX_FW_DOCKER") != "1" {
		t.Skip("real-kernel nftables tests skipped: set PHYLAX_FW_DOCKER=1 to run them in a network-namespace container (docker, --cap-add=NET_ADMIN, no host network)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found; cannot run real-kernel nftables tests")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "fw.test")
	build := exec.Command("go", "test", "-c", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build test binary: %v\n%s", err, out)
	}
	root, _ := filepath.Abs("../..")
	cmd := exec.Command("docker", "run", "--rm", "--network", "none", "--cap-add=NET_ADMIN",
		"-e", "PHYLAX_FW_INNER=1",
		"-v", dir+":/t:ro", "-v", root+":/src:ro", "-w", "/src/internal/firewall",
		"alpine:3.20", "/t/fw.test", "-test.run", "^TestKernel_", "-test.v", "-test.count=1")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	t.Logf("container output:\n%s", out.String())
	if err != nil {
		t.Fatalf("container run failed: %v", err)
	}
	s := out.String()
	if strings.Contains(s, "--- SKIP") {
		t.Fatalf("a kernel test was skipped inside the container (nf_tables unavailable?)")
	}
	if n := strings.Count(s, "--- PASS: TestKernel_"); n < 8 {
		t.Fatalf("only %d kernel tests passed", n)
	}
}

func inContainer(t *testing.T) {
	t.Helper()
	if os.Getenv("PHYLAX_FW_INNER") != "1" {
		t.Skip("real-kernel test: run via TestKernelInDocker (PHYLAX_FW_DOCKER=1)")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Skip("refusing to touch nftables outside a container")
	}
}

func resetKernel(t *testing.T) {
	t.Helper()
	inContainer(t)
	c := &nftables.Conn{}
	c.FlushRuleset()
	if err := c.Flush(); err != nil {
		t.Skipf("nftables not usable in this container: %v", err)
	}
}

func newMgr(t *testing.T, dm *deadman.Manager) *LinuxManager {
	t.Helper()
	resetKernel(t)
	return NewLinux(LinuxOptions{Deadman: dm})
}

func newDeadman(t *testing.T) *deadman.Manager {
	t.Helper()
	dm, err := deadman.Open(t.TempDir(), deadman.Options{Handlers: Handlers(nil)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dm.Close() })
	return dm
}

func policy(t *testing.T, manifestName, host string) *render.HostPolicy {
	t.Helper()
	hp, ok := linuxPolicies(t, manifestName)[host]
	if !ok {
		t.Fatalf("no host %s in %s", host, manifestName)
	}
	return hp
}

func mustRead(t *testing.T, m *LinuxManager) *Ruleset {
	t.Helper()
	rs, _, err := m.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func waitState(t *testing.T, dm *deadman.Manager, id string, want deadman.State) deadman.Entry {
	t.Helper()
	var e deadman.Entry
	for i := 0; i < 100; i++ {
		var err error
		if e, err = dm.Get(id); err == nil && e.State == want {
			return e
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("entry %s is %s, wanted %s (%s)", id, e.State, want, e.Error)
	return e
}

func TestKernel_ApplyVerifyIdempotentAndForeign(t *testing.T) {
	m := newMgr(t, nil)
	ctx := context.Background()

	// A foreign firewall (ufw-like, drops by default) and a table that reuses
	// our name in another family. Neither may be touched.
	c := &nftables.Conn{}
	ufw := c.AddTable(&nftables.Table{Name: "ufw", Family: nftables.TableFamilyINet})
	pol := nftables.ChainPolicyDrop
	ch := c.AddChain(&nftables.Chain{Name: "input", Table: ufw, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Policy: &pol})
	c.AddRule(&nftables.Rule{Table: ufw, Chain: ch, Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept}}})
	clash := c.AddTable(&nftables.Table{Name: "phylax", Family: nftables.TableFamilyIPv4})
	cc := c.AddChain(&nftables.Chain{Name: "mine", Table: clash})
	c.AddRule(&nftables.Rule{Table: clash, Chain: cc, Exprs: []expr.Any{&expr.Counter{}}})
	if err := c.Flush(); err != nil {
		t.Skipf("nftables unusable: %v", err)
	}

	res, err := m.Apply(ctx, policy(t, "2027", "rocky-ecom"), ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("first apply reported no change")
	}
	var sawUfw, sawClash bool
	for _, f := range res.Foreign {
		if f.Name == "ufw" {
			sawUfw = f.Hooked && f.MayBlock
		}
		if f.Name == "phylax" && f.Family == uint8(nftables.TableFamilyIPv4) {
			sawClash = f.ShadowsOurName
		}
	}
	if !sawUfw || !sawClash {
		t.Fatalf("foreign tables not reported correctly (ufw=%v clash=%v): %+v", sawUfw, sawClash, res.Foreign)
	}

	// Foreign tables are exactly as we left them.
	rules, err := c.GetRules(ufw, ch)
	if err != nil || len(rules) != 1 {
		t.Fatalf("foreign ufw rules disturbed: %v %d", err, len(rules))
	}
	rules, err = c.GetRules(clash, cc)
	if err != nil || len(rules) != 1 {
		t.Fatalf("foreign ip phylax table disturbed: %v %d", err, len(rules))
	}

	// What is in the kernel is what we declared.
	want, _ := Translate(policy(t, "2027", "rocky-ecom"), TranslateOptions{})
	if d := DiffRulesets(want, mustRead(t, m)); len(d) != 0 {
		t.Fatalf("kernel differs from declared: %v", d)
	}
	dr, err := m.DetectDrift(ctx, want)
	if err != nil || !dr.Clean || !dr.ManagementIntact {
		t.Fatalf("drift on a fresh apply: %+v %v", dr, err)
	}

	res2, err := m.Apply(ctx, policy(t, "2027", "rocky-ecom"), ApplyOptions{})
	if err != nil || res2.Changed {
		t.Fatalf("re-apply: changed=%v err=%v", res2.Changed, err)
	}
}

func TestKernel_RichPolicyRoundTrips(t *testing.T) {
	m := newMgr(t, nil)
	hp := &render.HostPolicy{
		Host: "x", Family: "linux", DefaultIn: render.Drop, DefaultOut: render.Drop,
		DenyLogGroup: 7, SinkholePort: 9999,
		Rules: []render.Rule{
			{Group: render.GroupMgmt, Kind: render.KindAgentLink, Dir: render.Out, Action: render.Accept, Proto: "tcp", RemotePorts: []uint16{8443},
				Peers: pfx("10.0.0.5/32"), Comment: "agent"},
			{Group: render.GroupMgmt, Kind: render.KindAgentLink, Dir: render.In, Action: render.Accept, Proto: "tcp", LocalPorts: []uint16{8443},
				Peers: pfx("10.0.0.0/24", "10.0.0.9/32", "192.168.1.0/25", "fd00::/64", "fd00:0:0:1::/64", "203.0.113.7/32")},
			{Group: render.GroupBase, Kind: render.KindICMP, Dir: render.In, Action: render.Accept, Proto: "icmp"},
			{Group: render.GroupBase, Kind: render.KindICMPv6, Dir: render.Out, Action: render.Accept, Proto: "icmpv6"},
			{Group: render.GroupBase, Kind: render.KindDHCP, Dir: render.Out, Action: render.Accept, Proto: "udp", LocalPorts: []uint16{68}, RemotePorts: []uint16{67}},
			{Group: render.GroupService, Kind: render.KindService, Dir: render.In, Action: render.Accept, Proto: "tcp", LocalPorts: []uint16{22, 80, 443, 8080}, Service: "web", Comment: "web (http)"},
			{Group: render.GroupService, Kind: render.KindService, Dir: render.In, Action: render.Accept, Proto: "udp", LocalPorts: []uint16{53}},
			{Group: render.GroupEgress, Kind: render.KindEgress, Dir: render.Out, Action: render.Accept, Proto: "tcp", RemotePorts: []uint16{443, 80},
				Peers: pfx("0.0.0.0/0"), Comment: "any v4"},
			{Group: render.GroupEgress, Kind: render.KindEgress, Dir: render.Out, Action: render.Accept, Proto: "tcp", RemotePorts: []uint16{25},
				Peers: pfx("172.16.0.0/12", "172.16.5.0/24", "2001:db8::/32")},
			{Group: render.GroupCanary, Kind: render.KindCanary, Dir: render.Out, Action: render.Drop, Proto: "tcp", RemotePorts: []uint16{4444},
				Peers: pfx("10.0.0.99/32"), Log: true, LogGroup: 8, Comment: "canary"},
			{Group: render.GroupDecoy, Kind: render.KindDecoy, Dir: render.In, Action: render.Accept, Proto: "tcp", LocalPorts: []uint16{2222}},
		},
	}
	res, err := m.Apply(context.Background(), hp, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("no change")
	}
	got := mustRead(t, m)
	if got.Table(render.TableNAT) == nil {
		t.Fatal("sinkhole table missing")
	}
	want, _ := Translate(hp, TranslateOptions{})
	if d := DiffRulesets(want, got); len(d) != 0 {
		t.Fatalf("read-back differs: %v", d)
	}
	if len(got.Table(render.TableMgmt).Sets) == 0 || len(got.Table(render.TableMain).Sets) == 0 {
		t.Fatal("expected named sets for multi-value matches")
	}
	// Shadow of the same policy also installs and verifies, and removes the sinkhole.
	if _, err := m.Apply(context.Background(), hp, ApplyOptions{Mode: ModeShadow}); err != nil {
		t.Fatal(err)
	}
	got = mustRead(t, m)
	if got.Table(render.TableNAT) != nil {
		t.Fatal("shadow left the sinkhole table behind")
	}
	for _, c := range got.Table(render.TableMain).Chains {
		if c.Policy == nil || *c.Policy != uint32(nftables.ChainPolicyAccept) {
			t.Fatalf("shadow chain %s does not accept", c.Name)
		}
	}
}

func TestKernel_DeadmanRollbackRestoresExactPreviousRuleset(t *testing.T) {
	dm := newDeadman(t)
	m := newMgr(t, dm)
	ctx := context.Background()

	if _, err := m.Apply(ctx, policy(t, "2027", "rocky-ecom"), ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, m)
	beforeHash := before.Hash()

	res, err := m.Apply(ctx, policy(t, "2027", "ubuntu-email"), ApplyOptions{DeadmanID: "fw-1", NodeID: "n1", Timeout: 400 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if !res.DeadmanArmed || !res.Changed {
		t.Fatalf("expected armed change: %+v", res)
	}
	if mustRead(t, m).Hash() == beforeHash {
		t.Fatal("second policy did not change anything")
	}
	e := waitState(t, dm, "fw-1", deadman.StateRolledBack)
	if e.FiredBy != "timer" {
		t.Fatalf("fired by %q", e.FiredBy)
	}
	after := mustRead(t, m)
	if d := DiffRulesets(before, after); len(d) != 0 || after.Hash() != beforeHash {
		t.Fatalf("rollback is not exact: %v", d)
	}

	// Confirmed changes stay.
	if _, err := m.Apply(ctx, policy(t, "2027", "ubuntu-email"), ApplyOptions{DeadmanID: "fw-2", Timeout: 400 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	applied := mustRead(t, m).Hash()
	if _, err := dm.Confirm(ctx, "fw-2"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond)
	if mustRead(t, m).Hash() != applied {
		t.Fatal("confirmed change was rolled back")
	}

	// From nothing: rollback removes our tables.
	resetKernel(t)
	if _, err := m.Apply(ctx, policy(t, "2027", "rocky-ecom"), ApplyOptions{DeadmanID: "fw-3", Timeout: 300 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	waitState(t, dm, "fw-3", deadman.StateRolledBack)
	if n := len(mustRead(t, m).Tables); n != 0 {
		t.Fatalf("%d of our tables survived a rollback to the empty state", n)
	}
}

func TestKernel_RollbackFromFreshHandler(t *testing.T) {
	// The OS backstop runs the rollback in a new process that only has the
	// journal entry: the handler must work from that alone.
	dm := newDeadman(t)
	m := newMgr(t, dm)
	ctx := context.Background()
	if _, err := m.Apply(ctx, policy(t, "2027", "rocky-ecom"), ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, m)
	if _, err := m.Apply(ctx, policy(t, "2027", "ubuntu-email"), ApplyOptions{DeadmanID: "fw-fresh", Timeout: time.Hour}); err != nil {
		t.Fatal(err)
	}
	e, err := dm.Get("fw-fresh")
	if err != nil {
		t.Fatal(err)
	}
	if err := Handlers(nil)[KindNftRestore](ctx, e); err != nil {
		t.Fatal(err)
	}
	if d := DiffRulesets(before, mustRead(t, m)); len(d) != 0 {
		t.Fatalf("fresh handler rollback not exact: %v", d)
	}
	// Idempotent.
	if err := Handlers(nil)[KindNftRestore](ctx, e); err != nil {
		t.Fatal(err)
	}
	if d := DiffRulesets(before, mustRead(t, m)); len(d) != 0 {
		t.Fatalf("second rollback changed state: %v", d)
	}
}

func TestKernel_RejectedBatchChangesNothing(t *testing.T) {
	dm := newDeadman(t)
	m := newMgr(t, dm)
	ctx := context.Background()
	if _, err := m.Apply(ctx, policy(t, "2027", "rocky-ecom"), ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, m)
	bad, _ := Translate(policy(t, "2027", "ubuntu-email"), TranslateOptions{})
	mn := bad.Table(render.TableMain)
	mn.Chains[0].Rules = append(mn.Chains[0].Rules, &RuleSpec{Exprs: []Expr{{&expr.Verdict{Kind: expr.VerdictJump, Chain: "no_such_chain"}}}})
	if _, err := m.ApplyRuleset(ctx, bad, ApplyOptions{DeadmanID: "fw-bad", Timeout: time.Minute}); err == nil {
		t.Fatal("kernel accepted a jump to a missing chain")
	}
	if d := DiffRulesets(before, mustRead(t, m)); len(d) != 0 {
		t.Fatalf("a rejected batch changed the ruleset (not atomic): %v", d)
	}
	e, err := dm.Get("fw-bad")
	if err != nil || e.State != deadman.StateCancelled {
		t.Fatalf("dead-man entry after rejected batch: %+v %v", e, err)
	}
}

func TestKernel_VerifyFailureRollsBack(t *testing.T) {
	dm := newDeadman(t)
	resetKernel(t)
	var m *LinuxManager
	m = NewLinux(LinuxOptions{Deadman: dm})
	ctx := context.Background()
	if _, err := m.Apply(ctx, policy(t, "2027", "rocky-ecom"), ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, m)

	// Something deletes the management table right after our batch lands.
	m.opt.afterReplace = func() {
		c := &nftables.Conn{}
		c.DelTable(&nftables.Table{Name: render.TableMgmt, Family: nftables.TableFamilyINet})
		if err := c.Flush(); err != nil {
			t.Error(err)
		}
	}
	_, err := m.Apply(ctx, policy(t, "2027", "ubuntu-email"), ApplyOptions{DeadmanID: "fw-v", Timeout: time.Hour})
	m.opt.afterReplace = nil
	if err == nil || !strings.Contains(err.Error(), ErrVerify.Error()) {
		t.Fatalf("want verify failure, got %v", err)
	}
	if d := DiffRulesets(before, mustRead(t, m)); len(d) != 0 {
		t.Fatalf("not rolled back after failed verify: %v", d)
	}
	if e, _ := dm.Get("fw-v"); e.State != deadman.StateRolledBack || e.FiredBy != "verify" {
		t.Fatalf("dead-man journal after failed verify: %+v", e)
	}
}

func TestKernel_DriftDetection(t *testing.T) {
	m := newMgr(t, nil)
	ctx := context.Background()
	hp := policy(t, "2027", "rocky-ecom")
	want, _ := Translate(hp, TranslateOptions{})
	if _, err := m.Apply(ctx, hp, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	clean, err := m.DetectDrift(ctx, want)
	if err != nil || !clean.Clean {
		t.Fatalf("%+v %v", clean, err)
	}

	// Red team: delete one rule from the main input chain.
	c := &nftables.Conn{}
	tbl := &nftables.Table{Name: render.TableMain, Family: nftables.TableFamilyINet}
	chain := &nftables.Chain{Name: "input", Table: tbl}
	rules, err := c.GetRules(tbl, chain)
	if err != nil || len(rules) < 5 {
		t.Fatalf("rules: %v %d", err, len(rules))
	}
	if err := c.DelRule(rules[len(rules)-1]); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	d, err := m.DetectDrift(ctx, want)
	if err != nil {
		t.Fatal(err)
	}
	if d.Clean || d.Hash == clean.Hash || len(d.Diffs) == 0 || !strings.Contains(strings.Join(d.Diffs, "\n"), "missing") {
		t.Fatalf("tampering not detected: %+v", d)
	}

	// Red team: flush the whole ruleset. Management is reported gone.
	c.FlushRuleset()
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	d, _ = m.DetectDrift(ctx, want)
	if d.Clean || d.ManagementIntact || d.ManagementProblem == "" {
		t.Fatalf("flush not detected: %+v", d)
	}

	// Re-apply repairs.
	if res, err := m.Apply(ctx, hp, ApplyOptions{}); err != nil || !res.Changed {
		t.Fatalf("repair: %+v %v", res, err)
	}
	if d, _ := m.DetectDrift(ctx, want); !d.Clean || !d.ManagementIntact {
		t.Fatalf("still drifted: %+v", d)
	}
}

func TestKernel_PanicOpenAndRestore(t *testing.T) {
	m := newMgr(t, nil)
	ctx := context.Background()
	hp := policy(t, "2027", "rocky-ecom")
	if _, err := m.Apply(ctx, hp, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, m)

	c := &nftables.Conn{}
	c.AddTable(&nftables.Table{Name: "docker", Family: nftables.TableFamilyIPv4})
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}

	snap, err := m.PanicOpen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := mustRead(t, m)
	if d := DiffRulesets(OpenRuleset(), now); len(d) != 0 {
		t.Fatalf("panic open state wrong: %v", d)
	}
	if now.Table(render.TableMgmt) != nil || now.Table(render.TableNAT) != nil {
		t.Fatal("management/sinkhole tables survived panic open")
	}
	if _, foreign, _ := m.Read(ctx); len(foreign) != 1 || foreign[0].Name != "docker" {
		t.Fatalf("foreign table disturbed: %+v", foreign)
	}

	if _, err := m.Restore(ctx, snap); err != nil {
		t.Fatal(err)
	}
	if d := DiffRulesets(before, mustRead(t, m)); len(d) != 0 {
		t.Fatalf("restore after panic open not exact: %v", d)
	}
}
