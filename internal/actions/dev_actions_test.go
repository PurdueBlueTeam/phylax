package actions

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PurdueBlueTeam/phylax/internal/devices"
	"github.com/PurdueBlueTeam/phylax/internal/devices/palo"
	"github.com/PurdueBlueTeam/phylax/internal/devices/palo/palotest"
	"github.com/PurdueBlueTeam/phylax/internal/devices/palo/xmlapi"
	"github.com/PurdueBlueTeam/phylax/internal/devices/vyos"
	"github.com/PurdueBlueTeam/phylax/internal/devices/vyos/vyostest"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
)

const paloSeed = `<config version="11.0.0"><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
<rulebase><security><rules><entry name="human-rule"><from><member>inside</member></from><to><member>outside</member></to><action>allow</action></entry></rules></security></rulebase>
</entry></vsys><deviceconfig><system><hostname>pa1</hostname><permitted-ip><entry name="0.0.0.0/0"/></permitted-ip></system></deviceconfig></entry></devices></config>`

type fakeDevDir struct {
	pa  *palo.Adapter
	vy  *vyos.Adapter
	pi  *render.PaloIntent
	vi  *render.VyOSIntent
	ack bool
}

func (d *fakeDevDir) Palo(context.Context, string) (*palo.Adapter, error) {
	if d.pa == nil {
		return nil, errors.New("no palo")
	}
	return d.pa, nil
}
func (d *fakeDevDir) VyOS(context.Context, string) (*vyos.Adapter, error) {
	if d.vy == nil {
		return nil, errors.New("no vyos")
	}
	return d.vy, nil
}
func (d *fakeDevDir) PaloIntent(context.Context, string) (*render.PaloIntent, error) {
	return d.pi, nil
}
func (d *fakeDevDir) VyOSIntent(context.Context, string) (*render.VyOSIntent, error) {
	return d.vi, nil
}
func (d *fakeDevDir) ConsoleAck(context.Context, string) bool { return d.ack }

func paloFixture(t *testing.T) (*fixture, *palotest.Server, *fakeDevDir) {
	t.Helper()
	srv := palotest.New()
	t.Cleanup(srv.Close)
	srv.SeedRunning(paloSeed)
	key := srv.AddAdmin("phylax", "pw")
	ad, err := palo.New(palo.Config{Device: "palo1", Admin: "phylax", Key: key,
		Transport:    devices.Transport{HTTP: srv.Client(), Host: srv.URL},
		PollInterval: 5 * time.Millisecond, JobTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	dir := &fakeDevDir{pa: ad, ack: true}
	f := newFixture(t)
	f.env.Host = "palo1"
	f.env.Win.Devices = dir
	return f, srv, dir
}

func paloACL(srv *palotest.Server) []string {
	st, _ := xmlapi.ParseXPath(palotest.PermittedIPPath)
	n := srv.Running().Select(st)
	var out []string
	if n != nil {
		for _, e := range n.Children {
			out = append(out, e.Attr("name"))
		}
	}
	return out
}

func TestPaloPermittedIPsAdditiveThenRemove(t *testing.T) {
	f, srv, _ := paloFixture(t)
	o := f.ok(t, "palo.permitted_ips", map[string]any{"add": "127.0.0.1"}, func(r *Request) { r.DryRun = true })
	if !strings.Contains(o.Plan.Diff, "+ permitted-ip 127.0.0.1/32") || strings.Contains(o.Plan.Diff, "- permitted") {
		t.Fatalf("diff %q", o.Plan.Diff)
	}
	if len(paloACL(srv)) != 1 {
		t.Fatal("dry-run changed the device")
	}
	// additive: both entries afterwards, in one management commit
	o = f.ok(t, "palo.permitted_ips", map[string]any{"add": "127.0.0.1"})
	if acl := paloACL(srv); len(acl) != 2 {
		t.Fatalf("ACL %v", acl)
	}
	if o.Output["rolled_back"] != "false" {
		t.Fatalf("output %v", o.Output)
	}
	// removal is its own call (the template's second commit)
	f.ok(t, "palo.permitted_ips", map[string]any{"add": "127.0.0.1", "remove": "0.0.0.0/0"})
	if acl := paloACL(srv); len(acl) != 1 || acl[0] != "127.0.0.1/32" {
		t.Fatalf("ACL %v", acl)
	}
	commits := 0
	for _, op := range srv.Ops() {
		if strings.HasPrefix(op, "commit") {
			commits++
		}
	}
	if commits != 2 {
		t.Fatalf("commits = %d, want 2 separate commits", commits)
	}
	// converged: nothing to do
	if o := f.ok(t, "palo.permitted_ips", map[string]any{"add": "127.0.0.1", "remove": "0.0.0.0/0"}); o.Changed {
		t.Fatal("not idempotent")
	}
}

func TestPaloPermittedIPsLockoutRollsBack(t *testing.T) {
	f, srv, _ := paloFixture(t)
	// warm the keep-alive connection, as the real client would be
	if _, err := f.env.Win.Devices.(*fakeDevDir).pa.Info(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, err := f.run(t, "palo.permitted_ips", map[string]any{"add": "203.0.113.9", "remove": "0.0.0.0/0"})
	if !errors.Is(err, devices.ErrProbe) {
		t.Fatalf("want a fresh-connection failure, got %v", err)
	}
	if acl := paloACL(srv); len(acl) != 1 || acl[0] != "0.0.0.0/0" {
		t.Fatalf("ACL not restored: %v", acl)
	}
}

func TestPaloPermittedIPsRefusals(t *testing.T) {
	f, srv, dir := paloFixture(t)
	for _, p := range []map[string]any{
		{"add": "0.0.0.0/0"},
		{"add": "10.0.0.5", "remove": "10.0.0.5"},
		{"add": "not-an-ip"},
		{"add": ""},
	} {
		if _, err := f.run(t, "palo.permitted_ips", p); err == nil {
			t.Errorf("%v accepted", p)
		}
	}
	// no console acknowledgement and no dead-man: PAN-OS has none
	dir.ack = false
	if _, err := f.run(t, "palo.permitted_ips", map[string]any{"add": "127.0.0.1"}); !errors.Is(err, devices.ErrNoDeadman) {
		t.Fatalf("want ErrNoDeadman, got %v", err)
	}
	if len(paloACL(srv)) != 1 {
		t.Fatal("device changed without an acknowledgement")
	}
}

func TestPaloCommitCheck(t *testing.T) {
	f, srv, _ := paloFixture(t)
	o := f.ok(t, "palo.commit", map[string]any{"description": "phylax: add controller"})
	if o.Output["candidate"] != "clean" {
		t.Fatalf("output %v", o.Output)
	}
	// somebody else stages a change: the check fails and does not commit it
	evil := &xmlapi.Client{BaseURL: srv.URL, Key: srv.AddAdmin("evil", "pw"), HTTP: srv.Client()}
	if err := evil.ConfigSet(t.Context(), palotest.DevicePath+"/deviceconfig/system", `<domain>evil.example</domain>`); err != nil {
		t.Fatal(err)
	}
	_, err := f.run(t, "palo.commit", map[string]any{})
	if !errors.Is(err, devices.ErrPreflight) {
		t.Fatalf("want ErrPreflight, got %v", err)
	}
	for _, op := range srv.Ops() {
		if strings.HasPrefix(op, "commit") {
			t.Fatalf("palo.commit committed: %v", srv.Ops())
		}
	}
}

func loadManifest(t *testing.T) *manifest.Manifest {
	t.Helper()
	m, err := manifest.LoadDir("../../manifest/2027", manifest.Options{})
	if err != nil {
		t.Skipf("reference manifest not loadable: %v", err)
	}
	return m
}

func TestPaloApplyPolicyAndSnapshot(t *testing.T) {
	f, srv, dir := paloFixture(t)
	m := loadManifest(t)
	pi, err := render.PaloIntents(m, "palo1")
	if err != nil {
		t.Skipf("palo intent: %v", err)
	}
	dir.pi = pi
	srv.SeedRunning(strings.Replace(paloSeed, `<permitted-ip><entry name="0.0.0.0/0"/></permitted-ip>`, "", 1))
	o := f.ok(t, "palo.apply", map[string]any{"scope": "policy"}, func(r *Request) { r.DryRun = true })
	if !strings.Contains(o.Plan.Diff, "rule.upsert") {
		t.Fatalf("plan %+v", o.Plan)
	}
	f.ok(t, "palo.apply", map[string]any{"scope": "policy"})
	if n := srv.Running().Select(mustXPath(t, palotest.VsysPath+"/rulebase/security/rules")); n == nil || len(n.Children) < 2 {
		t.Fatalf("policy not pushed: %v", n)
	}
	if !strings.Contains(srv.Running().String(), "human-rule") {
		t.Fatal("the human's rule was removed")
	}
	// evidence export
	out := filepath.Join(t.TempDir(), "evidence", "palo.xml")
	f.env.Root = "" // write to the real temp path
	o = f.ok(t, "palo.snapshot", map[string]any{"out": out})
	b, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(b), "human-rule") || o.Output["hash"] == "" {
		t.Fatalf("snapshot file: %v %q", err, o.Output)
	}
}

func mustXPath(t *testing.T, x string) []xmlapi.Step {
	t.Helper()
	s, err := xmlapi.ParseXPath(x)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDeviceActionsUnsupportedWithoutDirectory(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		a string
		p map[string]any
	}{
		{"palo.permitted_ips", map[string]any{"add": "10.0.0.1"}},
		{"palo.commit", map[string]any{}},
		{"vyos.snapshot", map[string]any{"out": "/tmp/x"}},
	} {
		if _, err := f.run(t, tc.a, tc.p); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: %v", tc.a, err)
		}
	}
}

// ---- VyOS ----

func vyosFixture(t *testing.T) (*fixture, *vyostest.Server, *fakeDevDir) {
	t.Helper()
	srv := vyostest.New()
	t.Cleanup(srv.Close)
	srv.Seed(
		"set interfaces ethernet eth0 address '10.0.0.1/24'",
		"set service ssh port '22'",
		"set firewall ipv4 forward filter rule 110 description 'human rule'",
		"set firewall ipv4 forward filter rule 110 action 'accept'")
	ad, err := vyos.New(vyos.Config{Device: "vyos1",
		Transport: devices.Transport{HTTP: srv.HTTP.Client(), Host: "127.0.0.1"},
		SSH: vyos.SSHConfig{Addr: srv.SSHAddr, User: "phylax", Auth: []ssh.AuthMethod{ssh.Password("pw")},
			HostKey: ssh.FixedHostKey(srv.HostKey), ExecWait: 10 * time.Second},
		HTTPBase: srv.HTTP.URL, APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	dir := &fakeDevDir{vy: ad, ack: true}
	f := newFixture(t)
	f.env.Host = "vyos1"
	f.env.Win.Devices = dir
	return f, srv, dir
}

func TestVyOSSnapshotAndApply(t *testing.T) {
	f, srv, dir := vyosFixture(t)
	f.env.Root = ""
	out := filepath.Join(t.TempDir(), "vyos-config.txt")
	o := f.ok(t, "vyos.snapshot", map[string]any{"out": out})
	b, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(b), "human rule") || o.Output["hash"] == "" {
		t.Fatalf("%v %q", err, b)
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
		t.Fatalf("evidence mode %v", st.Mode())
	}
	m := loadManifest(t)
	name := ""
	for n, d := range m.Devices {
		if d.Vendor == "vyos" {
			name = n
		}
	}
	vi, err := render.VyOSIntents(m, name)
	if err != nil {
		t.Skipf("vyos intent: %v", err)
	}
	dir.vi = vi
	o = f.ok(t, "vyos.apply", map[string]any{"scope": "policy", "outbound_interface": "eth0"})
	if o.Output["rolled_back"] != "false" {
		t.Fatalf("output %v", o.Output)
	}
	if !srv.Has("set firewall ipv4 forward filter rule 110 action 'accept'") {
		t.Fatal("the human's rule was removed")
	}
	managed := 0
	for _, l := range srv.Lines() {
		if strings.Contains(l, "phylax-managed") {
			managed++
		}
	}
	if managed == 0 {
		t.Fatal("no managed rules were pushed")
	}
}
