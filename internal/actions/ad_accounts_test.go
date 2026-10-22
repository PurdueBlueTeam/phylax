package actions

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// buildDomain makes a small domain: Domain Admins contains alice and a nested
// group "Helpdesk" (containing bob and, through a cycle, Domain Admins again).
func buildDomain(f *winFixture) (alice, bob, admin, eve, carol ADObject) {
	ad := f.ad
	admin = ad.user("Administrator", true, "500")
	alice = ad.user("alice", true, "1105")
	bob = ad.user("bob", true, "1106")
	eve = ad.user("eve", true, "1107")
	carol = ad.user("carol", true, "1108")
	ad.user("krbtgt", false, "502")
	for _, n := range []string{"Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "DnsAdmins"} {
		ad.group(n)
	}
	help := ad.group("Helpdesk", bob)
	da := ad.group("Domain Admins", admin, alice, help)
	ad.addMemberFix(help.DN, da) // cycle
	ad.addMemberFix(ad.objs[lower("CN=DnsAdmins,CN=Users,"+ad.domain)].DN, eve)
	return
}

func lower(s string) string { return strings.ToLower(s) }

func TestResolveMembersNestedAndCycle(t *testing.T) {
	f := newWinFixture(t)
	buildDomain(f)
	da, _, _ := f.ad.Find(t.Context(), "Domain Admins")
	leaves, groups, err := ResolveMembers(t.Context(), f.ad, da)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, m := range leaves {
		paths = append(paths, m.Path)
	}
	got := strings.Join(paths, "|")
	if !strings.Contains(got, "Domain Admins > Helpdesk > bob") || !strings.Contains(got, "Domain Admins > alice") || len(leaves) != 3 {
		t.Fatalf("paths %v", paths)
	}
	if len(groups) != 2 { // Domain Admins, Helpdesk (cycle not re-entered)
		t.Fatalf("groups %v", groups)
	}
}

func TestAuditGroupsFindsNestedUnexpected(t *testing.T) {
	f := newWinFixture(t)
	buildDomain(f)
	o := f.ok(t, "ad.account.audit_groups", map[string]any{"allow": []any{"Administrator", "alice"}})
	if !strings.Contains(o.Output["members.Domain Admins"], "Domain Admins > Helpdesk > bob") {
		t.Fatalf("output %v", o.Output)
	}
	un := o.Output["unexpected"]
	if !strings.Contains(un, "bob") || !strings.Contains(un, "eve") || strings.Contains(un, "alice") || o.Output["unexpected_count"] != "2" {
		t.Fatalf("unexpected = %q", un)
	}
	if o.Output["nested_groups.Domain Admins"] != "Helpdesk" {
		t.Fatalf("nested: %v", o.Output)
	}
	if !strings.Contains(o.Output["groups_not_found"], "Backup Operators") {
		t.Fatalf("missing groups not reported: %v", o.Output)
	}
	// fail_on_unexpected turns the finding into a failed step
	if _, err := f.run(t, "ad.account.audit_groups", map[string]any{"allow": []any{"Administrator", "alice"}, "fail_on_unexpected": true}); err == nil ||
		!strings.Contains(err.Error(), "unexpected privileged member") {
		t.Fatalf("err %v", err)
	}
	f.ok(t, "ad.account.audit_groups", map[string]any{"allow": []any{"Administrator", "alice", "bob", "eve"}, "fail_on_unexpected": true})
}

func TestAdminCountSweep(t *testing.T) {
	f := newWinFixture(t)
	alice, bob, admin, eve, carol := buildDomain(f)
	_ = admin
	for _, o := range []ADObject{alice, bob, eve, carol} {
		f.ad.objs[lower(o.DN)].AdminCount = 1
	}
	f.ad.objs[lower(admin.DN)].AdminCount = 1
	k, _, _ := f.ad.Find(t.Context(), "krbtgt")
	f.ad.objs[lower(k.DN)].AdminCount = 1
	// eve is in DnsAdmins (not an AdminSDHolder group), carol in nothing: stale
	o := f.ok(t, "ad.account.admincount_sweep", map[string]any{"report_only": true})
	if o.Changed || !strings.Contains(strings.Join(o.Plan.Notes, "\n"), "carol") {
		t.Fatalf("report: %+v", o.Plan)
	}
	if f.ad.objs[lower(carol.DN)].AdminCount != 1 {
		t.Fatal("report_only changed carol")
	}
	o = f.ok(t, "ad.account.admincount_sweep", map[string]any{}, func(r *Request) { r.Deadman = time.Minute })
	if o.Output["cleared"] != "2" {
		t.Fatalf("cleared %v", o.Output)
	}
	for sam, want := range map[string]int{"carol": 0, "eve": 0, "alice": 1, "bob": 1, "Administrator": 1, "krbtgt": 1} {
		x, _, _ := f.ad.Find(t.Context(), sam)
		if x.AdminCount != want {
			t.Errorf("%s adminCount=%d want %d", sam, x.AdminCount, want)
		}
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if f.ad.objs[lower(carol.DN)].AdminCount != 1 || f.ad.objs[lower(eve.DN)].AdminCount != 1 {
		t.Fatal("rollback did not restore adminCount")
	}
}

func TestADDisable(t *testing.T) {
	f := newWinFixture(t)
	_, _, _, eve, _ := buildDomain(f)
	o := f.ok(t, "ad.account.disable", map[string]any{"users": []any{"eve"}}, func(r *Request) { r.DryRun = true })
	if !strings.Contains(o.Plan.Diff, "eve: enabled -> disabled") || !f.ad.objs[lower(eve.DN)].Enabled {
		t.Fatalf("dry run %+v", o.Plan)
	}
	o = f.ok(t, "ad.account.disable", map[string]any{"users": []any{"eve"}})
	if f.ad.objs[lower(eve.DN)].Enabled || o.DeadmanID == "" {
		t.Fatal("not disabled or no dead-man")
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if !f.ad.objs[lower(eve.DN)].Enabled {
		t.Fatal("rollback did not re-enable")
	}
	// refusals
	for _, tc := range []struct {
		users []any
		want  string
	}{
		{[]any{"Administrator"}, "built-in Administrator"},
		{[]any{"krbtgt"}, "krbtgt"},
		{[]any{"Helpdesk"}, "is a group"},
		{[]any{"ghost"}, "no such account"},
	} {
		if _, err := f.run(t, "ad.account.disable", map[string]any{"users": tc.users}); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: err %v, want %q", tc.users, err, tc.want)
		}
	}
	// scored account: guard
	f.env.Guard = StaticGuard{Accounts: []string{"carol"}}
	if _, err := f.run(t, "ad.account.disable", map[string]any{"users": []any{"carol"}}); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("scored account disabled: %v", err)
	}
}

func TestADDisableKeepsLastDomainAdmin(t *testing.T) {
	f := newWinFixture(t)
	ad := f.ad
	lone := ad.user("lone", true, "1200")
	ad.group("Domain Admins", lone)
	if _, err := f.run(t, "ad.account.disable", map[string]any{"users": []any{"lone"}}); err == nil || !strings.Contains(err.Error(), "last enabled Domain Admin") {
		t.Fatalf("err %v", err)
	}
	if !ad.objs[lower(lone.DN)].Enabled {
		t.Fatal("disabled")
	}
}

func TestADResetPassword(t *testing.T) {
	f := newWinFixture(t)
	buildDomain(f)
	f.env.Guard = StaticGuard{Accounts: []string{"carol"}}
	p := map[string]any{"user": "eve", "password": "Sup3r-Secret-Value!"}
	o := f.ok(t, "ad.account.reset_password", p, func(r *Request) { r.DryRun = true })
	if strings.Contains(o.Plan.Diff, "Sup3r") {
		t.Fatal("password in the diff")
	}
	f.ok(t, "ad.account.reset_password", p)
	if len(f.ad.pwCalls) != 1 {
		t.Fatal("password not set")
	}
	// scored account: only inside a PCR transaction
	sp := map[string]any{"user": "carol", "password": "Sup3r-Secret-Value!"}
	if _, err := f.run(t, "ad.account.reset_password", sp); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("scored reset outside PCR: %v", err)
	}
	f.ok(t, "ad.account.reset_password", sp, func(r *Request) { r.PCR = true })
	// krbtgt has its own action
	if _, err := f.run(t, "ad.account.reset_password", map[string]any{"user": "krbtgt", "password": "x"}); err == nil {
		t.Fatal("krbtgt reset through reset_password")
	}
	// the secret never appears in errors
	spec, _ := f.env.Registry.Get("ad.account.reset_password")
	pp, _ := spec.Spec().Validate(p)
	if strings.Contains(pp.Redacted(), "Sup3r") {
		t.Fatal("password in Redacted()")
	}
}

func TestADGroupRemove(t *testing.T) {
	f := newWinFixture(t)
	alice, bob, admin, _, _ := buildDomain(f)
	o := f.ok(t, "ad.account.group_remove", map[string]any{"group": "Domain Admins", "members": []any{"alice"}}, func(r *Request) { r.Deadman = time.Minute })
	da, _, _ := f.ad.Find(t.Context(), "Domain Admins")
	if strings.Contains(strings.Join(da.Members, "|"), alice.DN) {
		t.Fatal("alice still in Domain Admins")
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	da, _, _ = f.ad.Find(t.Context(), "Domain Admins")
	if !strings.Contains(strings.Join(da.Members, "|"), alice.DN) {
		t.Fatal("rollback did not re-add alice")
	}
	// bob is only nested via Helpdesk
	_, err := f.run(t, "ad.account.group_remove", map[string]any{"group": "Domain Admins", "members": []any{"bob"}})
	if err == nil || !strings.Contains(err.Error(), "only through nesting") {
		t.Fatalf("nested removal: %v", err)
	}
	_ = bob
	// the built-in Administrator stays
	if _, err := f.run(t, "ad.account.group_remove", map[string]any{"group": "Domain Admins", "members": []any{"Administrator"}}); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("RID 500 removal: %v", err)
	}
	_ = admin
	// scored accounts keep their access groups
	f.ad.group("Remote Desktop Users", alice)
	f.env.Guard = StaticGuard{Accounts: []string{"alice"}, Groups: []string{"Remote Desktop Users"}}
	if _, err := f.run(t, "ad.account.group_remove", map[string]any{"group": "Remote Desktop Users", "members": []any{"alice"}}); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("scored access group removal: %v", err)
	}
}

func TestADGroupRemoveKeepsDomainAdminsNonEmpty(t *testing.T) {
	f := newWinFixture(t)
	ad := f.ad
	one := ad.user("one", true, "1300")
	ad.group("Domain Admins", one)
	if _, err := f.run(t, "ad.account.group_remove", map[string]any{"group": "Domain Admins", "members": []any{"one"}}); err == nil ||
		!strings.Contains(err.Error(), "without an enabled member") {
		t.Fatalf("err %v", err)
	}
}

func TestKrbtgtDoubleReset(t *testing.T) {
	f := newWinFixture(t)
	ad := f.ad
	k := ad.user("krbtgt", false, "502")
	ad.objs[lower(k.DN)].PwdLastSet = fixedNow.Add(-400 * 24 * time.Hour)
	confirm := "krbtgt@" + ad.domain
	step := func(n int, extra map[string]any) (*Outcome, error) {
		p := map[string]any{"step": n, "confirm": confirm}
		for k, v := range extra {
			p[k] = v
		}
		return f.run(t, "ad.account.krbtgt_reset", p)
	}
	// guards
	if _, err := f.run(t, "ad.account.krbtgt_reset", map[string]any{"step": 1, "confirm": "yes"}); err == nil || !strings.Contains(err.Error(), "confirm must be") {
		t.Fatalf("no confirmation: %v", err)
	}
	if _, err := f.run(t, "ad.account.krbtgt_reset", map[string]any{"step": 3, "confirm": confirm}); err == nil {
		t.Fatal("step 3 accepted")
	}
	// dry run reports and changes nothing
	o, err := f.run(t, "ad.account.krbtgt_reset", map[string]any{"step": 1, "confirm": confirm}, func(r *Request) { r.DryRun = true })
	if err != nil || len(ad.pwCalls) != 0 || !strings.Contains(strings.Join(o.Plan.Notes, " "), "not reversible") {
		t.Fatalf("dry run: %v %+v", err, o.Plan)
	}
	// destructive actions are never silently rolled back: no dead-man entry
	if o, err := step(1, nil); err != nil || o.DeadmanID != "" || len(ad.pwCalls) != 1 {
		t.Fatalf("step 1: %v %+v", err, o)
	}
	// step 1 again, or step 2 now, is too early
	if _, err := step(1, nil); err == nil || !strings.Contains(err.Error(), "step 1 already done") {
		t.Fatalf("repeat step 1: %v", err)
	}
	if _, err := step(2, nil); err == nil || !strings.Contains(err.Error(), "too early") {
		t.Fatalf("early step 2: %v", err)
	}
	if len(ad.pwCalls) != 1 {
		t.Fatal("a refused step changed the password")
	}
	// after the gap, step 2 proceeds
	f.env.Now = func() time.Time { return fixedNow.Add(11 * time.Hour) }
	f.ad.now = f.env.Now
	if _, err := step(2, nil); err != nil || len(ad.pwCalls) != 2 {
		t.Fatalf("step 2: %v", err)
	}
	// a custom shorter gap (lab) is honoured and bounded
	if _, err := step(2, map[string]any{"gap_minutes": 0}); err == nil {
		t.Fatal("gap 0 accepted")
	}
}

func TestADUnsupportedWithoutBackend(t *testing.T) {
	f := newFixture(t)
	if _, err := f.run(t, "ad.account.audit_groups", map[string]any{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got %v", err)
	}
}

func TestRandomPassword(t *testing.T) {
	a, err := RandomPassword(40)
	if err != nil || len(a) != 40 {
		t.Fatal(err, a)
	}
	b, _ := RandomPassword(40)
	if a == b {
		t.Fatal("not random")
	}
	var lower, upper, digit, sym bool
	for _, c := range a {
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		default:
			sym = true
		}
	}
	if !(lower && upper && digit && sym) {
		t.Fatalf("missing class in %q", a)
	}
}
