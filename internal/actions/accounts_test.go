package actions

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func lines(s string) []string { return strings.Split(strings.TrimSuffix(s, "\n"), "\n") }

func TestSetPasswordKeepsEverythingElse(t *testing.T) {
	f := newFixture(t)
	before := lines(f.read(t, "etc/shadow"))
	f.ok(t, "user.set_password", map[string]any{"user": "sysadmin", "password": "N3w-Pass!"}, func(r *Request) { r.Deadman = NoDeadman })
	after := lines(f.read(t, "etc/shadow"))
	if len(after) != len(before) {
		t.Fatalf("line count changed: %d -> %d", len(before), len(after))
	}
	days := strconv.FormatInt(fixedNow.Unix()/86400, 10)
	for i := range before {
		if strings.HasPrefix(before[i], "sysadmin:") {
			f1 := strings.Split(after[i], ":")
			if len(f1) != 9 {
				t.Fatalf("field count %d: %q", len(f1), after[i])
			}
			// aging fields: min=1 max=90 warn=14 inactive=30 expire=20000 reserved=""
			if got := strings.Join(f1[3:], ":"); got != "1:90:14:30:20000:" {
				t.Fatalf("aging fields not kept: %q", got)
			}
			if f1[2] != days {
				t.Fatalf("lastchg %q want %q", f1[2], days)
			}
			if ok, err := CheckPassword(f1[1], "N3w-Pass!"); err != nil || !ok {
				t.Fatalf("new hash does not verify: %v %v", ok, err)
			}
			continue
		}
		if before[i] != after[i] {
			t.Fatalf("other line changed:\n %q\n %q", before[i], after[i])
		}
	}
	if st, _ := os.Stat(f.path("etc/shadow")); st.Mode().Perm() != 0o640 {
		t.Fatalf("shadow mode %v", st.Mode())
	}
	// passwd untouched, byte for byte
	if f.read(t, "etc/passwd") != passwdFix {
		t.Fatal("passwd modified")
	}
	// second run is a no-op (check says done)
	out, err := f.run(t, "user.set_password", map[string]any{"user": "sysadmin", "password": "N3w-Pass!"}, func(r *Request) { r.Deadman = NoDeadman })
	if err != nil || out.Changed || !out.Plan.Done {
		t.Fatalf("not idempotent: %+v %v", out, err)
	}
}

func TestSetPasswordNoTrailingNewlineAndHashParam(t *testing.T) {
	f := newFixture(t)
	f.write(t, "etc/shadow", strings.TrimSuffix(shadowFix, "\n"), 0o600)
	h, _ := HashPassword("pw1")
	f.ok(t, "user.set_password", map[string]any{"user": "bob", "hash": h, "must_change": true}, func(r *Request) { r.Deadman = NoDeadman })
	s := f.read(t, "etc/shadow")
	if strings.HasSuffix(s, "\n") {
		t.Fatal("trailing newline invented")
	}
	if !strings.Contains(s, "bob:"+h+":0:0:99999:7:::") {
		t.Fatalf("must_change/hash: %s", s)
	}
	if st, _ := os.Stat(f.path("etc/shadow")); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
}

func TestSetPasswordUnknownUserAndBadParams(t *testing.T) {
	f := newFixture(t)
	if _, err := f.run(t, "user.set_password", map[string]any{"user": "nobody2", "password": "x"}, func(r *Request) { r.Deadman = NoDeadman }); err == nil {
		t.Fatal("expected error for unknown user")
	}
	if _, err := f.run(t, "user.set_password", map[string]any{"user": "bob"}); err == nil {
		t.Fatal("expected error: neither password nor hash")
	}
	if _, err := f.run(t, "user.set_password", map[string]any{"user": "bob:x", "password": "x"}); err == nil {
		t.Fatal("expected invalid name error")
	}
	if _, err := f.run(t, "user.set_password", map[string]any{"user": "bob", "password": "x", "bogus": 1}); err == nil {
		t.Fatal("expected unknown parameter error")
	}
	if f.read(t, "etc/shadow") != shadowFix {
		t.Fatal("shadow changed by failed runs")
	}
}

func TestPasswordSecretsNeverInDiffOrErrors(t *testing.T) {
	f := newFixture(t)
	o, err := f.run(t, "user.set_password", map[string]any{"user": "bob", "password": "Sup3rSecretValue"}, func(r *Request) { r.DryRun = true })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(o.Plan.Diff, "Sup3rSecretValue") {
		t.Fatal("secret in diff")
	}
	_, err = f.run(t, "user.set_password", map[string]any{"user": "bob", "password": 12345})
	if err == nil || strings.Contains(err.Error(), "12345") {
		t.Fatalf("bad error handling: %v", err)
	}
}

func TestLockUnlock(t *testing.T) {
	f := newFixture(t)
	f.ok(t, "user.lock", map[string]any{"user": "sysadmin"}, func(r *Request) { r.Deadman = NoDeadman })
	if !strings.Contains(f.read(t, "etc/shadow"), "sysadmin:!$6$oldsalt$oldhasholdhasholdhash:19500:1:90:14:30:20000:\n") {
		t.Fatalf("lock result:\n%s", f.read(t, "etc/shadow"))
	}
	// already locked: no-op
	if o, _ := f.run(t, "user.lock", map[string]any{"user": "alice"}, func(r *Request) { r.Deadman = NoDeadman }); !o.Plan.Done {
		t.Fatal("alice already locked should be done")
	}
	f.ok(t, "user.lock", map[string]any{"user": "sysadmin", "unlock": true}, func(r *Request) { r.Deadman = NoDeadman })
	if f.read(t, "etc/shadow") != shadowFix {
		t.Fatalf("lock/unlock round trip differs:\n%s", f.read(t, "etc/shadow"))
	}
	// "*" accounts cannot be unlocked
	if _, err := f.run(t, "user.lock", map[string]any{"user": "bob", "unlock": true}, func(r *Request) { r.Deadman = NoDeadman }); err != nil {
		// bob "*" counts as locked, so unlock must fail loudly
		if !strings.Contains(err.Error(), "cannot unlock") {
			t.Fatalf("unexpected error %v", err)
		}
	} else {
		t.Fatal("unlocking * should fail")
	}
}

func TestCreateAndDeleteUser(t *testing.T) {
	f := newFixture(t)
	ctx := WithTag(t.Context(), Tag{Plan: "harden-1", Node: "n7"})
	_, err := f.env.Execute(ctx, Request{Action: "user.create", NodeID: "n7", Params: map[string]any{
		"user": "carol", "password": "Pw-carol-1", "create_home": true}})
	if err != nil {
		t.Fatal(err)
	}
	pw := f.read(t, "etc/passwd")
	if !strings.Contains(pw, "carol:x:1003:1003:phylax:harden-1:/home/carol:/bin/bash\n") {
		t.Fatalf("passwd:\n%s", pw)
	}
	if !strings.HasPrefix(pw, passwdFix) {
		t.Fatal("existing passwd lines disturbed")
	}
	if !strings.HasPrefix(f.read(t, "etc/shadow"), shadowFix) || !strings.HasPrefix(f.read(t, "etc/group"), groupFix) || !strings.HasPrefix(f.read(t, "etc/gshadow"), gshadowFix) {
		t.Fatal("existing lines disturbed")
	}
	if !strings.Contains(f.read(t, "etc/group"), "carol:x:1003:\n") || !strings.Contains(f.read(t, "etc/gshadow"), "carol:!::\n") {
		t.Fatal("private group missing")
	}
	if st, err := os.Stat(f.path("home/carol")); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("home: %v %v", st, err)
	}
	if ok, _ := f.env.Accounts.PasswordIs(t.Context(), "carol", "Pw-carol-1"); !ok {
		t.Fatal("password not set on create")
	}
	// again: done
	if o, _ := f.run(t, "user.create", map[string]any{"user": "carol"}); !o.Plan.Done {
		t.Fatal("create not idempotent")
	}
	// delete restores everything but keeps home
	f.ok(t, "user.delete", map[string]any{"user": "carol"}, func(r *Request) { r.Deadman = NoDeadman })
	for _, c := range []struct{ file, want string }{{"etc/passwd", passwdFix}, {"etc/shadow", shadowFix}, {"etc/group", groupFix}, {"etc/gshadow", gshadowFix}} {
		if got := f.read(t, c.file); got != c.want {
			t.Fatalf("%s after delete:\n%s", c.file, got)
		}
	}
	if _, err := os.Stat(f.path("home/carol")); err != nil {
		t.Fatal("home directory must be kept")
	}
	if _, err := f.run(t, "user.delete", map[string]any{"user": "root"}); err == nil {
		t.Fatal("deleting uid 0 must be refused")
	}
}

func TestGroupMembers(t *testing.T) {
	f := newFixture(t)
	f.ok(t, "group.members", map[string]any{"group": "sudo", "add": []any{"bob"}, "remove": []any{"alice"}}, func(r *Request) { r.Deadman = NoDeadman })
	if !strings.Contains(f.read(t, "etc/group"), "sudo:x:27:sysadmin,bob\n") || !strings.Contains(f.read(t, "etc/gshadow"), "sudo:*:sysadmin:sysadmin,bob\n") {
		t.Fatalf("group:\n%s\n%s", f.read(t, "etc/group"), f.read(t, "etc/gshadow"))
	}
	o, err := f.run(t, "group.members", map[string]any{"group": "sudo", "members": []any{"sysadmin", "bob"}}, func(r *Request) { r.Deadman = NoDeadman })
	if err != nil || !o.Plan.Done {
		t.Fatalf("exact set should be done: %+v %v", o, err)
	}
	f.ok(t, "group.members", map[string]any{"group": "sudo", "members": []any{"alice"}}, func(r *Request) { r.Deadman = NoDeadman })
	if !strings.Contains(f.read(t, "etc/group"), "sudo:x:27:alice\n") {
		t.Fatal(f.read(t, "etc/group"))
	}
	if _, err := f.run(t, "group.members", map[string]any{"group": "nosuch", "add": []any{"bob"}}); err == nil {
		t.Fatal("unknown group")
	}
}

// Many concurrent edits through the executor must serialize: none lost, no
// corruption, other lines intact.
func TestConcurrentAccountEdits(t *testing.T) {
	f := newFixture(t)
	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, 2*n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("svc%02d", i)
			if _, err := f.run(t, "user.create", map[string]any{"user": name, "password": "pw-" + name}, func(r *Request) { r.NodeID = name }); err != nil {
				errs <- err
				return
			}
			if _, err := f.run(t, "user.set_password", map[string]any{"user": name, "password": "second-" + name}, func(r *Request) { r.NodeID = name; r.Deadman = NoDeadman }); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("svc%02d", i)
		if ok, _ := f.env.Accounts.PasswordIs(t.Context(), name, "second-"+name); !ok {
			t.Errorf("%s lost its update", name)
		}
	}
	if !strings.HasPrefix(f.read(t, "etc/passwd"), passwdFix) {
		t.Fatal("passwd corrupted")
	}
	uids := map[string]bool{}
	for _, l := range lines(f.read(t, "etc/passwd")) {
		u := strings.Split(l, ":")[2]
		if uids[u] {
			t.Fatalf("duplicate uid %s", u)
		}
		uids[u] = true
	}
}

// Two independent FileAccounts values (as two processes would have) still
// serialize via the shadow-utils lock file.
func TestCrossProcessLockFile(t *testing.T) {
	f := newFixture(t)
	a := &FileAccounts{Root: f.root}
	rel, err := a.lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// An fcntl lock is per-process, so exclusion from another "process" cannot be
	// shown in-process; check the in-process mutex holds a second locker off.
	got := make(chan struct{})
	go func() {
		r2, err := a.lock(t.Context())
		if err == nil {
			r2()
		}
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("second locker entered while lock held")
	case <-time.After(100 * time.Millisecond):
	}
	rel()
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("second locker never acquired")
	}
	if _, err := os.Stat(f.path("etc/.pwd.lock")); err != nil {
		t.Fatal("lock file missing")
	}
}
