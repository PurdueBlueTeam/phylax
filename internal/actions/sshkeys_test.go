package actions

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"time"
)

func genKey(t *testing.T, comment string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var blob []byte
	for _, part := range [][]byte{[]byte("ssh-ed25519"), pub} {
		blob = binary.BigEndian.AppendUint32(blob, uint32(len(part)))
		blob = append(blob, part...)
	}
	s := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob)
	if comment != "" {
		s += " " + comment
	}
	return s
}

func TestAuthorizedKeys(t *testing.T) {
	f := newFixture(t)
	k1, k2, k3 := genKey(t, "alice@laptop"), genKey(t, ""), genKey(t, "")
	ctx := WithTag(t.Context(), Tag{Plan: "p1"})
	run := func(mode string, keys ...string) *Outcome {
		l := make([]any, len(keys))
		for i, k := range keys {
			l[i] = k
		}
		o, err := f.env.Execute(ctx, Request{Action: "ssh.authorized_keys", NodeID: "n", Deadman: NoDeadman,
			Params: map[string]any{"user": "alice", "keys": l, "mode": mode}})
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		return o
	}
	run("set", k1, k2)
	got := f.read(t, "home/alice/.ssh/authorized_keys")
	if !strings.Contains(got, k1+" phylax:p1\n") || !strings.Contains(got, k2+" phylax:p1\n") {
		t.Fatalf("tagging:\n%s", got)
	}
	st, _ := os.Stat(f.path("home/alice/.ssh/authorized_keys"))
	dst, _ := os.Stat(f.path("home/alice/.ssh"))
	if st.Mode().Perm() != 0o600 || dst.Mode().Perm() != 0o700 {
		t.Fatalf("modes %v %v", st.Mode(), dst.Mode())
	}
	if o := run("set", k2, k1); o.Changed {
		t.Fatal("set not idempotent for reordered same keys")
	}
	run("add", k3)
	if !strings.Contains(f.read(t, "home/alice/.ssh/authorized_keys"), k3) {
		t.Fatal("add")
	}
	run("remove", k1)
	got = f.read(t, "home/alice/.ssh/authorized_keys")
	if strings.Contains(got, strings.Fields(k1)[1]) || !strings.Contains(got, strings.Fields(k2)[1]) {
		t.Fatalf("remove:\n%s", got)
	}
	run("set", k3)
	if strings.Contains(f.read(t, "home/alice/.ssh/authorized_keys"), strings.Fields(k2)[1]) {
		t.Fatal("set did not replace")
	}
	// invalid keys are rejected before anything is written
	before := f.read(t, "home/alice/.ssh/authorized_keys")
	for _, bad := range []string{"not a key", "ssh-ed25519 AAAA", "ssh-rsa " + strings.Fields(k1)[1], "ssh-ed25519 " + strings.Fields(k1)[1] + "\nssh-rsa x"} {
		_, err := f.env.Execute(ctx, Request{Action: "ssh.authorized_keys", Deadman: NoDeadman, Params: map[string]any{"user": "alice", "keys": []any{bad}}})
		if err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if f.read(t, "home/alice/.ssh/authorized_keys") != before {
		t.Fatal("file changed by invalid input")
	}
}

func TestAuthorizedKeysDeadmanRollback(t *testing.T) {
	f := newFixture(t)
	f.write(t, "home/bob/.ssh/authorized_keys", "# mine\n", 0o600)
	k := genKey(t, "")
	f.ok(t, "ssh.authorized_keys", map[string]any{"user": "bob", "keys": []any{k}}, func(r *Request) { r.Deadman = 120 * time.Millisecond })
	waitFor(t, "rollback", func() bool { return f.read2("home/bob/.ssh/authorized_keys") == "# mine\n" })
}
