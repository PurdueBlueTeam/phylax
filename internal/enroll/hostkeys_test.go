package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/vault"
	"golang.org/x/crypto/ssh"
)

func testPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s.PublicKey()
}

func TestHostKeysRecordThenCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts.json")
	h, err := OpenHostKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	first, second := testPublicKey(t), testPublicKey(t)
	cb := h.Callback("h1")
	if err := cb("h1", nil, first); err != nil {
		t.Fatalf("first contact: %v", err)
	}
	if err := cb("h1", nil, first); err != nil {
		t.Fatalf("same key later: %v", err)
	}
	if err := cb("h1", nil, second); !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("different key err = %v, want ErrHostKeyChanged", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("known_hosts mode = %o, want 600", fi.Mode().Perm())
	}
	re, err := OpenHostKeys(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	rcb := re.Callback("h1")
	if err := rcb("h1", nil, first); err != nil {
		t.Fatalf("recorded key after reopen: %v", err)
	}
	if err := rcb("h1", nil, second); !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("a changed key after reopen err = %v, want ErrHostKeyChanged", err)
	}
}

func TestSSHPushHostKeyChanged(t *testing.T) {
	var alerts []string
	f := newEnrollerWith(t, func(o *Options) {
		o.Alert = func(host, reason, detail string) { alerts = append(alerts, host+" "+reason) }
	})
	srv := fakeSSHDefaults()
	addr := startFakeSSH(t, srv)
	hk, err := OpenHostKeys(filepath.Join(f.dir, "known_hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	// A different key was recorded for this host at an earlier contact.
	if err := hk.Callback("h1")("h1", nil, testPublicKey(t)); err != nil {
		t.Fatal(err)
	}
	p := &SSHPusher{Controller: "10.0.0.5:7443", HostKeys: hk, Timeout: 2 * time.Second}
	tgt := Target{Host: "h1", Addr: addr, User: "root", Pass: vault.NewSecretString("pw"), Hostname: "h1"}
	err = p.Push(context.Background(), f.e, tgt)
	var pe *PushError
	if !errors.As(err, &pe) || pe.Class != ClassHostKey {
		t.Fatalf("err = %v, want class %s", err, ClassHostKey)
	}
	if len(alerts) != 1 || alerts[0] != "h1 key_mismatch" {
		t.Fatalf("alerts = %v, want one key_mismatch for h1", alerts)
	}
}
