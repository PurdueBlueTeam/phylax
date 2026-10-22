package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

var fast = Options{WorkFactor: 10}

func newVault(t *testing.T) (*Vault, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "vault.age")
	v, err := Create(p, []byte("correct horse"), fast)
	if err != nil {
		t.Fatal(err)
	}
	return v, p
}

func TestRoundTripAndFileIsEncrypted(t *testing.T) {
	v, p := newVault(t)
	id, err := v.Put("cred/web01/root", NewSecretString("Sup3r.Secret-pw"), "initial")
	if err != nil || id != "v1" {
		t.Fatalf("put: %q %v", id, err)
	}
	raw, _ := os.ReadFile(p)
	if bytes.Contains(raw, []byte("Sup3r.Secret-pw")) || bytes.Contains(raw, []byte("web01")) {
		t.Fatal("plaintext leaked into vault file")
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	v2, err := Open(p, fast)
	if err != nil {
		t.Fatal(err)
	}
	if !v2.Locked() {
		t.Fatal("should start locked")
	}
	if _, _, err := v2.Get("cred/web01/root"); !errors.Is(err, ErrLocked) {
		t.Fatalf("got %v", err)
	}
	if err := v2.Unlock([]byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	s, gotID, err := v2.Get("cred/web01/root")
	if err != nil || s.Reveal() != "Sup3r.Secret-pw" || gotID != "v1" {
		t.Fatalf("get: %v %v", gotID, err)
	}
	names, _ := v2.Names()
	if len(names) != 1 || names[0] != "cred/web01/root" {
		t.Fatalf("names %v", names)
	}
	v2.Lock()
	if !v2.Locked() {
		t.Fatal("lock")
	}
	if _, _, err := v2.Get("x"); !errors.Is(err, ErrLocked) {
		t.Fatal("expected locked")
	}
}

func TestWrongPassphrase(t *testing.T) {
	v, p := newVault(t)
	v.Put("a", NewSecretString("x"), "")
	v2, _ := Open(p, fast)
	if err := v2.Unlock([]byte("nope")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("got %v", err)
	}
	if !v2.Locked() {
		t.Fatal("must stay locked")
	}
}

func TestTamperDetected(t *testing.T) {
	v, p := newVault(t)
	v.Put("a", NewSecretString("topsecretvalue"), "")
	orig, _ := os.ReadFile(p)
	// Flip a bit in several positions: header (MAC / stanza) and payload.
	for _, pos := range []int{len(orig) / 3, len(orig) / 2, len(orig) - 1, len(orig) - 20} {
		b := append([]byte(nil), orig...)
		b[pos] ^= 0x01
		os.WriteFile(p, b, 0o600)
		v2, _ := Open(p, fast)
		err := v2.Unlock([]byte("correct horse"))
		if err == nil {
			t.Fatalf("flip at %d accepted", pos)
		}
		if !v2.Locked() {
			t.Fatal("unlocked after tamper")
		}
	}
	// Truncation, including of the final chunk.
	os.WriteFile(p, orig[:len(orig)-5], 0o600)
	v2, _ := Open(p, fast)
	if err := v2.Unlock([]byte("correct horse")); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("truncation: %v", err)
	}
	// Payload flip is reported as corruption, not as a wrong passphrase.
	b := append([]byte(nil), orig...)
	b[len(b)-1] ^= 0x80
	os.WriteFile(p, b, 0o600)
	v3, _ := Open(p, fast)
	if err := v3.Unlock([]byte("correct horse")); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("payload flip: %v", err)
	}
}

func TestHistoryRollbackAndPrune(t *testing.T) {
	v, p := newVault(t)
	v.opt.MaxHistory = 3
	for i := 1; i <= 5; i++ {
		id, err := v.Put("k", NewSecretString(fmt.Sprintf("pw-%d", i)), fmt.Sprintf("n%d", i))
		if err != nil || id != fmt.Sprintf("v%d", i) {
			t.Fatal(id, err)
		}
	}
	h, _ := v.History("k")
	if len(h) != 3 || h[0].ID != "v3" || !h[2].Current || h[2].Note != "n5" {
		t.Fatalf("history %+v", h)
	}
	if _, err := v.GetVersion("k", "v1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("v1 should be pruned")
	}
	if err := v.Rollback("k", "v3"); err != nil {
		t.Fatal(err)
	}
	s, id, _ := v.Get("k")
	if s.Reveal() != "pw-3" || id != "v3" {
		t.Fatal(s.Reveal(), id)
	}
	// Roll forward again, and a new Put never reuses an id.
	if err := v.Rollback("k", "v5"); err != nil {
		t.Fatal(err)
	}
	if id, _ := v.Put("k", NewSecretString("pw-6"), ""); id != "v6" {
		t.Fatal(id)
	}
	if err := v.Rollback("k", "v99"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	// Persisted.
	v2, _ := Open(p, fast)
	v2.Unlock([]byte("correct horse"))
	s, id, _ = v2.Get("k")
	if s.Reveal() != "pw-6" || id != "v6" {
		t.Fatal(s.Reveal(), id)
	}
	old, err := v2.GetVersion("k", "v4")
	if err != nil || old.Reveal() != "pw-4" {
		t.Fatal(err)
	}
}

func TestPruneKeepsCurrentAfterRollback(t *testing.T) {
	v, _ := newVault(t)
	v.opt.MaxHistory = 2
	v.Put("k", NewSecretString("a"), "")
	v.Put("k", NewSecretString("b"), "")
	v.Rollback("k", "v1")
	v.Put("k", NewSecretString("c"), "")
	if _, err := v.GetVersion("k", "v3"); err != nil {
		t.Fatal("new current must survive prune")
	}
}

func TestFailedWriteLeavesStateUnchanged(t *testing.T) {
	v, p := newVault(t)
	v.Put("k", NewSecretString("a"), "")
	v.path = filepath.Join(filepath.Dir(p), "no-such-dir", "v.age")
	if _, err := v.Put("k", NewSecretString("b"), ""); err == nil {
		t.Fatal("expected write error")
	}
	s, id, _ := v.Get("k")
	if s.Reveal() != "a" || id != "v1" {
		t.Fatal("state changed after failed save")
	}
	if _, err := v.Put("fresh", NewSecretString("z"), ""); err == nil {
		t.Fatal("expected error")
	}
	if _, _, err := v.Get("fresh"); !errors.Is(err, ErrNotFound) {
		t.Fatal("failed new entry must not exist")
	}
}

func TestDeleteAndChangePassphrase(t *testing.T) {
	v, p := newVault(t)
	v.Put("a", NewSecretString("1"), "")
	v.Put("b", NewSecretString("2"), "")
	if err := v.Delete("a"); err != nil {
		t.Fatal(err)
	}
	if err := v.ChangePassphrase([]byte("new pass")); err != nil {
		t.Fatal(err)
	}
	v2, _ := Open(p, fast)
	if err := v2.Unlock([]byte("correct horse")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatal("old passphrase must stop working")
	}
	if err := v2.Unlock([]byte("new pass")); err != nil {
		t.Fatal(err)
	}
	if n, _ := v2.Names(); len(n) != 1 || n[0] != "b" {
		t.Fatal(n)
	}
}

func TestCreateRefusesOverwrite(t *testing.T) {
	_, p := newVault(t)
	if _, err := Create(p, []byte("x"), fast); !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
}

func TestExportBackupPassphrase(t *testing.T) {
	v, _ := newVault(t)
	v.Put("k", NewSecretString("a"), "")
	v.Put("k", NewSecretString("b"), "")
	var buf bytes.Buffer
	if err := v.ExportBackup(&buf); err != nil {
		t.Fatal(err)
	}
	bp := filepath.Join(t.TempDir(), "backup.age")
	os.WriteFile(bp, buf.Bytes(), 0o600)
	b, _ := Open(bp, fast)
	if err := b.Unlock([]byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	h, _ := b.History("k")
	if len(h) != 2 {
		t.Fatal("history must be in backup")
	}
}

func TestExportBackupX25519AndRestore(t *testing.T) {
	v, _ := newVault(t)
	v.Put("k", NewSecretString("val"), "")
	id, _ := age.GenerateX25519Identity()
	var buf bytes.Buffer
	if err := v.ExportBackup(&buf, id.Recipient()); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("val")) {
		t.Fatal("plaintext in backup")
	}
	// The live passphrase must not open an X25519-only backup.
	bp := filepath.Join(t.TempDir(), "b.age")
	os.WriteFile(bp, buf.Bytes(), 0o600)
	bv, _ := Open(bp, fast)
	if err := bv.Unlock([]byte("correct horse")); err == nil {
		t.Fatal("passphrase opened x25519 backup")
	}
	np := filepath.Join(t.TempDir(), "restored.age")
	r, err := RestoreBackup(np, bytes.NewReader(buf.Bytes()), id, []byte("fresh pass"), fast)
	if err != nil {
		t.Fatal(err)
	}
	s, _, _ := r.Get("k")
	if s.Reveal() != "val" {
		t.Fatal("restore content")
	}
	other, _ := age.GenerateX25519Identity()
	if _, err := RestoreBackup(filepath.Join(t.TempDir(), "x"), bytes.NewReader(buf.Bytes()), other, []byte("p"), fast); err == nil {
		t.Fatal("wrong identity accepted")
	}
	r2, _ := Open(np, fast)
	if err := r2.Unlock([]byte("fresh pass")); err != nil {
		t.Fatal(err)
	}
}

func TestSecretRedaction(t *testing.T) {
	const raw = "hunter2-needle-value"
	s := NewSecretString(raw)
	type wrap struct {
		User string
		Pw   Secret
		Ptr  *Secret
	}
	w := wrap{"u", s, &s}
	jb, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	var lb bytes.Buffer
	slog.New(slog.NewJSONHandler(&lb, nil)).Info("m", "pw", s, "w", w)
	slog.New(slog.NewTextHandler(&lb, nil)).Info("m", "pw", s)
	outs := []string{
		fmt.Sprintf("%v", s), fmt.Sprintf("%s", s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s),
		fmt.Sprintf("%q", s), fmt.Sprintf("%x", s), fmt.Sprintf("%d", s), fmt.Sprint(s),
		fmt.Sprintf("%v", w), fmt.Sprintf("%+v", w), fmt.Sprintf("%#v", w), fmt.Sprintf("%v", &s),
		fmt.Sprintf("%v", []Secret{s}), fmt.Sprintf("%v", map[string]Secret{"a": s}),
		string(jb), lb.String(), fmt.Sprint(fmt.Errorf("wrapped: %v", s)),
	}
	for i, o := range outs {
		if strings.Contains(o, raw) || strings.Contains(o, "hunter2") {
			t.Fatalf("output %d leaks: %s", i, o)
		}
	}
	if !strings.Contains(string(jb), Redacted) {
		t.Fatal("json should show marker")
	}
	if err := json.Unmarshal([]byte(`"x"`), &s); err == nil {
		t.Fatal("unmarshal must be refused")
	}
}

func TestSecretZeroAndEqual(t *testing.T) {
	a := NewSecretString("abcdef")
	b := NewSecretString("abcdef")
	if !a.Equal(b) || a.Equal(NewSecretString("abcdeg")) || a.Equal(NewSecretString("abc")) {
		t.Fatal("equal")
	}
	buf := a.b
	a.Zero()
	if !a.IsZero() || !bytes.Equal(buf, make([]byte, 6)) {
		t.Fatal("not wiped")
	}
}

func TestLockWipesBuffers(t *testing.T) {
	v, _ := newVault(t)
	v.Put("k", NewSecretString("wipe-me-please"), "")
	buf := v.doc.Entries["k"].Versions[0].Value
	pass := v.pass
	v.Lock()
	if bytes.Contains(buf, []byte("wipe")) || !bytes.Equal(pass, make([]byte, len(pass))) {
		t.Fatal("buffers not wiped on Lock")
	}
}

func TestRedactString(t *testing.T) {
	s := NewSecretString("p@ss-word1")
	got := RedactString("login failed for u:p@ss-word1 and again p@ss-word1", s)
	if strings.Contains(got, "p@ss") || strings.Count(got, Redacted) != 2 {
		t.Fatal(got)
	}
}

func TestConcurrentPuts(t *testing.T) {
	v, _ := newVault(t)
	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			_, err := v.Put(fmt.Sprintf("k%d", i%2), NewSecretString("v"), "")
			done <- err
		}(i)
	}
	for i := 0; i < 8; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	h, _ := v.History("k0")
	if len(h) != 4 {
		t.Fatal(len(h))
	}
}
