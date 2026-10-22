package actions

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
)

func secretCtx(t *testing.T, kv map[string]string) context.Context {
	t.Helper()
	b, _ := json.Marshal(kv)
	ctx, err := WithSecrets(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func (f *fixture) runCtx(t *testing.T, ctx context.Context, action string, params map[string]any, mut ...func(*Request)) (*Outcome, error) {
	t.Helper()
	r := Request{Action: action, Params: params, NodeID: "n1"}
	for _, m := range mut {
		m(&r)
	}
	return f.env.Execute(ctx, r)
}

const honeySecret = "Falcon!Secret77-DO-NOT-LOG"

func plantParams(extra map[string]any) map[string]any {
	p := map[string]any{"path": "/root/.aws/credentials", "mode": "0600", "only_if_absent": true,
		"secret_params": []any{"content"}, "secret_refs": map[string]any{"content": "honeytoken/ht-1/content"}}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

func TestFilePlantUsesSecretContentAndNeverShowsIt(t *testing.T) {
	f := newFixture(t)
	ctx := secretCtx(t, map[string]string{"content": "aws_secret=" + honeySecret + "\n"})

	// Dry run: a diff that names the file but not the content.
	o, err := f.runCtx(t, ctx, "file.plant", plantParams(nil), func(r *Request) { r.DryRun = true })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(o.Plan.Diff, honeySecret) || !strings.Contains(o.Plan.Diff, "/root/.aws/credentials") {
		t.Fatalf("diff: %q", o.Plan.Diff)
	}
	o, err = f.runCtx(t, ctx, "file.plant", plantParams(nil))
	if err != nil || !o.Changed {
		t.Fatalf("%+v %v", o, err)
	}
	if got := f.read(t, "root/.aws/credentials"); !strings.Contains(got, honeySecret) {
		t.Fatalf("content not written: %q", got)
	}
	if st, _ := os.Stat(f.path("root/.aws/credentials")); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	for _, s := range []string{o.Plan.Diff, strings.Join(o.Plan.Notes, "|")} {
		if strings.Contains(s, honeySecret) {
			t.Errorf("outcome leaks the secret: %q", s)
		}
	}
	// Idempotent.
	if o, err := f.runCtx(t, ctx, "file.plant", plantParams(nil)); err != nil || o.Changed {
		t.Fatalf("second run: %+v %v", o, err)
	}
}

func TestFilePlantOnlyIfAbsentNeverClobbers(t *testing.T) {
	f := newFixture(t)
	f.write(t, "root/.bash_history", "ls\ncd /var/www\n", 0o600)
	ctx := secretCtx(t, map[string]string{"content": "mysql -p'" + honeySecret + "'\n"})
	o, err := f.runCtx(t, ctx, "file.plant", plantParams(map[string]any{"path": "/root/.bash_history"}))
	if err != nil {
		t.Fatal(err)
	}
	if o.Changed {
		t.Fatal("reported a change")
	}
	if got := f.read(t, "root/.bash_history"); got != "ls\ncd /var/www\n" {
		t.Fatalf("real history clobbered: %q", got)
	}
	// And verify accepts the pre-existing file rather than failing the plan.
	a, _ := f.env.Registry.Get("file.plant")
	p, _ := a.Spec().Validate(plantParams(map[string]any{"path": "/root/.bash_history"}))
	if err := a.Verify(ctx, f.env, p); err != nil {
		t.Fatalf("verify of a pre-existing file: %v", err)
	}
	// Without only_if_absent the same step replaces it.
	o, err = f.runCtx(t, ctx, "file.plant", plantParams(map[string]any{"path": "/root/.bash_history", "only_if_absent": false}))
	if err != nil || !o.Changed || !strings.Contains(f.read(t, "root/.bash_history"), honeySecret) {
		t.Fatalf("%+v %v", o, err)
	}
}

func TestFilePlantRefusesPlaintextAndMissingSecrets(t *testing.T) {
	f := newFixture(t)
	// A plan that declares content secret yet carries it is rejected.
	_, err := f.runCtx(t, secretCtx(t, map[string]string{"content": "x"}), "file.plant",
		plantParams(map[string]any{"content": "leaked in the plan"}))
	if err == nil || strings.Contains(err.Error(), "leaked in the plan") {
		t.Fatalf("plaintext + secret declaration: %v", err)
	}
	// Secret declared but not delivered.
	if _, err := f.runCtx(t, context.Background(), "file.plant", plantParams(nil)); err == nil || !strings.Contains(err.Error(), "not delivered") {
		t.Fatalf("missing secret: %v", err)
	}
	// Only content may be secret.
	if _, err := f.runCtx(t, context.Background(), "file.plant", plantParams(map[string]any{"secret_params": []any{"path"}})); err == nil {
		t.Fatal("arbitrary secret_params accepted")
	}
	// Plain content still works (non-secret honey file).
	if _, err := f.runCtx(t, context.Background(), "file.plant", map[string]any{"path": "/root/notes.txt", "content": "Internal use only\n"}); err != nil {
		t.Fatal(err)
	}
}

func TestWithSecretsRejectsGarbageAndOversize(t *testing.T) {
	if _, err := WithSecrets(context.Background(), []byte(`["a"]`)); err == nil {
		t.Error("non-object accepted")
	}
	if _, err := WithSecrets(context.Background(), make([]byte, maxSecretsBlob+1)); err == nil {
		t.Error("oversize accepted")
	}
	ctx, err := WithSecrets(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := SecretParam(ctx, "x"); ok {
		t.Error("phantom secret")
	}
}

// ---- ad.honey_account ----

type fakeAD struct {
	mu       sync.Mutex
	accounts map[string]HoneyAccount
	failWith error
}

func (a *fakeAD) HoneyAccountExists(_ context.Context, n string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.accounts[n]
	return ok, nil
}

func (a *fakeAD) CreateHoneyAccount(_ context.Context, h HoneyAccount) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failWith != nil {
		return a.failWith
	}
	if a.accounts == nil {
		a.accounts = map[string]HoneyAccount{}
	}
	a.accounts[h.Name] = h
	return nil
}

func adParams(extra map[string]any) map[string]any {
	p := map[string]any{"name": "svc_sql07", "ou": "OU=Decoys,DC=corp,DC=example", "description": "Service account",
		"spn": "MSSQLSvc/sql07.corp.example:1433", "secret_params": []any{"password"},
		"secret_refs": map[string]any{"password": "honeytoken/ht-2/password"}}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

func TestADHoneyAccountThroughBackend(t *testing.T) {
	f := newFixture(t)
	be := &fakeAD{}
	SetHoneyADBackend(be)
	defer SetHoneyADBackend(nil)
	ctx := secretCtx(t, map[string]string{"password": honeySecret})

	o, err := f.runCtx(t, ctx, "ad.honey_account", adParams(nil), func(r *Request) { r.DryRun = true })
	if err != nil || strings.Contains(o.Plan.Diff, honeySecret) || len(be.accounts) != 0 {
		t.Fatalf("dry run: %+v %v accounts=%v", o, err, be.accounts)
	}
	o, err = f.runCtx(t, ctx, "ad.honey_account", adParams(map[string]any{"dont_require_preauth": true}))
	if err != nil || !o.Changed {
		t.Fatalf("%+v %v", o, err)
	}
	got := be.accounts["svc_sql07"]
	if got.Password != honeySecret || got.SPN == "" || !got.DontRequirePreauth || !got.Enabled {
		t.Fatalf("backend got %+v", got)
	}
	// Idempotent: an existing account is left alone.
	if o, err := f.runCtx(t, ctx, "ad.honey_account", adParams(nil)); err != nil || o.Changed {
		t.Fatalf("second run: %+v %v", o, err)
	}
}

func TestADHoneyAccountSecretHygiene(t *testing.T) {
	f := newFixture(t)
	be := &fakeAD{failWith: errors.New("ldap: constraint violation for password " + honeySecret)}
	SetHoneyADBackend(be)
	defer SetHoneyADBackend(nil)
	ctx := secretCtx(t, map[string]string{"password": honeySecret})
	_, err := f.runCtx(t, ctx, "ad.honey_account", adParams(nil))
	if err == nil || strings.Contains(err.Error(), honeySecret) {
		t.Fatalf("backend error leaked or swallowed: %v", err)
	}
	// There is no plaintext password parameter at all.
	if _, err := f.runCtx(t, ctx, "ad.honey_account", adParams(map[string]any{"password": "x"})); err == nil {
		t.Fatal("plaintext password parameter accepted")
	}
	// Secret not declared => refused.
	if _, err := f.runCtx(t, ctx, "ad.honey_account", adParams(map[string]any{"secret_params": []any{}})); err == nil {
		t.Fatal("undeclared password accepted")
	}
	// Unsafe account names are refused.
	if _, err := f.runCtx(t, ctx, "ad.honey_account", adParams(map[string]any{"name": "bad name"})); err == nil {
		t.Fatal("bad sAMAccountName accepted")
	}
}

func TestADHoneyAccountWithoutBackend(t *testing.T) {
	f := newFixture(t)
	SetHoneyADBackend(nil)
	_, err := f.runCtx(t, secretCtx(t, map[string]string{"password": "p"}), "ad.honey_account", adParams(nil))
	if !errors.Is(err, ErrNoADBackend) {
		t.Fatalf("err = %v", err)
	}
}

func TestDecoyCheck(t *testing.T) {
	f := newFixture(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	up := ln.Addr().(*net.TCPAddr).Port
	if _, err := f.runCtx(t, context.Background(), "deception.decoy_check", map[string]any{"ports": []any{itoa(up)}, "wait_sec": 1}); err != nil {
		t.Fatalf("listening port: %v", err)
	}
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	dp := dead.Addr().(*net.TCPAddr).Port
	dead.Close()
	_, err = f.runCtx(t, context.Background(), "deception.decoy_check", map[string]any{"ports": []any{itoa(up), itoa(dp)}, "wait_sec": 1})
	if err == nil || !strings.Contains(err.Error(), itoa(dp)) {
		t.Fatalf("closed port not reported: %v", err)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }
