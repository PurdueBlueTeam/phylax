package honeytokens

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

var allKinds = []TokenDef{{Kind: "ssh_key"}, {Kind: "db_cred"}, {Kind: "shell_history"}, {Kind: "passwords_file"},
	{Kind: "browser_cred"}, {Kind: "aws_key"}}

func TestUniqueAcrossHostsAndKinds(t *testing.T) {
	reg := NewRegistry()
	g := NewGenerator(reg)
	secrets, users, ids, fps := map[string]string{}, map[string]string{}, map[string]bool{}, map[string]bool{}
	for i := 0; i < 150; i++ {
		host := fmt.Sprintf("host%03d", i)
		p, err := g.ForHost(HostSpec{Host: host, Tokens: allKinds, HoneyFiles: []string{"backup.sql", "id_rsa_old"}})
		if err != nil {
			t.Fatal(err)
		}
		for _, tk := range p.Tokens {
			if ids[tk.ID] {
				t.Fatalf("duplicate id %s", tk.ID)
			}
			ids[tk.ID] = true
			if tk.Secret != "" {
				if prev, dup := secrets[tk.Secret]; dup {
					t.Fatalf("secret reused between %s and %s", prev, host)
				}
				secrets[tk.Secret] = host
			}
			if tk.User != "" {
				if prev, dup := users[strings.ToLower(tk.User)]; dup {
					t.Fatalf("user %s reused between %s and %s", tk.User, prev, host)
				}
				users[strings.ToLower(tk.User)] = host
			}
			if tk.Fingerprint != "" {
				if fps[tk.Fingerprint] {
					t.Fatal("fingerprint reused")
				}
				fps[tk.Fingerprint] = true
			}
		}
	}
	if len(reg.Tokens()) != len(ids) {
		t.Errorf("registry has %d, plans have %d", len(reg.Tokens()), len(ids))
	}
}

// A generator whose entropy repeats must be caught by the registry, not ship
// two hosts with the same secret.
func TestRegistryRefusesCollisions(t *testing.T) {
	reg := NewRegistry()
	a := Token{ID: "ht-1", Host: "h1", Kind: KindDBCred, User: "svc_a", Secret: "S3cret", Path: "/x"}
	if err := reg.Add(a); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]Token{
		"id":     {ID: "ht-1", Host: "h2", Kind: KindDBCred, Secret: "other"},
		"secret": {ID: "ht-2", Host: "h2", Kind: KindDBCred, Secret: "S3cret"},
		"user":   {ID: "ht-3", Host: "h2", Kind: KindDBCred, User: "SVC_A"},
		"path":   {ID: "ht-4", Host: "h1", Kind: KindHoneyFile, Path: "/X"},
	} {
		if err := reg.Add(b); !errors.Is(err, ErrDuplicate) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if err := reg.Add(Token{ID: "ht-5", Host: "h2", Kind: KindHoneyFile, Path: "/x"}); err != nil {
		t.Errorf("same path on another host is fine: %v", err)
	}

	// Identical entropy for two hosts: the generator redraws instead of reusing values.
	reg2 := NewRegistry()
	mk := func() *Generator { return &Generator{Rand: rand.New(rand.NewSource(7)), Reg: reg2} }
	pa, err := mk().ForHost(HostSpec{Host: "a", Tokens: []TokenDef{{Kind: "db_cred"}}})
	if err != nil {
		t.Fatal(err)
	}
	pb, err := mk().ForHost(HostSpec{Host: "b", Tokens: []TokenDef{{Kind: "db_cred"}}})
	if err != nil {
		t.Fatal(err)
	}
	if pa.Tokens[0].Secret == pb.Tokens[0].Secret || pa.Tokens[0].User == pb.Tokens[0].User {
		t.Error("two hosts share a secret or account")
	}
}

func TestTokenContents(t *testing.T) {
	reg := NewRegistry()
	g := NewGenerator(reg)
	p, err := g.ForHost(HostSpec{Host: "rocky-ecom", Tokens: allKinds, HoneyFiles: []string{"backup.sql", "/srv/share/id_rsa_old"}})
	if err != nil {
		t.Fatal(err)
	}
	byKind := map[Kind][]ActionSpec{}
	tokByID := map[string]Token{}
	for _, tk := range p.Tokens {
		tokByID[tk.ID] = tk
	}
	for _, a := range p.Actions {
		if a.Action != "file.write" || a.Host != "rocky-ecom" || !a.OnlyIfAbsent {
			t.Errorf("action %+v must be a guarded file.write on the host", a)
		}
		if len(a.SecretParams) == 0 || a.Params["mode"] == "" {
			t.Errorf("secrets/mode not set: %+v", a)
		}
		byKind[tokByID[a.Token].Kind] = append(byKind[tokByID[a.Token].Kind], a)
	}
	// ssh key: parses, fingerprint matches the registry
	for _, a := range byKind[KindSSHKey] {
		signer, err := ssh.ParsePrivateKey([]byte(a.Params["content"].(string)))
		if err != nil {
			t.Fatalf("honey key does not parse: %v", err)
		}
		tk := tokByID[a.Token]
		if ssh.FingerprintSHA256(signer.PublicKey()) != tk.Fingerprint {
			t.Error("fingerprint mismatch")
		}
		if m, ok := reg.MatchFingerprint(tk.Fingerprint); !ok || m.Host != "rocky-ecom" {
			t.Error("registry does not match the key fingerprint")
		}
	}
	if len(byKind[KindSSHKey]) != 2 || len(byKind[KindHoneyFile]) != 1 {
		t.Errorf("ssh=%d honey=%d (id_rsa_old must become a key)", len(byKind[KindSSHKey]), len(byKind[KindHoneyFile]))
	}
	aws := tokByID[byKind[KindAWSKey][0].Token]
	if !regexp.MustCompile(`^AKIA[A-Z2-7]{16}$`).MatchString(aws.User) || len(aws.Secret) != 40 {
		t.Errorf("aws key format: %q / %d chars", aws.User, len(aws.Secret))
	}
	if c := byKind[KindAWSKey][0].Params["content"].(string); !strings.Contains(c, aws.User) || !strings.Contains(c, aws.Secret) {
		t.Error("aws credentials file lacks the key")
	}
	// secrets are present in the planted content
	for _, k := range []Kind{KindDBCred, KindShellHistory, KindPasswordsFile, KindBrowserCred} {
		a := byKind[k][0]
		if !strings.Contains(a.Params["content"].(string), tokByID[a.Token].Secret) {
			t.Errorf("%s content lacks its secret", k)
		}
	}
	// passwords file carries three distinct tokens
	pw := 0
	for _, tk := range p.Tokens {
		if tk.Kind == KindPasswordsFile {
			pw++
		}
	}
	if pw != 3 {
		t.Errorf("passwords file tokens = %d", pw)
	}
	// every planted file is watched via fanotify on Linux
	if len(p.Watches) != len(p.Actions) {
		t.Errorf("%d watches for %d files", len(p.Watches), len(p.Actions))
	}
	for _, w := range p.Watches {
		if w.Method != "fanotify" {
			t.Errorf("watch %+v", w)
		}
	}
	// a .env's creds are the db_cred token
	if env := byKind[KindDBCred][0].Params["content"].(string); !strings.Contains(env, "DB_PASSWORD=") {
		t.Errorf(".env = %q", env)
	}
}

func TestWindowsPlan(t *testing.T) {
	g := NewGenerator(NewRegistry())
	p, err := g.ForHost(HostSpec{Host: "mssql", Windows: true, Tokens: []TokenDef{{Kind: "db_cred"}, {Kind: "passwords_file"}},
		HoneyFiles: []string{`C:\Shares\SOP\passwords.xlsx`}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Watches) == 0 {
		t.Fatal("no watches")
	}
	for _, w := range p.Watches {
		if w.Method != "sacl" || !strings.HasPrefix(w.Path, `C:\`) {
			t.Errorf("watch %+v", w)
		}
	}
	if _, err := g.ForHost(HostSpec{Host: "w2", Windows: true, Tokens: []TokenDef{{Kind: "ssh_key"}}}); err == nil {
		t.Error("ssh_key on Windows should be refused")
	}
}

func TestADAccounts(t *testing.T) {
	reg := NewRegistry()
	g := NewGenerator(reg)
	spec := HostSpec{Host: "dc01", Windows: true, Domain: "corp.example",
		Tokens: []TokenDef{{Kind: "ad_spn"}, {Kind: "ad_asrep"}, {Kind: "ad_admin"}}}
	p, err := g.ForHost(spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.ADAccount) != 3 || len(p.Actions) != 3 {
		t.Fatalf("%d accounts, %d actions", len(p.ADAccount), len(p.Actions))
	}
	for _, a := range p.ADAccount {
		if !strings.HasPrefix(a.OU, "OU=Decoys,DC=corp,DC=example") {
			t.Errorf("OU = %q", a.OU)
		}
		switch a.Kind {
		case KindADSPN:
			if !regexp.MustCompile(`^MSSQLSvc/[a-z]+\d\d\.corp\.example:1433$`).MatchString(a.SPN) {
				t.Errorf("spn = %q", a.SPN)
			}
		case KindADASREP:
			if !a.DontRequirePreauth || a.SPN != "" {
				t.Errorf("asrep = %+v", a)
			}
		case KindADAdmin:
			if !strings.Contains(a.Name, "adm") && !strings.Contains(a.Name, "admin") {
				t.Errorf("admin lookalike name %q", a.Name)
			}
		}
	}
	for _, a := range p.Actions {
		if a.Action != "ad.honey_account" || a.Params["logon_rights"] != "none" || a.SecretParams[0] != "password" {
			t.Errorf("action %+v", a)
		}
	}
	// sightings resolve to the DC
	seeds := reg.Seeds()
	if len(seeds["honeytoken.spns"]) != 1 || len(seeds["honeytoken.accounts"]) != 3 {
		t.Errorf("seeds = %+v", seeds)
	}
	spn := seeds["honeytoken.spns"][0]
	if tk, ok := reg.Attribute(map[string]any{"service_name": strings.ToUpper(spn)}); !ok || tk.Host != "dc01" || tk.Kind != KindADSPN {
		t.Errorf("4769 attribution = %+v %v", tk, ok)
	}
	if tk, ok := reg.Attribute(map[string]any{"account": `CORP\` + strings.ToUpper(p.ADAccount[1].Name)}); !ok || tk.Kind != KindADASREP {
		t.Errorf("account attribution = %+v %v", tk, ok)
	}
	if _, err := NewGenerator(NewRegistry()).ForHost(HostSpec{Host: "web", Tokens: []TokenDef{{Kind: "ad_spn"}}}); err == nil {
		t.Error("AD token on a host without a domain should fail")
	}
}

func TestAttributeAndMatch(t *testing.T) {
	reg := NewRegistry()
	g := NewGenerator(reg)
	p, _ := g.ForHost(HostSpec{Host: "ubuntu-email", Tokens: []TokenDef{{Kind: "db_cred"}, {Kind: "shell_history"}, {Kind: "aws_key"}},
		HoneyFiles: []string{"/root/creds.txt"}})
	var db, hist, aws, file Token
	for _, tk := range p.Tokens {
		switch tk.Kind {
		case KindDBCred:
			db = tk
		case KindShellHistory:
			hist = tk
		case KindAWSKey:
			aws = tk
		case KindHoneyFile:
			file = tk
		}
	}
	if tk, ok := reg.MatchCredential("anyone", hist.Secret); !ok || tk.ID != hist.ID {
		t.Error("history password should match whatever account it is sprayed at")
	}
	if _, ok := reg.MatchCredential("svc", "wrong"); ok {
		t.Error("wrong secret matched")
	}
	if _, ok := reg.MatchCredential("svc", ""); ok {
		t.Error("empty secret matched")
	}
	for name, f := range map[string]map[string]any{
		"account":    {"account": db.User},
		"aws":        {"aws_access_key_id": aws.User},
		"object":     {"object_name": file.Path},
		"id":         {"honeytoken": file.ID},
		"4663 field": {"path": strings.ToUpper(file.Path)},
	} {
		tk, ok := reg.Attribute(f)
		if !ok || tk.Host != "ubuntu-email" {
			t.Errorf("%s: attribution %+v %v", name, tk, ok)
		}
	}
	if _, ok := reg.Attribute(map[string]any{"account": "azul"}); ok {
		t.Error("real account attributed")
	}
	if seeds := reg.Seeds(); len(seeds["honeytoken.aws_keys"]) != 1 || len(seeds["honeytoken.paths"]) < 3 {
		t.Errorf("seeds = %+v", seeds)
	}
}

func TestBadInput(t *testing.T) {
	g := NewGenerator(NewRegistry())
	for name, s := range map[string]HostSpec{
		"no host":      {Tokens: allKinds},
		"unknown kind": {Host: "h", Tokens: []TokenDef{{Kind: "nope"}}},
		"relative":     {Host: "h", Tokens: []TokenDef{{Kind: "db_cred", At: "etc/x"}}},
		"traversal":    {Host: "h", Tokens: []TokenDef{{Kind: "db_cred", At: "/var/../etc/x"}}},
		"newline":      {Host: "h", Tokens: []TokenDef{{Kind: "db_cred", At: "/x\ny"}}},
	} {
		if _, err := g.ForHost(s); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// ---- watcher ----

type fakeWatcher struct {
	ch      chan ReadEvent
	watched []string
	once    sync.Once
}

func (f *fakeWatcher) Watch(p string) error     { f.watched = append(f.watched, p); return nil }
func (f *fakeWatcher) Events() <-chan ReadEvent { return f.ch }
func (f *fakeWatcher) Close() error             { f.once.Do(func() { close(f.ch) }); return nil }

func TestWatchModuleAttributes(t *testing.T) {
	reg := NewRegistry()
	p, _ := NewGenerator(reg).ForHost(HostSpec{Host: "rocky-ecom", HoneyFiles: []string{"/root/passwords.txt"}})
	w := &fakeWatcher{ch: make(chan ReadEvent, 4)}
	m := &WatchModule{W: w, Paths: []string{"/root/passwords.txt"}, Reg: reg, Host: "rocky-ecom", IgnorePID: 1}
	var mu sync.Mutex
	var got []event.Event
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- m.Start(ctx, func(e event.Event) error { mu.Lock(); got = append(got, e); mu.Unlock(); return nil })
	}()
	w.ch <- ReadEvent{Path: "/root/passwords.txt", PID: 1, Exe: "/agent"} // own pid: ignored
	w.ch <- ReadEvent{Path: "/root/passwords.txt", PID: 99, Exe: "/usr/bin/cat"}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("%d events", len(got))
	}
	e := got[0]
	if e.Kind != KindHoneyRead || e.Priority != event.PriorityCritical || e.Fields["honeytoken"] != p.Tokens[0].ID ||
		e.Fields["token_origin"] != "rocky-ecom" || e.Fields["exe"] != "/usr/bin/cat" {
		t.Errorf("event = %+v", e)
	}
	if len(w.watched) != 1 {
		t.Errorf("watched = %v", w.watched)
	}
}

func TestFanotifyRealRead(t *testing.T) {
	w, err := NewFanotify()
	if err != nil {
		t.Skipf("fanotify unavailable (needs Linux and root): %v", err)
	}
	defer w.Close()
	f := filepath.Join(t.TempDir(), "passwords.txt")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.Watch(f); err != nil {
		t.Skipf("fanotify mark failed (filesystem or capability): %v", err)
	}
	if _, err := os.ReadFile(f); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-w.Events():
		if ev.Path != f {
			t.Errorf("path = %q", ev.Path)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no fanotify event for a read")
	}
}
