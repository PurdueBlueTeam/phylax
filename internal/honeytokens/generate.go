package honeytokens

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"path"
	"slices"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/PurdueBlueTeam/phylax/pools"
)

// ActionSpec is one step the planner can emit. This package only describes
// steps; nothing here touches the host.
type ActionSpec struct {
	Action string         `json:"action"` // an internal/actions name, or ad.honey_account (DC-side)
	Host   string         `json:"host"`
	Params map[string]any `json:"params"`
	Risk   string         `json:"risk"`
	// SecretParams names params that must travel in the step's secrets blob
	// and be redacted from diffs.
	SecretParams []string `json:"secret_params,omitempty"`
	// OnlyIfAbsent: the planner must skip the step if the target exists
	// (file.write replaces; never clobber a real history or credentials file).
	OnlyIfAbsent bool   `json:"only_if_absent,omitempty"`
	Token        string `json:"token"` // token ID the step plants
	Note         string `json:"note,omitempty"`
}

// Watch is a honey file to watch for reads.
type Watch struct {
	Host   string `json:"host"`
	Path   string `json:"path"`
	Method string `json:"method"` // fanotify (Linux) | sacl (Windows, 4663)
	Token  string `json:"token"`
}

// ADAccount is a honey Active Directory account definition.
type ADAccount struct {
	Token       string `json:"token"`
	Name        string `json:"name"`
	Kind        Kind   `json:"kind"`
	SPN         string `json:"spn,omitempty"`
	OU          string `json:"ou"`
	Description string `json:"description"`
	// DontRequirePreauth makes the account AS-REP roastable.
	DontRequirePreauth bool `json:"dont_require_preauth,omitempty"`
	// Password is a long, random, uncrackable-in-practice-but-plausible secret:
	// the account has no rights and never logs on legitimately.
	Password string `json:"-"`
}

// HostPlan is the output for one host.
type HostPlan struct {
	Host      string       `json:"host"`
	Tokens    []Token      `json:"tokens"`
	Actions   []ActionSpec `json:"actions"`
	Watches   []Watch      `json:"watches,omitempty"`
	ADAccount []ADAccount  `json:"ad_accounts,omitempty"`
}

// HostSpec is the manifest-derived input for one host (decoys.yml entry plus
// the host's OS family and, for a DC, the domain).
type HostSpec struct {
	Host    string
	Windows bool
	Domain  string // DNS domain, e.g. corp.example (needed for AD tokens)
	// Honeytokens and HoneyFiles come from decoys.yml.
	Tokens     []TokenDef
	HoneyFiles []string
}

// TokenDef mirrors manifest.Honeytoken.
type TokenDef struct {
	Kind string
	At   string
}

// Generator creates unique tokens. Every value is drawn from Rand (crypto/rand
// by default) and checked against the registry, so two hosts never share a
// secret, account, fingerprint, SPN or path.
type Generator struct {
	Rand io.Reader
	Reg  *Registry

	mu  sync.Mutex
	cur *HostPlan // plan being built: its tokens are not in Reg yet
}

// NewGenerator returns a generator over reg using crypto/rand.
func NewGenerator(reg *Registry) *Generator { return &Generator{Rand: rand.Reader, Reg: reg} }

func (g *Generator) rnd() io.Reader {
	if g.Rand == nil {
		return rand.Reader
	}
	return g.Rand
}

func (g *Generator) intn(n int) int {
	v, err := rand.Int(g.rnd(), big.NewInt(int64(n)))
	if err != nil {
		panic("honeytokens: entropy source failed: " + err.Error())
	}
	return int(v.Int64())
}

func (g *Generator) pick(pool []string) string { return pool[g.intn(len(pool))] }

func (g *Generator) bytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(g.rnd(), b); err != nil {
		panic("honeytokens: entropy source failed: " + err.Error())
	}
	return b
}

func (g *Generator) id() string { return "ht-" + hex.EncodeToString(g.bytes(6)) }

var (
	pwWords1 = []string{"Summer", "Winter", "Spring", "Autumn", "Falcon", "Tiger", "Orange", "Silver", "Dragon", "Eagle", "Harbor", "Mustang", "Rocket", "Thunder", "Maple", "Cobalt", "Granite", "Pioneer", "Boiler", "Anchor", "Meadow", "Copper", "Ranger", "Bishop", "Window", "Castle", "Jaguar", "Pepper", "Marble", "Nimbus", "Orchid", "Walnut"}
	pwWords2 = []string{"Backup", "Admin", "Server", "Portal", "Secure", "Access", "Office", "Campus", "Reports", "Mail", "Cloud", "Vault", "Gate", "Share", "Sales", "Ops", "Data", "Net", "Web", "Staff", "Login", "Root", "Edge", "Core", "Link", "Desk", "Lab", "Hub", "Node", "Site", "Team", "Zone"}
	pwSyms   = []string{"!", "#", "$", "@", "%", "&", "*", "?"}
)

// password makes a plausible human-pattern password; uniqueness is enforced
// by the registry check around it.
func (g *Generator) password() string {
	return fmt.Sprintf("%s%s%02d%s%02d", g.pick(pwWords1), g.pick(pwWords2), g.intn(100), g.pick(pwSyms), g.intn(100))
}

func (g *Generator) username(poolFile string) string {
	return fmt.Sprintf("%s%03d", g.pick(pools.Lines(poolFile)), g.intn(1000))
}

// AWSAccessKeyID returns a key id in AWS format (AKIA + 16 base32 chars).
// It is not a real credential; its use is only ever seen in our own egress.
func (g *Generator) awsKeyID() string {
	return "AKIA" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(g.bytes(10))
}

func (g *Generator) awsSecret() string {
	const al = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := make([]byte, 40)
	for i := range b {
		b[i] = al[g.intn(len(al))]
	}
	return string(b)
}

// sshKey returns a fake ed25519 private key (OpenSSH PEM) and its fingerprint.
func (g *Generator) sshKey(comment string) (pemStr, fp string, err error) {
	pub, priv, err := ed25519.GenerateKey(g.rnd())
	if err != nil {
		return "", "", err
	}
	blk, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return "", "", err
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(blk)), ssh.FingerprintSHA256(sp), nil
}

// unique fills in a token via mk until the registry has no collision.
func (g *Generator) unique(mk func() Token) (Token, error) {
	for range 50 {
		t := mk()
		if (g.Reg == nil || !g.Reg.Taken(t)) && !g.collidesWithPlan(t) {
			return t, nil
		}
	}
	return Token{}, fmt.Errorf("honeytokens: could not generate a unique token")
}

// collidesWithPlan checks t against the tokens already generated for the host
// being planned.
func (g *Generator) collidesWithPlan(t Token) bool {
	if g.cur == nil {
		return false
	}
	r := NewRegistry()
	for _, o := range g.cur.Tokens {
		_ = r.Add(o)
	}
	return r.Taken(t)
}

// ForHost builds the plan for one host and registers its tokens. On error
// nothing is registered.
func (g *Generator) ForHost(spec HostSpec) (*HostPlan, error) {
	if spec.Host == "" {
		return nil, fmt.Errorf("honeytokens: host is required")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	p := &HostPlan{Host: spec.Host}
	g.cur = p
	defer func() { g.cur = nil }()
	for _, d := range spec.Tokens {
		if err := g.one(spec, p, Kind(d.Kind), d.At); err != nil {
			return nil, fmt.Errorf("host %s token %s: %w", spec.Host, d.Kind, err)
		}
	}
	for _, f := range spec.HoneyFiles {
		if err := g.honeyFile(spec, p, f); err != nil {
			return nil, fmt.Errorf("host %s honey file %s: %w", spec.Host, f, err)
		}
	}
	if g.Reg != nil {
		for _, t := range p.Tokens {
			if err := g.Reg.Add(t); err != nil {
				return nil, err
			}
		}
	}
	return p, nil
}

func (g *Generator) one(spec HostSpec, p *HostPlan, k Kind, at string) error {
	if !k.Valid() {
		return fmt.Errorf("unknown honeytoken kind %q", k)
	}
	if k.IsAD() {
		return g.adAccount(spec, p, k, at)
	}
	if at == "" {
		at = defaultPath(spec.Windows, k)
	}
	if at == "" || !validPath(spec.Windows, at) {
		return fmt.Errorf("unusable path %q", at)
	}
	switch k {
	case KindSSHKey:
		if spec.Windows {
			return fmt.Errorf("ssh_key is planted on Linux hosts")
		}
		return g.addSSHKey(spec, p, at)
	case KindDBCred:
		return g.addDBCred(spec, p, at)
	case KindShellHistory:
		return g.addHistory(spec, p, at)
	case KindPasswordsFile:
		return g.addPasswords(spec, p, at, false)
	case KindBrowserCred:
		return g.addPasswords(spec, p, at, true)
	case KindAWSKey:
		return g.addAWS(spec, p, at)
	case KindHoneyFile:
		return g.honeyFile(spec, p, at)
	}
	return fmt.Errorf("unhandled kind %q", k)
}

func defaultPath(win bool, k Kind) string {
	if win {
		switch k {
		case KindDBCred:
			return `C:\inetpub\wwwroot\web.config.bak`
		case KindPasswordsFile:
			return `C:\Users\Administrator\Documents\passwords.txt`
		case KindBrowserCred:
			return `C:\Users\Administrator\Downloads\chrome_passwords.csv`
		case KindAWSKey:
			return `C:\Users\Administrator\.aws\credentials`
		case KindShellHistory:
			return `C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
		}
		return ""
	}
	switch k {
	case KindSSHKey:
		return "/root/.ssh/id_rsa_backup"
	case KindDBCred:
		return "/var/www/html/.env.bak"
	case KindPasswordsFile:
		return "/root/passwords.txt"
	case KindBrowserCred:
		return "/root/Downloads/chrome_passwords.csv"
	case KindAWSKey:
		return "/root/.aws/credentials"
	case KindShellHistory:
		return "/root/.bash_history"
	}
	return ""
}

func validPath(win bool, p string) bool {
	if strings.ContainsAny(p, "\x00\n") || len(p) > 260 || strings.Contains(p, "..") {
		return false
	}
	if win {
		return len(p) > 3 && p[1] == ':'
	}
	return strings.HasPrefix(p, "/") && path.Clean(p) == p
}

func (g *Generator) watchFor(spec HostSpec, p *HostPlan, t Token) {
	m := "fanotify"
	if spec.Windows {
		m = "sacl"
	}
	p.Watches = append(p.Watches, Watch{Host: spec.Host, Path: t.Path, Method: m, Token: t.ID})
}

// plantFile appends the token and the file.write step for it.
func (g *Generator) plantFile(spec HostSpec, p *HostPlan, t Token, content string, mode string, onlyIfAbsent bool) {
	if !slices.ContainsFunc(p.Tokens, func(o Token) bool { return o.ID == t.ID }) {
		p.Tokens = append(p.Tokens, t)
	}
	p.Actions = append(p.Actions, ActionSpec{Action: "file.write", Host: spec.Host, Risk: "service", Token: t.ID,
		Params:       map[string]any{"path": t.Path, "content": content, "mode": mode},
		SecretParams: []string{"content"}, OnlyIfAbsent: onlyIfAbsent})
	g.watchFor(spec, p, t)
}

func (g *Generator) addSSHKey(spec HostSpec, p *HostPlan, at string) error {
	t, err := g.unique(func() Token {
		return Token{ID: g.id(), Host: spec.Host, Kind: KindSSHKey, Path: at}
	})
	if err != nil {
		return err
	}
	pemStr, fp, err := g.sshKey("backup@" + spec.Host)
	if err != nil {
		return err
	}
	// ed25519 keys have unique fingerprints with overwhelming probability;
	// the registry still refuses a collision at Add.
	t.Fingerprint = fp
	g.plantFile(spec, p, t, pemStr, "0600", true)
	return nil
}

func (g *Generator) addDBCred(spec HostSpec, p *HostPlan, at string) error {
	t, err := g.unique(func() Token {
		return Token{ID: g.id(), Host: spec.Host, Kind: KindDBCred, Path: at, User: g.username("svc_names.txt"), Secret: g.password()}
	})
	if err != nil {
		return err
	}
	var body string
	switch {
	case strings.HasSuffix(strings.ToLower(at), "web.config.bak") || strings.HasSuffix(strings.ToLower(at), ".config"):
		body = fmt.Sprintf("<configuration>\n  <connectionStrings>\n    <add name=\"Main\" connectionString=\"Server=127.0.0.1;Database=app;User Id=%s;Password=%s;\" />\n  </connectionStrings>\n</configuration>\n", t.User, t.Secret)
	default:
		body = fmt.Sprintf("APP_ENV=production\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=app\nDB_USERNAME=%s\nDB_PASSWORD=%s\n", t.User, t.Secret)
	}
	g.plantFile(spec, p, t, body, "0640", true)
	return nil
}

func (g *Generator) addHistory(spec HostSpec, p *HostPlan, at string) error {
	t, err := g.unique(func() Token {
		return Token{ID: g.id(), Host: spec.Host, Kind: KindShellHistory, Path: at, Secret: g.password()}
	})
	if err != nil {
		return err
	}
	var body string
	if spec.Windows {
		body = fmt.Sprintf("Get-Service\r\n$cred = ConvertTo-SecureString '%s' -AsPlainText -Force\r\nEnter-PSSession -ComputerName backup01 -Credential (New-Object PSCredential('administrator',$cred))\r\n", t.Secret)
	} else {
		body = fmt.Sprintf("ls -la /opt/backup\nmysql -u backup -p'%s' -h 127.0.0.1 app\ncd /var/www/html\nsystemctl status nginx\n", t.Secret)
	}
	// A real history file must not be clobbered, hence OnlyIfAbsent.
	g.plantFile(spec, p, t, body, "0600", true)
	return nil
}

func (g *Generator) addPasswords(spec HostSpec, p *HostPlan, at string, browser bool) error {
	var rows [][3]string // label, user, secret
	first := true
	k := KindPasswordsFile
	if browser {
		k = KindBrowserCred
	}
	var toks []Token
	for _, label := range []string{"vpn", "router", "intranet"} {
		lab := label
		isFirst := first
		t, err := g.unique(func() Token {
			tk := Token{ID: g.id(), Host: spec.Host, Kind: k, User: g.username("users.txt"), Secret: g.password()}
			if isFirst {
				tk.Path = at
			}
			return tk
		})
		if err != nil {
			return err
		}
		first = false
		p.Tokens = append(p.Tokens, t) // visible to the uniqueness check of the next one
		toks = append(toks, t)
		rows = append(rows, [3]string{lab, t.User, t.Secret})
	}
	var b strings.Builder
	if browser {
		b.WriteString("name,url,username,password,note\n")
		for _, r := range rows {
			fmt.Fprintf(&b, "%s,https://%s.corp.local/login,%s,%s,\n", r[0], r[0], r[1], r[2])
		}
	} else {
		b.WriteString("# do not share\n")
		for _, r := range rows {
			fmt.Fprintf(&b, "%s: %s / %s\n", r[0], r[1], r[2])
		}
	}
	// plant the file with the first token; register the rest.
	g.plantFile(spec, p, toks[0], b.String(), "0600", true)
	return nil
}

func (g *Generator) addAWS(spec HostSpec, p *HostPlan, at string) error {
	t, err := g.unique(func() Token {
		return Token{ID: g.id(), Host: spec.Host, Kind: KindAWSKey, Path: at, User: g.awsKeyID(), Secret: g.awsSecret()}
	})
	if err != nil {
		return err
	}
	body := fmt.Sprintf("[default]\naws_access_key_id = %s\naws_secret_access_key = %s\nregion = us-east-1\n", t.User, t.Secret)
	g.plantFile(spec, p, t, body, "0600", true)
	return nil
}

func (g *Generator) honeyFile(spec HostSpec, p *HostPlan, f string) error {
	if !strings.ContainsAny(f, `/\`) { // bare names (from decoys.yml) go to a default directory
		if spec.Windows {
			f = `C:\Users\Administrator\Documents\` + f
		} else {
			f = "/root/" + f
		}
	}
	if !validPath(spec.Windows, f) {
		return fmt.Errorf("unusable path %q", f)
	}
	if strings.HasPrefix(strings.ToLower(path.Base(strings.ReplaceAll(f, `\`, "/"))), "id_rsa") && !spec.Windows {
		return g.addSSHKey(spec, p, f)
	}
	t, err := g.unique(func() Token { return Token{ID: g.id(), Host: spec.Host, Kind: KindHoneyFile, Path: f} })
	if err != nil {
		return err
	}
	base := strings.ToLower(f)
	var body string
	switch {
	case strings.HasSuffix(base, ".sql"):
		body = fmt.Sprintf("-- MySQL dump 10.13  Distrib 8.0.36\n-- Host: localhost    Database: app\n-- honey:%s\nDROP TABLE IF EXISTS `users`;\n", t.ID)
	default:
		body = fmt.Sprintf("Internal use only (%s)\n", t.ID)
	}
	g.plantFile(spec, p, t, body, "0600", true)
	return nil
}

func (g *Generator) adAccount(spec HostSpec, p *HostPlan, k Kind, ou string) error {
	if spec.Domain == "" {
		return fmt.Errorf("%s needs the domain (host %s is not a DC in the manifest)", k, spec.Host)
	}
	if ou == "" {
		ou = "OU=Decoys," + dnOf(spec.Domain)
	}
	pool, desc := "svc_names.txt", "Service account"
	switch k {
	case KindADAdmin:
		pool, desc = "admin_names.txt", "Administrator account (legacy)"
	case KindADASREP:
		pool, desc = "users.txt", "Contractor account"
	}
	t, err := g.unique(func() Token {
		tk := Token{ID: g.id(), Host: spec.Host, Kind: k, Path: ou, User: g.username(pool), Secret: g.password() + g.password()}
		if k == KindADSPN {
			tk.SPN = fmt.Sprintf("MSSQLSvc/%s%02d.%s:1433", g.pick([]string{"sql", "db", "bkp", "rpt"}), g.intn(100), spec.Domain)
		}
		return tk
	})
	if err != nil {
		return err
	}
	acc := ADAccount{Token: t.ID, Name: t.User, Kind: k, SPN: t.SPN, OU: ou, Description: desc,
		DontRequirePreauth: k == KindADASREP, Password: t.Secret}
	p.Tokens = append(p.Tokens, t)
	p.ADAccount = append(p.ADAccount, acc)
	params := map[string]any{"name": acc.Name, "ou": ou, "description": desc, "password": t.Secret,
		"enabled": true, "logon_rights": "none"}
	if acc.SPN != "" {
		params["spn"] = acc.SPN
	}
	if acc.DontRequirePreauth {
		params["dont_require_preauth"] = true
	}
	p.Actions = append(p.Actions, ActionSpec{Action: "ad.honey_account", Host: spec.Host, Risk: "service", Token: t.ID,
		Params: params, SecretParams: []string{"password"},
		Note: "DC-side action; the account gets no group memberships. Audit 4768/4769/4771/4776 must be on."})
	return nil
}

func dnOf(domain string) string {
	parts := strings.Split(domain, ".")
	for i, p := range parts {
		parts[i] = "DC=" + p
	}
	return strings.Join(parts, ",")
}
