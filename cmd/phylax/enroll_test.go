package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/controller"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

const enrollRelease = "phylax-linux-amd64"

// writeReleaseDir writes a fake linux release file the pusher uploads.
func writeReleaseDir(t *testing.T, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, enrollRelease), data, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// writeEnrollManifest writes a two-host manifest (h1, h2) and returns its dir.
func writeEnrollManifest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	topology := `team: 1
controller:
  host: ctl
  agent_port: 7443
  ui: 127.0.0.1:8443
segments:
  lan:
    cidr: 127.0.0.0/24
`
	hosts := `hosts:
  ctl: { segment: lan, ip: 127.0.0.10, os: { family: debian, version: "12" }, roles: [controller] }
  h1:  { segment: lan, ip: 127.0.0.1,  os: { family: debian, version: "12" }, default_credentials: host.a }
  h2:  { segment: lan, ip: 127.0.0.2,  os: { family: debian, version: "12" }, default_credentials: host.b }
`
	if err := os.WriteFile(filepath.Join(dir, "topology.yml"), []byte(topology), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(hosts), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.LoadDir(dir, manifest.Options{}); err != nil {
		t.Fatalf("test manifest: %v", err)
	}
	return dir
}

// newEnrollDataDir creates a controller data dir (identity, plan key, store).
func newEnrollDataDir(t *testing.T, manifestPath, releaseDir string) string {
	t.Helper()
	dir := t.TempDir()
	cfg := controller.Config{DataDir: dir, ManifestPath: manifestPath, ReleaseDir: releaseDir}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	c, err := controller.New(context.Background(), cfg, controller.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeEnrollConfig(t *testing.T, dataDir, manifestPath, releaseDir string) string {
	t.Helper()
	cfg := map[string]string{"data_dir": dataDir, "manifest_path": manifestPath,
		"release_dir": releaseDir, "ui_listen": "off", "agent_listen": "127.0.0.1:0"}
	b, _ := json.Marshal(cfg)
	path := filepath.Join(t.TempDir(), "controller.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runEnrollCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	err := runEnroll(context.Background(), args, &out, &errb)
	return out.String(), err
}

func TestEnrollLinePrintsPinnedLine(t *testing.T) {
	releaseDir := writeReleaseDir(t, []byte("fake agent"))
	dataDir := newEnrollDataDir(t, "", releaseDir)
	out, err := runEnrollCmd(t, "-data-dir", dataDir, "-release-dir", releaseDir,
		"line", "-os", "linux", "-ctl", "10.0.0.5:7443", "h1")
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(out)
	if !strings.HasPrefix(line, "curl -sk --pinnedpubkey sha256//") || !strings.HasSuffix(line, "|sh") {
		t.Fatalf("line = %q", line)
	}
	tok := line[strings.Index(line, "/l/")+3 : strings.LastIndex(line, "|sh")]
	if tok == "" {
		t.Fatalf("line has no token: %q", line)
	}
	b, err := os.ReadFile(filepath.Join(dataDir, "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), tok) {
		t.Fatal("tokens.json holds the token in clear")
	}
}

func TestEnrollPushAgainstFakeSSH(t *testing.T) {
	manifestDir := writeEnrollManifest(t)
	releaseDir := writeReleaseDir(t, []byte("fake agent binary"))
	dataDir := newEnrollDataDir(t, manifestDir, releaseDir)
	cfgPath := writeEnrollConfig(t, dataDir, manifestDir, releaseDir)

	fake := &sshFake{user: "root", pass: "pw", hostname: "h1"}
	addr := startSSHFake(t, fake)
	prev := enrollPushAddr
	enrollPushAddr = func(manifest.Host) string { return addr }
	defer func() { enrollPushAddr = prev }()

	vaultPath := filepath.Join(t.TempDir(), "vault.age")
	v, err := vault.Create(vaultPath, []byte("pass"), vault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put("host.a", vault.NewSecretString("root:pw"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put("host.b", vault.NewSecretString("root:bad"), ""); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	t.Setenv("PHYLAX_VAULT_PASSPHRASE", "pass")

	out, err := runEnrollCmd(t, "-config", cfgPath, "-vault", vaultPath,
		"push", "-ctl", "10.0.0.5:7443", "h1", "h2")
	if err == nil {
		t.Fatal("push with one bad password returned nil")
	}
	if !strings.Contains(out, "h1 ok") {
		t.Errorf("stdout lacks h1 ok:\n%s", out)
	}
	if !strings.Contains(out, "h2 FAIL auth_refused:") {
		t.Errorf("stdout lacks h2 FAIL auth_refused:\n%s", out)
	}
	if strings.Contains(out, "root:pw") || strings.Contains(out, "root:bad") {
		t.Errorf("stdout leaked a password:\n%s", out)
	}
	// The randomised-name secret must not be on any command line; the install
	// step reads it from a 0600 file instead.
	var secretHex string
	for _, c := range fake.commands() {
		if strings.Contains(c.cmd, "name.key") && strings.Contains(c.cmd, "base64 -d") {
			secretHex = strings.TrimSpace(string(mustBase64(t, c.stdin)))
		}
	}
	if len(secretHex) != 64 {
		t.Fatalf("no name-secret upload of a 32-byte hex secret: %q", secretHex)
	}
	for _, c := range fake.commands() {
		if strings.Contains(c.cmd, secretHex) {
			t.Errorf("a command line carries the name secret: %q", c.cmd)
		}
		if strings.Contains(c.cmd, "--secret ") {
			t.Errorf("a command line carries --secret: %q", c.cmd)
		}
	}
	var install string
	for _, c := range fake.commands() {
		if strings.Contains(c.cmd, "agent install") {
			install = c.cmd
		}
	}
	if !strings.Contains(install, "--secret-file") {
		t.Errorf("the install command does not use --secret-file: %q", install)
	}
}

func mustBase64(t *testing.T, b []byte) []byte {
	t.Helper()
	out, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(b), "\n", ""))
	if err != nil {
		t.Fatalf("not base64: %v", err)
	}
	return out
}

func TestEnrollStatus(t *testing.T) {
	manifestDir := writeEnrollManifest(t)
	releaseDir := writeReleaseDir(t, []byte("fake agent"))
	dataDir := newEnrollDataDir(t, manifestDir, releaseDir)
	cfgPath := writeEnrollConfig(t, dataDir, manifestDir, releaseDir)

	// Enroll h1 in the store, as a successful hello would.
	cfg, err := controller.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	c, err := controller.New(context.Background(), cfg, controller.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Store().EnrollAgent(context.Background(), "h1", []byte("pubkey")); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := runEnrollCmd(t, "-config", cfgPath, "status")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) == 4 {
			got[f[0]] = f[1:]
		}
	}
	want := map[string][3]string{
		"h1": {"true", "false", "false"},
		"h2": {"false", "false", "false"},
	}
	for host, w := range want {
		f, ok := got[host]
		if !ok || f[0] != w[0] || f[1] != w[1] || f[2] != w[2] {
			t.Errorf("status row %s = %v, want %v\n%s", host, f, w, out)
		}
	}
}
