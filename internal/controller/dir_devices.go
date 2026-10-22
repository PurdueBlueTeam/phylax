package controller

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/creds"
	"github.com/PurdueBlueTeam/phylax/internal/devices"
	"github.com/PurdueBlueTeam/phylax/internal/devices/palo"
	"github.com/PurdueBlueTeam/phylax/internal/devices/palo/xmlapi"
	"github.com/PurdueBlueTeam/phylax/internal/devices/vyos"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

// VaultStore is the slice of *vault.Vault the controller-side execution path
// uses. Values are read at execution time; nothing is cached beyond the
// pooled adapters (which are rebuilt when the vault version changes).
type VaultStore interface {
	Get(name string) (vault.Secret, string, error)
	Put(name string, value vault.Secret, note string) (string, error)
}

// DirectoryOptions configures the controller's device and Splunk directory.
type DirectoryOptions struct {
	// Manifest returns the current manifest (devices, hosts).
	Manifest func() *manifest.Manifest
	Vault    VaultStore
	// DeviceAccount is the device admin account whose password is in the vault
	// at creds.VaultKey(device, account) (default "phylax").
	DeviceAccount string
	// SplunkAccount is the Splunk management account (default "admin"); its
	// password is at creds.VaultKey(host, account).
	SplunkAccount string
	// TunePalo / TuneVyOS adjust an adapter config after the defaults and the
	// credentials are filled in (transport, timeouts; tests point them at fakes).
	TunePalo func(device string, cfg *palo.Config)
	TuneVyOS func(device string, cfg *vyos.Config)
	// SplunkBase overrides https://<host address>:8089.
	SplunkBase func(host string) string
	// SplunkHTTP overrides the HTTP client used for splunkd.
	SplunkHTTP *http.Client
	// Pins maps a device or Splunk host name to the hex SHA-256 of its TLS leaf
	// certificate (or SSH host key blob). Without a pin the first key seen is
	// remembered for the life of the process (trust on first use).
	Pins map[string]string
	// Acked reports whether the Network role acknowledged console access for
	// the plan node in ctx's tag (wired by EnableDeviceExec).
	Acked func(ctx context.Context, planID, node string) bool
}

type paloEnt struct {
	mu  sync.Mutex
	ver string
	ad  *palo.Adapter
}
type vyosEnt struct {
	mu  sync.Mutex
	ver string
	ad  *vyos.Adapter
}

// Directory implements actions.DeviceDirectory and actions.SplunkDirectory for
// the controller. Credentials are resolved from the vault when an adapter or
// client is needed; they never appear in plans, the store or logs (errors
// are passed through Redact).
type Directory struct {
	o DirectoryOptions

	mu      sync.Mutex
	palos   map[string]*paloEnt
	vyoses  map[string]*vyosEnt
	clients map[string]*http.Client
	locks   map[string]chan struct{}
	seen    map[string]string // pin trust-on-first-use
	secrets map[string]vault.Secret
	sphttp  *http.Client
}

var (
	_ actions.DeviceDirectory = (*Directory)(nil)
	_ actions.SplunkDirectory = (*Directory)(nil)
)

// NewDirectory builds the directory.
func NewDirectory(o DirectoryOptions) (*Directory, error) {
	if o.Manifest == nil {
		return nil, errors.New("controller: device directory needs a manifest")
	}
	if o.Vault == nil {
		return nil, errors.New("controller: device directory needs a vault")
	}
	if o.DeviceAccount == "" {
		o.DeviceAccount = "phylax"
	}
	if o.SplunkAccount == "" {
		o.SplunkAccount = "admin"
	}
	return &Directory{o: o, palos: map[string]*paloEnt{}, vyoses: map[string]*vyosEnt{}, clients: map[string]*http.Client{},
		locks: map[string]chan struct{}{}, seen: map[string]string{}, secrets: map[string]vault.Secret{}}, nil
}

func (d *Directory) track(s vault.Secret) {
	if s.IsZero() {
		return
	}
	d.mu.Lock()
	d.secrets[s.Reveal()] = s
	d.mu.Unlock()
}

// Redact removes every credential the directory has resolved from s (also in
// URL-encoded form). Error text from adapters goes through it before it can
// reach a plan result, the store or a log.
func (d *Directory) Redact(s string) string {
	d.mu.Lock()
	all := make([]vault.Secret, 0, 2*len(d.secrets))
	for v, sec := range d.secrets {
		all = append(all, sec)
		if q := url.QueryEscape(v); q != v {
			all = append(all, vault.NewSecretString(q))
		}
	}
	d.mu.Unlock()
	return vault.RedactString(s, all...)
}

// Lock serialises work on one device (or Splunk host): the returned func
// releases it. It gives up when ctx ends.
func (d *Directory) Lock(ctx context.Context, name string) (func(), error) {
	d.mu.Lock()
	ch := d.locks[name]
	if ch == nil {
		ch = make(chan struct{}, 1)
		d.locks[name] = ch
	}
	d.mu.Unlock()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for the %s lock: %w", name, ctx.Err())
	}
}

// Drop forgets the pooled adapter of a device (after a credential rotation).
func (d *Directory) Drop(device string) {
	d.mu.Lock()
	delete(d.palos, device)
	delete(d.vyoses, device)
	d.mu.Unlock()
}

func (d *Directory) device(name, vendor string) (manifest.Device, error) {
	m := d.o.Manifest()
	if m == nil {
		return manifest.Device{}, errors.New("no manifest loaded")
	}
	dev, ok := m.Devices[name]
	if !ok {
		return dev, fmt.Errorf("%q is not a device in the manifest", name)
	}
	if dev.Vendor != vendor {
		return dev, fmt.Errorf("%q is a %s device, not %s", name, dev.Vendor, vendor)
	}
	return dev, nil
}

func (d *Directory) secret(host, account string) (vault.Secret, string, error) {
	s, ver, err := d.o.Vault.Get(creds.VaultKey(host, account))
	if err != nil {
		return s, ver, fmt.Errorf("credential for %s/%s: %w", host, account, err)
	}
	d.track(s)
	return s, ver, nil
}

// pin returns the check for a presented key fingerprint.
func (d *Directory) pin(name string, fp string) error {
	want := d.o.Pins[name]
	d.mu.Lock()
	defer d.mu.Unlock()
	if want == "" {
		want = d.seen[name]
	}
	if want == "" {
		d.seen[name] = fp
		return nil
	}
	if !strings.EqualFold(want, fp) {
		return fmt.Errorf("%s: presented key %s does not match the pinned %s", name, fp, want)
	}
	return nil
}

// httpFor returns the pooled HTTPS client of a device or host (pinned or TOFU).
func (d *Directory) httpFor(name string) *http.Client {
	d.mu.Lock()
	defer d.mu.Unlock()
	if c := d.clients[name]; c != nil {
		return c
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, // identity is the pin below
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 {
					return errors.New("no certificate")
				}
				h := sha256.Sum256(raw[0])
				return d.pin(name, hex.EncodeToString(h[:]))
			}},
		MaxIdleConnsPerHost: 4, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 15 * time.Second,
		ResponseHeaderTimeout: 6 * time.Minute,
	}
	c := &http.Client{Transport: tr, Timeout: 10 * time.Minute}
	d.clients[name] = c
	return c
}

func baseURL(h string) string {
	if strings.Contains(h, "://") {
		return h
	}
	return "https://" + h
}

// Palo returns the pooled adapter of a PAN-OS device, rebuilt when the vault
// credential changed.
func (d *Directory) Palo(ctx context.Context, device string) (*palo.Adapter, error) {
	dev, err := d.device(device, "panos")
	if err != nil {
		return nil, err
	}
	pw, ver, err := d.secret(device, d.o.DeviceAccount)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	e := d.palos[device]
	if e == nil {
		e = &paloEnt{}
		d.palos[device] = e
	}
	d.mu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ad != nil && e.ver == ver {
		return e.ad, nil
	}
	cfg := palo.Config{Device: device, Admin: d.o.DeviceAccount,
		Transport: devices.Transport{HTTP: d.httpFor(device), Host: dev.Mgmt}}
	if d.o.TunePalo != nil {
		d.o.TunePalo(device, &cfg)
	}
	kc := &xmlapi.Client{BaseURL: baseURL(cfg.Transport.Host), HTTP: cfg.Transport.HTTP}
	key, err := kc.Keygen(ctx, cfg.Admin, pw.Reveal())
	if err != nil {
		return nil, fmt.Errorf("palo %s: API key: %s", device, d.Redact(err.Error()))
	}
	d.track(vault.NewSecretString(key))
	cfg.Key = key
	ad, err := palo.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("palo %s: %s", device, d.Redact(err.Error()))
	}
	e.ad, e.ver = ad, ver
	return ad, nil
}

// VyOS returns the pooled adapter of a VyOS router.
func (d *Directory) VyOS(ctx context.Context, device string) (*vyos.Adapter, error) {
	dev, err := d.device(device, "vyos")
	if err != nil {
		return nil, err
	}
	pw, ver, err := d.secret(device, d.o.DeviceAccount)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	e := d.vyoses[device]
	if e == nil {
		e = &vyosEnt{}
		d.vyoses[device] = e
	}
	d.mu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ad != nil && e.ver == ver {
		return e.ad, nil
	}
	addr := dev.Mgmt
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), "22")
	}
	cfg := vyos.Config{Device: device, Transport: devices.Transport{HTTP: d.httpFor(device), Host: dev.Mgmt},
		SSH: vyos.SSHConfig{Addr: addr, User: d.o.DeviceAccount, Auth: []ssh.AuthMethod{ssh.Password(pw.Reveal())},
			HostKey: func(_ string, _ net.Addr, k ssh.PublicKey) error {
				h := sha256.Sum256(k.Marshal())
				return d.pin(device, hex.EncodeToString(h[:]))
			}}}
	// An optional HTTP API key, only when the operator stored one.
	if k, _, err := d.o.Vault.Get(creds.VaultKey(device, "api")); err == nil {
		d.track(k)
		cfg.HTTPBase, cfg.APIKey = baseURL(dev.Mgmt), k.Reveal()
	}
	if d.o.TuneVyOS != nil {
		d.o.TuneVyOS(device, &cfg)
	}
	ad, err := vyos.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("vyos %s: %s", device, d.Redact(err.Error()))
	}
	e.ad, e.ver = ad, ver
	return ad, nil
}

// PaloIntent derives the policy intent of a PAN-OS device from the manifest.
func (d *Directory) PaloIntent(_ context.Context, device string) (*render.PaloIntent, error) {
	m := d.o.Manifest()
	if m == nil {
		return nil, errors.New("no manifest loaded")
	}
	return render.PaloIntents(m, device)
}

// VyOSIntent derives the policy intent of a VyOS router from the manifest.
func (d *Directory) VyOSIntent(_ context.Context, device string) (*render.VyOSIntent, error) {
	m := d.o.Manifest()
	if m == nil {
		return nil, errors.New("no manifest loaded")
	}
	return render.VyOSIntents(m, device)
}

// ConsoleAck reports whether the Network role acknowledged console access for
// the plan node being executed (identified by the action tag in ctx). An ack
// belongs to one plan node, never to a device in general.
func (d *Directory) ConsoleAck(ctx context.Context, _ string) bool {
	t := actions.TagFrom(ctx)
	if t.Plan == "" || t.Node == "" || d.o.Acked == nil {
		return false
	}
	return d.o.Acked(ctx, t.Plan, t.Node)
}

// Client returns the splunkd management client of a host, authenticated with
// the vault credential (resolved now).
func (d *Directory) Client(_ context.Context, host string) (actions.SplunkAPI, error) {
	pw, _, err := d.secret(host, d.o.SplunkAccount)
	if err != nil {
		return nil, err
	}
	base := ""
	if d.o.SplunkBase != nil {
		base = d.o.SplunkBase(host)
	}
	if base == "" {
		addr := host
		if m := d.o.Manifest(); m != nil {
			if a, ok := m.HostAddr(host); ok {
				addr = a.String()
			}
		}
		base = "https://" + net.JoinHostPort(addr, "8089")
	}
	hc := d.o.SplunkHTTP
	if hc == nil {
		hc = d.httpFor("splunk:" + host)
	}
	return &actions.HTTPSplunk{Base: base, User: d.o.SplunkAccount, Password: pw.Reveal(), HTTP: hc}, nil
}
