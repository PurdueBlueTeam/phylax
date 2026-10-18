// Package agent implements `phylax agent`: the host-side link. It dials
// the controller (or its relay) over pinned TLS, enrolls with its
// one-time token, resends spooled events from the ack watermark, keeps a
// 5 s heartbeat, and reconnects with jittered backoff.
package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/action"
	agentfim "github.com/PurdueBlueTeam/phylax/internal/agent/fimmod"
	"github.com/PurdueBlueTeam/phylax/internal/checks"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/spool"
)

// Bundle is the bootstrap config the console one-liner installs.
type Bundle struct {
	Controller string   `json:"controller"` // addr:port
	Pin        link.Pin `json:"pin"`
	Host       string   `json:"host"`
	Token      string   `json:"token"`
	Roles      []string `json:"roles"`
	Services   []Service  `json:"services,omitempty"`
	FimWatches []FimWatch `json:"fim_watches,omitempty"`
	LogWatches []LogWatch `json:"log_watches,omitempty"`
	PlanKey    string   `json:"plan_key,omitempty"` // base64 ed25519 public key

	// Segment names the segment this host sits in (the check_runner's
	// vantage is "segment:<segment>").
	Segment string `json:"segment,omitempty"`
	// Capture configures the capture role (docs: agent roles).
	Capture *CaptureCfg `json:"capture,omitempty"`
	// Checks is the active-check list the check_runner role runs from
	// inside its segment (docs: Active checks — two vantage points).
	Checks []checks.Check `json:"checks,omitempty"`
}

// CaptureCfg is the capture module's configuration: which interfaces to
// read, the ports captured full-length (scored, decoy, sinkhole) and the
// declared service ports mapped to their protocol for the phase-1 parsers.
type CaptureCfg struct {
	Ifaces    []string       `json:"ifaces,omitempty"`
	Full      []int          `json:"full,omitempty"`
	PortProto map[int]string `json:"port_proto,omitempty"`
	RingBytes int64          `json:"ring_bytes,omitempty"` // 0 = default 64 MiB
}

// Agent is one host's link state.
type Agent struct {
	bundle Bundle
	dir    string
	sp     *spool.Store
	key    ed25519.PrivateKey
	cert   *x509.Certificate
	log    *log.Logger
	reg    *action.Registry
	fim    *agentfim.Module

	// locks: resource -> lock name held while a step runs (docs: actions
	// declare the resources they lock).
	locksMu sync.Mutex
	locks   map[string]string

	version string
	// module status reported in heartbeats; collectors register here.
	moduleMu   chan<- string
	modules    map[string]string
	drops      uint64
	safeMode   bool
	enrolled   bool // set after the first successful ack
	stopped    chan struct{}
}

const (
	heartbeatPeriod = 5 * time.Second
	batchSize       = 200
	maxBackoff      = 30 * time.Second
)

// New opens (or creates) the agent state under dir.
func New(dir string, bundle Bundle, logf *log.Logger) (*Agent, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if logf == nil {
		logf = log.New(os.Stderr, "agent: ", log.LstdFlags)
	}
	sp, err := spool.Open(filepath.Join(dir, "spool"), 200<<20) // 200 MB cap
	if err != nil {
		return nil, err
	}
	a := &Agent{
		bundle:  bundle,
		dir:     dir,
		sp:      sp,
		log:     logf,
		version: "0.1.0",
		modules: map[string]string{"link": "ok"},
		locks:   map[string]string{},
		stopped: make(chan struct{}),
	}
	if b, err := os.ReadFile(filepath.Join(dir, "safe_mode")); err == nil &&
		strings.TrimSpace(string(b)) == "1" {
		a.safeMode = true
		logf.Printf("safe mode ON (flag file)")
	}
	if err := a.loadOrCreateIdentity(); err != nil {
		sp.Close()
		return nil, err
	}
	return a, nil
}

func (a *Agent) loadOrCreateIdentity() error {
	keyPath := filepath.Join(a.dir, a.bundle.Host+"-identity", "key")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	if b, err := os.ReadFile(keyPath); err == nil && len(b) == ed25519.PrivateKeySize {
		a.key = ed25519.PrivateKey(b)
		cert, err := link.SelfSignedCert(a.key, a.bundle.Host)
		if err != nil {
			return err
		}
		a.cert = cert
		return nil
	}
	_, priv, err := link.NewKeyPair()
	if err != nil {
		return err
	}
	cert, err := link.SelfSignedCert(priv, a.bundle.Host)
	if err != nil {
		return err
	}
	a.key, a.cert = priv, cert
	return os.WriteFile(keyPath, []byte(priv), 0o600)
}

// Spool exposes the local spool (collectors append to it).
func (a *Agent) Spool() *spool.Store { return a.sp }

// SetModule records a module's status for heartbeats.
func (a *Agent) SetModule(name, status string) {
	a.modules[name] = status
}

// LockTry takes a named resource lock for owner; false when held by
// someone else (docs: plans and tier-0 responses share locks).
func (a *Agent) LockTry(name, owner string) bool {
	a.locksMu.Lock()
	defer a.locksMu.Unlock()
	if other, busy := a.locks[name]; busy && other != owner {
		return false
	}
	a.locks[name] = owner
	return true
}

// LockRelease returns a lock to the pool.
func (a *Agent) LockRelease(name, owner string) {
	a.locksMu.Lock()
	defer a.locksMu.Unlock()
	if a.locks[name] == owner {
		delete(a.locks, name)
	}
}

// LockOwner reports who holds a lock, or "" when free.
func (a *Agent) LockOwner(name string) string {
	a.locksMu.Lock()
	defer a.locksMu.Unlock()
	return a.locks[name]
}

// StartModule runs fn in a supervised goroutine: a panicking or exiting
// module is restarted on its own and reported, it never takes the agent
// down (docs: Modules). fn returning an error is treated the same.
func (a *Agent) StartModule(name string, fn func(context.Context) error) {
	a.SetModule(name, "starting")
	go func() {
		for {
			done := make(chan struct{})
			go func() {
				defer func() {
					if r := recover(); r != nil {
						a.log.Printf("%s: panic: %v (restarting)", name, r)
					}
					close(done)
				}()
				if err := fn(context.Background()); err != nil {
					a.log.Printf("%s: exited: %v (restarting)", name, err)
				}
			}()
			select {
			case <-done:
				a.SetModule(name, "restarting")
				time.Sleep(500 * time.Millisecond)
				a.SetModule(name, "running")
			case <-a.stopped:
				return
			}
		}
	}()
	a.SetModule(name, "running")
}

// Publish appends an event to the spool. The link sync loop ships it.
func (a *Agent) Publish(evType string, data any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, _, err = a.sp.Append(spool.Event{TS: time.Now().UTC(), Type: evType, Data: b, Class: spool.ClassProtected})
	return err
}

// PublishClass appends an event in the given spool class (log lines,
// churn: sheddable when the spool nears its cap).
func (a *Agent) PublishClass(evType string, data any, class int) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, _, err = a.sp.Append(spool.Event{TS: time.Now().UTC(), Type: evType, Data: b, Class: class})
	return err
}

// Run blocks, reconnecting forever, until ctx is done.
func (a *Agent) Run(ctx context.Context) error {
	// detection and automatic response keep working with the link down
	// (docs: principle 4), so modules start before the first dial.
	if a.bundle.Services != nil || a.bundle.FimWatches != nil || a.bundle.LogWatches != nil {
		a.StartModules(a.bundle.Services, a.bundle.FimWatches, a.bundle.LogWatches)
	}
	a.startCapture(ctx)
	a.startChecks(ctx)
	backoff := time.Second
	for ctx.Err() == nil {
		err := a.runOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			a.log.Printf("link down: %v", err)
		}
		jitter := time.Duration(rand.Int64N(int64(backoff)/2 + 1))
		delay := backoff + jitter
		a.log.Printf("reconnect in %s", delay.Round(time.Millisecond))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
	return nil
}

// runOnce is one connection: dial, hello, ack, sync, heartbeat, until dead.
func (a *Agent) runOnce(ctx context.Context) error {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tlsCfg := link.ClientConfig(a.key, a.cert, a.bundle.Pin, []string{link.ALPNAgent})
	conn, err := tls.DialWithDialer(dialer, "tcp", a.bundle.Controller, tlsCfg)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	lc := link.NewConn(conn, a.bundle.Controller)
	defer lc.Close()

	acked := make(chan uint64, 8)
	lc.On(link.TypAck, func(_ context.Context, _ *link.Conn, m *link.Message) error {
		var ack link.Ack
		if err := link.DecodeJSON(m.Payload, &ack); err != nil {
			return err
		}
		a.sp.Ack(ack.Seq)
		if !a.enrolled {
			a.enrolled = true // controller accepted this identity
		}
		select {
		case acked <- ack.Seq:
		default:
		}
		return nil
	})
	lc.On(link.TypConfig, func(_ context.Context, _ *link.Conn, m *link.Message) error {
		a.log.Printf("config received (epoch/sig: M1 placeholder)")
		return nil
	})
	lc.On(link.TypStep, a.handleStep)
	lc.On(link.TypControl, a.handleControl)
	// M3+: fetch (control plane chunks for file payloads) is deferred; the
	// step's params carry inline content for now.

	// Hello: token on first contact, bare afterwards.
	hello := link.Hello{
		Host:    a.bundle.Host,
		Version: a.version,
		Roles:   a.bundle.Roles,
		LastSeq: a.sp.MaxSeq(),
	}
	if !a.enrolled {
		hello.Token = a.bundle.Token
	}
	if err := a.send(lc, link.TypHello, &hello); err != nil {
		return err
	}
	a.enrolled = true

	// Sync loop: resend from the ack watermark; heartbeat every 5 s.
	hb := time.NewTicker(heartbeatPeriod)
	sync := time.NewTicker(500 * time.Millisecond)
	defer sync.Stop()
	a.sendHeartbeat(lc)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-lc.Done():
			return fmt.Errorf("connection closed")
		case <-hb.C:
			a.sendHeartbeat(lc)
		case <-sync.C:
			if err := a.sync(lc); err != nil {
				return err
			}
		case <-acked:
			if err := a.sync(lc); err != nil {
				return err
			}
		}
	}
}

// sync ships spooled events beyond what we've sent, in batches.
func (a *Agent) sync(lc *link.Conn) error {
	maxSeq := a.sp.MaxSeq()
	sent := a.sp.Acked()
	if maxSeq <= sent {
		return nil
	}
	recs, err := a.sp.Range(sent + 1, sent + batchSize)
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		return nil
	}
	evs := make([]link.Event, 0, len(recs))
	for _, r := range recs {
		evs = append(evs, link.Event{Seq: r.Seq, TS: r.TS, Type: r.Type, Data: r.Data, Hash: r.Hash, Prev: r.Prev})
	}
	return a.send(lc, link.TypEvents, &link.Events{Events: evs})
}

func (a *Agent) sendHeartbeat(lc *link.Conn) {
	mods := make(map[string]string, len(a.modules))
	for k, v := range a.modules {
		mods[k] = v
	}
	hb := link.Heartbeat{
		Seq:        a.sp.MaxSeq(),
		HostClock:  time.Now().UTC().Format(time.RFC3339Nano),
		SpoolDepth: a.sp.Count(),
		Modules:    mods,
		SafeMode:   a.safeMode,
		Drops:      a.drops,
	}
	_ = a.send(lc, link.TypHeartbeat, &hb)
}

func (a *Agent) send(lc *link.Conn, typ byte, msg any) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return lc.Enqueue(link.PrioCore, &link.Message{Type: typ, Payload: b})
}

// Close flushes and closes the spool.
func (a *Agent) Close() error {
	close(a.stopped)
	return a.sp.Close()
}

