package mods

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/capture"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// CaptureFile is the optional per-host capture tuning in the agent state
// directory. The signed AgentConfig decides whether the module runs (role
// "capture") and which ports are scored (the net module's service map); this
// file only holds local knobs and is never needed.
const CaptureFile = "capture.json"

// CaptureSealFile holds the 32-byte (hex) key credential-derived fields are
// sealed with. Without it those fields are dropped.
const CaptureSealFile = "capture.seal"

// OrgNetsFile overrides the shipped Microsoft/cloud network lists.
const OrgNetsFile = "orgnets.json"

type captureFile struct {
	Interface      string   `json:"interface,omitempty"`
	Exclude        []string `json:"exclude,omitempty"`     // "addr:port" endpoints never captured (controller link)
	LocalAddrs     []string `json:"local_addrs,omitempty"` // default: the interface's addresses
	RingMB         int      `json:"ring_mb,omitempty"`
	HoldMB         int      `json:"hold_mb,omitempty"`
	DiskBudgetMB   int      `json:"disk_budget_mb,omitempty"`
	FreezeBeforeS  int      `json:"freeze_before_sec,omitempty"`
	FreezeAfterS   int      `json:"freeze_after_sec,omitempty"`
	ScanThreshold  int      `json:"scan_threshold,omitempty"`
	ScanWindowS    int      `json:"scan_window_sec,omitempty"`
	ScoredPortsAdd []uint16 `json:"scored_ports,omitempty"`
}

// CaptureHeldMB is the capture module's ring and freeze-hold budget in MiB
// for cfg: zero without the capture role (the module does not run), otherwise
// the local capture file's values, defaulting like the ring does. The agent
// adds it to the process memory cap.
func CaptureHeldMB(cfg *plan.AgentConfig, stateDir string) int64 {
	if cfg == nil || !hasCaptureRole(cfg) {
		return 0
	}
	ring, hold := int64(capture.DefaultRingBytes>>20), int64(capture.DefaultHoldBytes>>20)
	lc := captureFile{}
	if b, err := os.ReadFile(filepath.Join(stateDir, CaptureFile)); err == nil && json.Unmarshal(b, &lc) == nil {
		if lc.RingMB > 0 {
			ring = int64(lc.RingMB)
		}
		if lc.HoldMB > 0 {
			hold = int64(lc.HoldMB)
		}
	}
	return ring + hold
}

// captureModule adapts capture.Module (which cannot import internal/agent's
// named Emit type without a cycle of concerns) to agent.Module.
type captureModule struct{ *capture.Module }

func (m captureModule) Start(ctx context.Context, emit agent.Emit) error {
	return m.Module.Start(ctx, emit)
}

func hasCaptureRole(c *plan.AgentConfig) bool { return slices.Contains(c.Roles, "capture") }

// scoredPorts are the ports of every service the host declares or decoys
// (the net module's "proto/port" map), sorted.
func scoredPorts(c *plan.AgentConfig) []uint16 {
	set := map[uint16]bool{}
	if c.Modules.Net != nil { // decoy ports too: they are captured in full
		for k := range c.Modules.Net.Services {
			if _, p, ok := strings.Cut(k, "/"); ok {
				if n, err := strconv.ParseUint(p, 10, 16); err == nil {
					set[uint16(n)] = true
				}
			}
		}
	}
	out := make([]uint16, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func init() { agent.RegisterFactory(captureFactory) }

var captureFactory = agent.Factory{
	Name: "capture",
	Section: func(c *plan.AgentConfig) (string, bool) {
		if !hasCaptureRole(c) {
			return "", false
		}
		var svc map[string]string
		if c.Modules.Net != nil {
			svc = c.Modules.Net.Services
		}
		return fp([]any{c.Roles, svc}), true
	},
	Build: buildCapture,
}

func buildCapture(env agent.Env, c *plan.AgentConfig) (agent.ModuleSpec, error) {
	if runtime.GOOS != "linux" {
		return agent.ModuleSpec{}, unavailable("packet capture needs Linux AF_PACKET (Windows raw capture is not implemented)")
	}
	var lc captureFile
	if b, err := os.ReadFile(filepath.Join(env.StateDir, CaptureFile)); err == nil {
		if err := json.Unmarshal(b, &lc); err != nil {
			return agent.ModuleSpec{}, fmt.Errorf("%s: %w", CaptureFile, err)
		}
	} else if !os.IsNotExist(err) {
		return agent.ModuleSpec{}, err
	}
	cfg := capture.ModuleConfig{
		Host: env.Host, StateDir: env.StateDir, Interface: lc.Interface,
		ScoredPorts:  append(scoredPorts(c), lc.ScoredPortsAdd...),
		Ring:         capture.RingConfig{MaxBytes: int64(lc.RingMB) << 20, HoldBytes: int64(lc.HoldMB) << 20},
		DiskBudget:   int64(lc.DiskBudgetMB) << 20,
		FreezeBefore: time.Duration(lc.FreezeBeforeS) * time.Second, FreezeAfter: time.Duration(lc.FreezeAfterS) * time.Second,
		ScanTargets: lc.ScanThreshold, ScanWindow: time.Duration(lc.ScanWindowS) * time.Second,
		Subscribe: func(buf int) (<-chan event.Event, func()) { return env.Subscribe(buf) }, Logger: env.Logger,
	}
	slices.Sort(cfg.ScoredPorts)
	cfg.ScoredPorts = slices.Compact(cfg.ScoredPorts)
	for _, e := range lc.Exclude {
		ap, err := netip.ParseAddrPort(e)
		if err != nil {
			return agent.ModuleSpec{}, fmt.Errorf("%s: exclude %q: %w", CaptureFile, e, err)
		}
		cfg.Exclude = append(cfg.Exclude, ap)
	}
	for _, a := range lc.LocalAddrs {
		ad, err := netip.ParseAddr(a)
		if err != nil {
			return agent.ModuleSpec{}, fmt.Errorf("%s: local_addrs %q: %w", CaptureFile, a, err)
		}
		cfg.LocalAddrs = append(cfg.LocalAddrs, ad)
	}
	nets, err := capture.LoadOrgNets(filepath.Join(env.StateDir, OrgNetsFile))
	if err != nil {
		return agent.ModuleSpec{}, err
	}
	cfg.OrgNets = nets
	if raw, err := os.ReadFile(filepath.Join(env.StateDir, CaptureSealFile)); err == nil {
		key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return agent.ModuleSpec{}, fmt.Errorf("%s: %w", CaptureSealFile, err)
		}
		if cfg.Seal, err = capture.NewAESGCMSealer(key); err != nil {
			return agent.ModuleSpec{}, fmt.Errorf("%s: %w", CaptureSealFile, err)
		}
	}
	m, err := capture.NewModule(cfg)
	if err != nil {
		return agent.ModuleSpec{}, err
	}
	return subSpec(captureModule{m}, 600, 1200), nil
}
