package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"path/filepath"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/bootstrapfile"
	"github.com/PurdueBlueTeam/phylax/internal/link"
)

// The agent.* family, part 1 (design: Lifecycle, the agent.* actions): the
// signed forms of the console operations for a host that still answers.
// agent.replace_binary and agent.rename are in agent_swap.go and go through
// the swap helper.
func init() {
	Register(func() []Action { return []Action{agentSetController{}, agentSafeMode{}, agentConfig{}} })
}

const (
	// optionsFile is the agent's live-tunable options (agent.config). The agent
	// applies it at start and on every heartbeat tick.
	optionsFile = "options.json"
	// agent.config accepts memory limits in MB in this range.
	optMinMemoryMB = 32
	optMaxMemoryMB = 1024
)

// agentPath is a file in the agent's state directory.
func agentPath(env *Env, name string) (string, error) {
	if env.AgentRoot == "" {
		return "", errors.New("actions: no agent state directory")
	}
	return filepath.Join(env.AgentRoot, name), nil
}

// readControllers reads the bootstrap file's controller list and pin.
func readControllers(path string) ([]string, string, error) {
	raw, _, err := readBounded(path)
	if err != nil {
		return nil, "", err
	}
	var b struct {
		Controllers   []string `json:"controllers"`
		ControllerPin string   `json:"controller_pin"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	return b.Controllers, b.ControllerPin, nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// agentSetController is the signed form of `phylax set-controller`: it
// rewrites the agent's bootstrap file through the same leaf package the CLI
// uses. Lockout class: a wrong address that the agent cannot confirm is undone
// by the default dead-man window.
type agentSetController struct{}

func (agentSetController) Spec() Spec {
	return Spec{Name: "agent.set_controller", Risk: RiskLockout,
		Doc: "point the agent at new controller addresses (the signed form of phylax set-controller)",
		Params: []ParamSpec{
			{Name: "controllers", Type: String, Required: true, Max: 1024},
			{Name: "pin", Type: String, Max: 128},
		}}
}

func (agentSetController) Locks(Params) []string  { return nil }
func (agentSetController) Touches(Params) []Touch { return nil }

// addresses splits and validates the controller list and pin.
func (agentSetController) addresses(p Params) ([]string, error) {
	var out []string
	for _, a := range strings.Split(p.Str("controllers"), ",") {
		if a = strings.TrimSpace(a); a == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(a); err != nil {
			return nil, fmt.Errorf("controller address %q: %w", a, err)
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, errors.New("at least one controller address is required")
	}
	if pin := strings.TrimSpace(p.Str("pin")); pin != "" {
		if _, err := link.ParsePin(pin); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (a agentSetController) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	addrs, err := a.addresses(p)
	if err != nil {
		return Plan{}, err
	}
	pin := strings.TrimSpace(p.Str("pin"))
	path, err := agentPath(env, "bootstrap.json")
	if err != nil {
		return Plan{}, err
	}
	old, oldPin, err := readControllers(path)
	if err != nil {
		return Plan{}, err
	}
	pl := Plan{Diff: fmt.Sprintf("controllers: %s -> %s", strings.Join(old, ", "), strings.Join(addrs, ", "))}
	if pin != "" && pin != oldPin {
		pl.Diff += fmt.Sprintf("\ncontroller pin: %s -> %s", oldPin, pin)
	}
	pl.Done = sameStrings(old, addrs) && (pin == "" || pin == oldPin)
	return pl, nil
}

func (agentSetController) Capture(_ context.Context, env *Env, _ Params) (Rollback, error) {
	path, err := agentPath(env, "bootstrap.json")
	if err != nil {
		return Rollback{}, err
	}
	return snapshotRollback(path)
}

func (a agentSetController) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	addrs, err := a.addresses(p)
	if err != nil {
		return nil, err
	}
	path, err := agentPath(env, "bootstrap.json")
	if err != nil {
		return nil, err
	}
	if err := bootstrapfile.Rewrite(path, addrs, strings.TrimSpace(p.Str("pin"))); err != nil {
		return nil, err
	}
	return nil, nil
}

func (a agentSetController) Verify(_ context.Context, env *Env, p Params) error {
	addrs, err := a.addresses(p)
	if err != nil {
		return err
	}
	path, err := agentPath(env, "bootstrap.json")
	if err != nil {
		return err
	}
	got, gotPin, err := readControllers(path)
	if err != nil {
		return err
	}
	if !sameStrings(got, addrs) {
		return fmt.Errorf("agent.set_controller: bootstrap has %v", got)
	}
	if pin := strings.TrimSpace(p.Str("pin")); pin != "" && pin != gotPin {
		return errors.New("agent.set_controller: bootstrap pin not rewritten")
	}
	return nil
}

// agentSafeMode turns safe mode on. Turning it off stays a signed control from
// the operator UI (design: the executor refuses every action while safe mode is
// on, so no action can clear it).
type agentSafeMode struct{}

func (agentSafeMode) Spec() Spec {
	return Spec{Name: "agent.safe_mode", Risk: RiskNone,
		Doc: "turn the agent's safe mode on (turning it off is a signed control from the operator UI)",
		Params: []ParamSpec{
			{Name: "on", Type: Bool, Required: true},
		}}
}

func (agentSafeMode) Locks(Params) []string  { return nil }
func (agentSafeMode) Touches(Params) []Touch { return nil }

var errSafeModeOff = errors.New("agent.safe_mode: safe mode is turned off from the operator UI")

func (agentSafeMode) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	if !p.Bool("on") {
		return Plan{}, errSafeModeOff
	}
	on := env.Safe.On()
	return Plan{Done: on, Diff: "safe mode: on"}, nil
}

func (agentSafeMode) Capture(context.Context, *Env, Params) (Rollback, error) {
	return Rollback{}, nil
}

func (agentSafeMode) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	if !p.Bool("on") {
		return nil, errSafeModeOff
	}
	if env.Safe == nil {
		return nil, errors.New("agent.safe_mode: no safe-mode switch on this host")
	}
	return nil, env.Safe.Set(true)
}

func (agentSafeMode) Verify(_ context.Context, env *Env, p Params) error {
	if !p.Bool("on") {
		return errSafeModeOff
	}
	if !env.Safe.On() {
		return errors.New("agent.safe_mode: safe mode is not on")
	}
	return nil
}

// agentConfig writes the agent's options.json; the agent applies it within one
// heartbeat (debug.SetMemoryLimit) and the change needs no restart.
type agentConfig struct{}

func (agentConfig) Spec() Spec {
	return Spec{Name: "agent.config", Risk: RiskService,
		Doc: "set the agent's memory limit in MB (options.json, applied live)",
		Params: []ParamSpec{
			{Name: "memory_limit_mb", Type: Int, Required: true, Check: func(v any) error {
				if n := v.(int); n < optMinMemoryMB || n > optMaxMemoryMB {
					return fmt.Errorf("must be %d..%d MB", optMinMemoryMB, optMaxMemoryMB)
				}
				return nil
			}},
		}}
}

func (agentConfig) Locks(Params) []string  { return nil }
func (agentConfig) Touches(Params) []Touch { return nil }

type agentOptions struct {
	MemoryLimitMB int `json:"memory_limit_mb"`
}

// currentOptions reads options.json; ok is false when there is none.
func currentOptions(path string) (agentOptions, bool, error) {
	raw, _, err := readBounded(path)
	if errors.Is(err, fs.ErrNotExist) {
		return agentOptions{}, false, nil
	}
	if err != nil {
		return agentOptions{}, false, err
	}
	var o agentOptions
	if err := json.Unmarshal(raw, &o); err != nil {
		return agentOptions{}, false, fmt.Errorf("%s: %w", path, err)
	}
	return o, true, nil
}

func (agentConfig) Plan(_ context.Context, env *Env, p Params) (Plan, error) {
	path, err := agentPath(env, optionsFile)
	if err != nil {
		return Plan{}, err
	}
	n, _ := p.Int("memory_limit_mb")
	cur, ok, err := currentOptions(path)
	if err != nil {
		return Plan{}, err
	}
	if !ok {
		return Plan{Diff: fmt.Sprintf("%s: absent -> memory_limit_mb=%d", optionsFile, n)}, nil
	}
	return Plan{Done: cur.MemoryLimitMB == n,
		Diff: fmt.Sprintf("%s: memory_limit_mb=%d -> %d", optionsFile, cur.MemoryLimitMB, n)}, nil
}

func (agentConfig) Capture(_ context.Context, env *Env, _ Params) (Rollback, error) {
	path, err := agentPath(env, optionsFile)
	if err != nil {
		return Rollback{}, err
	}
	return snapshotRollback(path)
}

func (agentConfig) Apply(_ context.Context, env *Env, p Params) (Output, error) {
	path, err := agentPath(env, optionsFile)
	if err != nil {
		return nil, err
	}
	n, _ := p.Int("memory_limit_mb")
	raw, err := json.Marshal(agentOptions{MemoryLimitMB: n})
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	return nil, atomicfile.WriteFile(path, raw, 0o600)
}

func (agentConfig) Verify(_ context.Context, env *Env, p Params) error {
	path, err := agentPath(env, optionsFile)
	if err != nil {
		return err
	}
	n, _ := p.Int("memory_limit_mb")
	cur, ok, err := currentOptions(path)
	if err != nil {
		return err
	}
	if !ok || cur.MemoryLimitMB != n {
		return fmt.Errorf("agent.config: %s does not carry memory_limit_mb=%d", path, n)
	}
	return nil
}
