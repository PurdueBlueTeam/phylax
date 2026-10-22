package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

// UnitState is a service's current state in platform-neutral terms.
type UnitState struct {
	Exists bool `json:"exists"`
	Active bool `json:"active"`
	// Enabled is "enabled", "disabled", "masked", "static" or another
	// systemd unit-file state; on Windows "enabled" (automatic), "manual",
	// "disabled" ("masked" is reported as "disabled").
	Enabled string `json:"enabled"`
}

// ServiceManager controls services: systemd over D-Bus on Linux, the service
// control manager on Windows. Implementations return once the state is reached
// or an error/timeout occurs.
type ServiceManager interface {
	State(ctx context.Context, unit string) (UnitState, error)
	Start(ctx context.Context, unit string) error
	Stop(ctx context.Context, unit string) error
	Restart(ctx context.Context, unit string) error
	Enable(ctx context.Context, unit string) error
	Disable(ctx context.Context, unit string) error
	Mask(ctx context.Context, unit string) error
	Unmask(ctx context.Context, unit string) error
}

const kindServiceState = "service.state"

var serviceOps = []string{"start", "stop", "restart", "enable", "disable", "mask", "unmask"}

var unitRe = regexp.MustCompile(`^[A-Za-z0-9:_.@\\-]{1,256}$`)

type serviceState struct {
	name string
	op   string // "" for service.state
}

func (s serviceState) Spec() Spec {
	ps := []ParamSpec{{Name: "unit", Type: String, Required: true, Check: func(v any) error {
		if !unitRe.MatchString(v.(string)) {
			return errors.New("invalid unit name")
		}
		return nil
	}}}
	if s.op == "" {
		ps = append(ps,
			ParamSpec{Name: "state", Type: Enum, Enum: []string{"running", "stopped", "restarted"}},
			ParamSpec{Name: "enable", Type: Enum, Enum: []string{"enabled", "disabled", "masked", "unmasked"}})
	}
	return Spec{Name: s.name, Risk: RiskService, Params: ps, Doc: "Service control (systemd D-Bus / Windows SCM)."}
}

// ops returns the desired operations in execution order.
func (s serviceState) ops(p Params) []string {
	if s.op != "" {
		return []string{s.op}
	}
	var out []string
	switch p.Str("enable") {
	case "unmasked":
		out = append(out, "unmask")
	case "enabled":
		out = append(out, "unmask")
	}
	switch p.Str("state") {
	case "running":
		out = append(out, "start")
	case "stopped":
		out = append(out, "stop")
	case "restarted":
		out = append(out, "restart")
	}
	switch p.Str("enable") {
	case "enabled":
		out = append(out, "enable")
	case "disabled":
		out = append(out, "disable")
	case "masked":
		out = append(out, "mask")
	}
	return out
}

func (s serviceState) Locks(p Params) []string {
	l := []string{LockService(p.Str("unit"))}
	switch strings.TrimSuffix(p.Str("unit"), ".service") {
	case "sshd", "ssh":
		l = append(l, LockSSHD)
	case "auditd":
		l = append(l, LockAudit)
	}
	return l
}

func (s serviceState) Touches(p Params) []Touch {
	var ts []Touch
	for _, op := range s.ops(p) {
		switch op {
		case "stop":
			ts = append(ts, Touch{Kind: TouchService, Name: p.Str("unit"), Op: OpStop})
		case "disable":
			ts = append(ts, Touch{Kind: TouchService, Name: p.Str("unit"), Op: OpDisable})
		case "mask":
			ts = append(ts, Touch{Kind: TouchService, Name: p.Str("unit"), Op: OpMask})
		}
	}
	return ts
}

func svcOrErr(env *Env) (ServiceManager, error) {
	if env.Services == nil {
		return nil, fmt.Errorf("services: %w", ErrUnsupported)
	}
	return env.Services, nil
}

func pending(ops []string, st UnitState) []string {
	var out []string
	enabledLike := strings.HasPrefix(st.Enabled, "enabled") || st.Enabled == "static" || st.Enabled == "alias" ||
		st.Enabled == "indirect" || st.Enabled == "generated" || st.Enabled == "transient"
	masked := strings.HasPrefix(st.Enabled, "masked")
	for _, op := range ops {
		done := false
		switch op {
		case "start":
			done = st.Active
		case "stop":
			done = !st.Active
		case "enable":
			done = enabledLike
		case "disable":
			done = !strings.HasPrefix(st.Enabled, "enabled")
		case "mask":
			done = masked
		case "unmask":
			done = !masked
		}
		if !done {
			out = append(out, op)
		}
	}
	return out
}

func (s serviceState) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	sm, err := svcOrErr(env)
	if err != nil {
		return Plan{}, err
	}
	ops := s.ops(p)
	if len(ops) == 0 {
		return Plan{}, errors.New("nothing requested: give state and/or enable")
	}
	st, err := sm.State(ctx, p.Str("unit"))
	if err != nil {
		return Plan{}, err
	}
	if !st.Exists {
		return Plan{}, fmt.Errorf("unit %q not found", p.Str("unit"))
	}
	todo := pending(ops, st)
	if len(todo) == 0 {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: fmt.Sprintf("%s: active=%v enabled=%s; will %s", p.Str("unit"), st.Active, st.Enabled, strings.Join(todo, ", "))}, nil
}

type serviceRestore struct {
	Unit  string    `json:"unit"`
	State UnitState `json:"state"`
}

func (s serviceState) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	st, err := env.Services.State(ctx, p.Str("unit"))
	if err != nil {
		return Rollback{}, err
	}
	return Rollback{Kind: kindServiceState, Data: serviceRestore{Unit: p.Str("unit"), State: st}}, nil
}

func (s serviceState) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	sm := env.Services
	unit := p.Str("unit")
	st, err := sm.State(ctx, unit)
	if err != nil {
		return nil, err
	}
	todo := map[string]bool{}
	for _, op := range pending(s.ops(p), st) {
		todo[op] = true
	}
	// Order: unmask, stop, start/restart, enable/disable/mask.
	for _, op := range []string{"unmask", "stop", "start", "restart", "enable", "disable", "mask"} {
		if !todo[op] {
			continue
		}
		if err := runOp(ctx, sm, op, unit); err != nil {
			return nil, fmt.Errorf("%s %s: %w", op, unit, err)
		}
	}
	return nil, nil
}

func runOp(ctx context.Context, sm ServiceManager, op, unit string) error {
	switch op {
	case "start":
		return sm.Start(ctx, unit)
	case "stop":
		return sm.Stop(ctx, unit)
	case "restart":
		return sm.Restart(ctx, unit)
	case "enable":
		return sm.Enable(ctx, unit)
	case "disable":
		return sm.Disable(ctx, unit)
	case "mask":
		return sm.Mask(ctx, unit)
	case "unmask":
		return sm.Unmask(ctx, unit)
	}
	return fmt.Errorf("unknown op %q", op)
}

func (s serviceState) Verify(ctx context.Context, env *Env, p Params) error {
	st, err := env.Services.State(ctx, p.Str("unit"))
	if err != nil {
		return err
	}
	var ops []string
	for _, op := range s.ops(p) {
		if op == "restart" {
			op = "start" // after a restart the unit must be active
		}
		ops = append(ops, op)
	}
	if left := pending(ops, st); len(left) > 0 {
		return fmt.Errorf("service %s not in desired state (still: %v)", p.Str("unit"), left)
	}
	return nil
}

// restoreServices is the dead-man Handler for kindServiceState. Idempotent.
func restoreServices(ctx context.Context, env *Env, e deadman.Entry) error {
	var r serviceRestore
	if err := json.Unmarshal(e.Data, &r); err != nil {
		return err
	}
	sm := env.Services
	if sm == nil {
		return ErrUnsupported
	}
	cur, err := sm.State(ctx, r.Unit)
	if err != nil {
		return err
	}
	var errs []error
	wasMasked := strings.HasPrefix(r.State.Enabled, "masked")
	if !wasMasked && strings.HasPrefix(cur.Enabled, "masked") {
		errs = append(errs, sm.Unmask(ctx, r.Unit))
	}
	if r.State.Active && !cur.Active {
		errs = append(errs, sm.Start(ctx, r.Unit))
	} else if !r.State.Active && cur.Active {
		errs = append(errs, sm.Stop(ctx, r.Unit))
	}
	switch {
	case wasMasked && !strings.HasPrefix(cur.Enabled, "masked"):
		errs = append(errs, sm.Mask(ctx, r.Unit))
	case r.State.Enabled == "enabled" && cur.Enabled != "enabled":
		errs = append(errs, sm.Enable(ctx, r.Unit))
	case r.State.Enabled == "disabled" && cur.Enabled == "enabled":
		errs = append(errs, sm.Disable(ctx, r.Unit))
	}
	return errors.Join(errs...)
}
