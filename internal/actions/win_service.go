package actions

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

const kindSvcCfg = "win.service_config"

// criticalServices are never disabled by win.service.config, scored or not:
// disabling them takes a DC or the management plane down.
var criticalServices = []string{
	"WinRM", "TermService", "LanmanServer", "LanmanWorkstation", "NTDS", "Netlogon", "Kdc", "DNS",
	"RpcSs", "RpcEptMapper", "DcomLaunch", "SamSs", "EventLog", "BFE", "Winmgmt", "DFSR", "IsmServ",
}

var svcStarts = []string{"auto", "auto_delayed", "manual", "disabled"}

type svcCfgUndo struct {
	Unit    string `json:"unit"`
	Start   string `json:"start"`
	Running bool   `json:"running"`
}

func init() {
	registerUndo(kindSvcCfg, func(ctx context.Context, env *Env, e deadman.Entry) error {
		var u svcCfgUndo
		if err := jsonUndo(e, &u); err != nil {
			return err
		}
		if env.Win.Svc == nil {
			return unsupported("service configuration")
		}
		var errs []error
		errs = append(errs, env.Win.Svc.SetStart(ctx, u.Unit, u.Start))
		if u.Running && env.Services != nil {
			if st, err := env.Services.State(ctx, u.Unit); err == nil && st.Exists && !st.Active {
				errs = append(errs, env.Services.Start(ctx, u.Unit))
			}
		}
		return errors.Join(errs...)
	})
}

type winServiceConfig struct{}

func (winServiceConfig) Spec() Spec {
	return Spec{Name: "win.service.config", Risk: RiskService,
		Doc: "Set a Windows service's start type, optionally stopping it. dc_only limits the change to domain controllers (Print Spooler: disable it on DCs). WinRM, RDP, SMB server, Netlogon, NTDS, KDC, DNS and other core services are never disabled; scored services are refused by the scoring guard.",
		Params: []ParamSpec{
			{Name: "unit", Type: String, Required: true, Check: func(v any) error {
				if !unitRe.MatchString(v.(string)) {
					return errors.New("invalid service name")
				}
				return nil
			}},
			{Name: "start", Type: Enum, Required: true, Enum: svcStarts},
			{Name: "stop", Type: Bool},
			{Name: "dc_only", Type: Bool}}}
}

func (winServiceConfig) Locks(p Params) []string { return []string{LockService(p.Str("unit"))} }
func (winServiceConfig) Touches(p Params) []Touch {
	var ts []Touch
	if p.Str("start") == "disabled" {
		ts = append(ts, Touch{Kind: TouchService, Name: p.Str("unit"), Op: OpDisable})
	}
	if p.Bool("stop") {
		ts = append(ts, Touch{Kind: TouchService, Name: p.Str("unit"), Op: OpStop})
	}
	return ts
}

func (winServiceConfig) refuse(p Params) error {
	if p.Str("start") != "disabled" && !p.Bool("stop") {
		return nil
	}
	for _, c := range criticalServices {
		if strings.EqualFold(c, p.Str("unit")) {
			return fmt.Errorf("%w: %s is a core service and is never disabled or stopped by a plan", ErrScoringUnsafe, c)
		}
	}
	return nil
}

func (a winServiceConfig) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	if err := a.refuse(p); err != nil {
		return Plan{}, err
	}
	if env.Win.Svc == nil {
		return Plan{}, unsupported("service configuration")
	}
	if p.Bool("dc_only") {
		rs, err := regStore(env)
		if err != nil {
			return Plan{}, err
		}
		oi, err := readOSInfo(ctx, rs)
		if err != nil {
			return Plan{}, err
		}
		if !oi.isDC() {
			return Plan{Done: true, Notes: []string{"not a domain controller; dc_only leaves " + p.Str("unit") + " alone"}}, nil
		}
	}
	cfg, err := env.Win.Svc.Config(ctx, p.Str("unit"))
	if err != nil {
		return Plan{}, err
	}
	if !cfg.Exists {
		return Plan{Done: true, Notes: []string{"service " + p.Str("unit") + " not installed"}}, nil
	}
	var d []string
	if cfg.Start != p.Str("start") {
		d = append(d, fmt.Sprintf("~ %s start: %s -> %s", p.Str("unit"), cfg.Start, p.Str("start")))
	}
	if p.Bool("stop") && cfg.Running {
		d = append(d, "~ "+p.Str("unit")+": running -> stopped")
	}
	if len(d) == 0 {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: strings.Join(d, "\n")}, nil
}

func (winServiceConfig) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	cfg, err := env.Win.Svc.Config(ctx, p.Str("unit"))
	if err != nil {
		return Rollback{}, err
	}
	return Rollback{Kind: kindSvcCfg, Data: svcCfgUndo{Unit: p.Str("unit"), Start: cfg.Start, Running: cfg.Running}}, nil
}

func (winServiceConfig) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	if err := env.Win.Svc.SetStart(ctx, p.Str("unit"), p.Str("start")); err != nil {
		return nil, err
	}
	if p.Bool("stop") {
		if env.Services == nil {
			return nil, unsupported("services")
		}
		if err := env.Services.Stop(ctx, p.Str("unit")); err != nil {
			return nil, fmt.Errorf("stop %s: %w", p.Str("unit"), err)
		}
	}
	return nil, nil
}

func (winServiceConfig) Verify(ctx context.Context, env *Env, p Params) error {
	cfg, err := env.Win.Svc.Config(ctx, p.Str("unit"))
	if err != nil {
		return err
	}
	if cfg.Start != p.Str("start") {
		return fmt.Errorf("%s start type is %s, want %s", p.Str("unit"), cfg.Start, p.Str("start"))
	}
	if p.Bool("stop") && cfg.Running {
		return fmt.Errorf("%s is still running", p.Str("unit"))
	}
	return nil
}
