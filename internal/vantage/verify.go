package vantage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/checks/probe"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/scorer"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

// ErrNoPublicPath means there is no public service to verify the account on;
// the PCR engine treats any error from Login as a failed verification.
var ErrNoPublicPath = errors.New("vantage: no public service is configured for this account")

// VerifyRequest asks the Kali to log in with a freshly rotated credential.
// The password is a vault.Secret: it is held in memory only and redacts itself
// in logs and JSON, so the transport must carry it explicitly (signed step).
type VerifyRequest struct {
	ID      string // correlation id (the PCR transaction)
	Account string
	Pass    vault.Secret
}

// ServiceVerdict is one login attempt.
type ServiceVerdict struct {
	ID    string
	Type  probe.Type
	OK    bool
	Class probe.Class
	Err   string
}

// VerifyResult is the Kali's answer.
type VerifyResult struct {
	ID       string
	Account  string
	OK       bool
	Err      string
	Services []ServiceVerdict
}

// Transport carries a VerifyRequest to the Kali agent and returns its result.
// The wiring (a signed step over the agent link) lives with the controller.
type Transport interface {
	Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error)
}

// RemoteVerifier is the controller-side scorer.Verifier backed by the Kali.
type RemoteVerifier struct {
	T Transport
	// Timeout bounds one verification (default 60s).
	Timeout time.Duration
}

var _ scorer.Verifier = (*RemoteVerifier)(nil)

// Login implements scorer.Verifier.
func (v *RemoteVerifier) Login(ctx context.Context, account string, pass vault.Secret) error {
	to := v.Timeout
	if to <= 0 {
		to = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	res, err := v.T.Verify(ctx, VerifyRequest{ID: account, Account: account, Pass: pass})
	if err != nil {
		return fmt.Errorf("vantage: verify %s: %w", account, err)
	}
	if !res.OK {
		return fmt.Errorf("vantage: verification of %s failed: %s", account, res.Err)
	}
	return nil
}

// VerifyConfig configures the Kali-side verifier.
type VerifyConfig struct {
	Allow Allowlist
	// Targets returns the public services the account is scored on (the Specs
	// carry the host and port; credentials are supplied by the request).
	Targets func(account string) []probe.Spec
	Probe   probe.Options
	clock
}

// VerifyService performs the logins. It is also an agent module (its Start
// just waits) so the agent can register it, report health, and give it an
// Emit for V4 alerts.
type VerifyService struct {
	cfg  VerifyConfig
	emit atomic.Pointer[agent.Emit]
}

// NewVerifyService validates the configuration.
func NewVerifyService(cfg VerifyConfig) (*VerifyService, error) {
	if cfg.Targets == nil || len(cfg.Allow.prefixes) == 0 {
		return nil, errors.New("vantage: verify service needs Targets and a non-empty allowlist")
	}
	cfg.clock.defaults()
	return &VerifyService{cfg: cfg}, nil
}

var _ agent.Module = (*VerifyService)(nil)

// Name implements agent.Module.
func (s *VerifyService) Name() string { return "vantage.verify" }

// Start implements agent.Module.
func (s *VerifyService) Start(ctx context.Context, emit agent.Emit) error {
	s.emit.Store(&emit)
	<-ctx.Done()
	s.emit.Store(nil)
	return nil
}

func (s *VerifyService) emitter() agent.Emit {
	if e := s.emit.Load(); e != nil {
		return *e
	}
	return func(event.Event) error { return nil }
}

// Handle logs in with the new credential on every public service of the
// account, through the real public path. Success requires every service to
// accept it; a failure is a V4 alert and the PCR engine rolls back.
func (s *VerifyService) Handle(ctx context.Context, req VerifyRequest) VerifyResult {
	res := VerifyResult{ID: req.ID, Account: req.Account}
	specs := s.cfg.Targets(req.Account)
	var run []probe.Spec
	for _, sp := range specs {
		if !s.cfg.Allow.Allows(sp.Host) {
			res.Services = append(res.Services, ServiceVerdict{ID: sp.ID, Type: sp.Type, Class: probe.ClassConfig, Err: "target is not allowlisted"})
			continue
		}
		run = append(run, sp)
	}
	switch {
	case len(run) == 0:
		res.Err = ErrNoPublicPath.Error()
	default:
		cr := probe.Cred{User: req.Account, Pass: req.Pass}
		var bad []string
		for _, sp := range run {
			if ctx.Err() != nil {
				bad = append(bad, "cancelled")
				break
			}
			r := probe.AuthOnly(ctx, sp, cr, s.cfg.Probe)
			res.Services = append(res.Services, ServiceVerdict{ID: sp.ID, Type: sp.Type, OK: r.OK, Class: r.Class, Err: r.Err})
			if !r.OK {
				bad = append(bad, fmt.Sprintf("%s(%s): %s", sp.Type, sp.Host, r.Err))
			}
		}
		if len(bad) == 0 {
			res.OK = true
		} else {
			res.Err = strings.Join(bad, "; ")
		}
	}
	f := map[string]any{"id": req.ID, "account": req.Account, "ok": res.OK, "err": res.Err, "services": len(res.Services)}
	prio := event.PriorityNormal
	if !res.OK {
		prio = event.PriorityCritical // V4: starts the rollback
		det := make([]map[string]any, 0, len(res.Services))
		for _, sv := range res.Services {
			det = append(det, map[string]any{"id": sv.ID, "type": string(sv.Type), "ok": sv.OK, "class": string(sv.Class), "err": sv.Err})
		}
		f["detail"] = det
	}
	_ = s.emitter()(newEvent(KindPCRVerify, prio, s.cfg.Now(), f))
	return res
}

// LocalTransport runs the verification in-process (tests, or a controller
// that is also the verifier).
type LocalTransport struct{ S *VerifyService }

// Verify implements Transport.
func (l LocalTransport) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	return l.S.Handle(ctx, req), nil
}
