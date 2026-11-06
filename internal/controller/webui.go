package controller

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/chains"
	"github.com/PurdueBlueTeam/phylax/internal/store"
	"github.com/PurdueBlueTeam/phylax/internal/ui"
)

// storeAccounts keeps operator accounts in the controller's store.
type storeAccounts struct{ st *store.Store }

func (a storeAccounts) Get(ctx context.Context, name string) (ui.Account, error) {
	r, err := a.st.Account(ctx, name)
	if errors.Is(err, store.ErrNoAccount) {
		return ui.Account{}, ui.ErrNoAccount
	}
	return ui.Account{Name: r.Name, Hash: r.PHC, Created: r.Created}, err
}

func (a storeAccounts) Put(ctx context.Context, acct ui.Account) error {
	return a.st.PutAccount(ctx, store.UIAccount{Name: acct.Name, PHC: acct.Hash, Created: acct.Created})
}

func (a storeAccounts) Count(ctx context.Context) (int, error) { return a.st.CountAccounts(ctx) }

// storeAudit writes the operator audit log. The UI refuses a state-changing
// request when this fails.
type storeAudit struct{ st *store.Store }

func (a storeAudit) Record(ctx context.Context, e ui.AuditEntry) error {
	return a.st.AppendAudit(ctx, store.AuditRow{Time: e.Time, Actor: e.Actor, Action: e.Action, Remote: e.Remote, Detail: e.Detail})
}

// UIOptions configure NewUI.
type UIOptions struct {
	Addr     string // default 127.0.0.1:8443 (loopback only)
	PlansDir string // plan templates
	Chains   chains.Config
	Logger   *slog.Logger
	// Argon2 overrides the password hashing cost (tests only).
	Argon2 ui.Argon2Params
	Now    func() time.Time
	// Audit overrides the store-backed audit log (tests only).
	Audit ui.AuditLog
}

// NewUI builds the operator web UI on this controller: store-backed accounts
// and audit log, and the operator pages on real data. It returns the server
// and the backend (for SetScorer). The caller listens on srv.Addr() and calls
// srv.EnsureAdmin.
func (c *Controller) NewUI(opt UIOptions) (*ui.Server, *WebOps, error) {
	ops := NewWebOps(c, opt.PlansDir, opt.Chains)
	c.checks.attach(ops)
	if opt.Logger == nil {
		opt.Logger = c.log
	}
	audit := ui.AuditLog(storeAudit{c.st})
	if opt.Audit != nil {
		audit = opt.Audit
	}
	srv, err := ui.New(ui.Config{
		Accounts: storeAccounts{c.st}, Audit: audit, Agents: c, Ops: ops,
		AuditExempt: []string{"POST /agents/{host}/safemode"},
		Addr:        opt.Addr, Logger: opt.Logger, Argon2: opt.Argon2, Now: opt.Now,
	})
	if err != nil {
		return nil, nil, err
	}
	c.uiMu.Lock()
	c.ui = srv
	c.uiMu.Unlock()
	return srv, ops, nil
}
