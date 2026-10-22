package actions

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
)

// cron.disable and at.disable take a scheduled-job file out of service by
// moving it to quarantine (never deleting it); rollback and file.restore put
// it back.

var cronDirs = []string{"/etc/cron.d/", "/etc/cron.hourly/", "/etc/cron.daily/", "/etc/cron.weekly/", "/etc/cron.monthly/",
	"/var/spool/cron/", "/etc/anacrontab", "/etc/crontab"}
var atDirs = []string{"/var/spool/at/", "/var/spool/cron/atjobs/"}

type cronDisable struct {
	name string
	at   bool
}

func (c cronDisable) allowed() []string {
	if c.at {
		return atDirs
	}
	return cronDirs
}

func (c cronDisable) Spec() Spec {
	return Spec{Name: c.name, Risk: RiskService,
		Doc: "Quarantine one scheduled-job file (never deletes). Allowed only under the cron/at spool and drop-in directories.",
		Params: []ParamSpec{
			{Name: "path", Type: Path, Required: true, Check: func(v any) error {
				s := v.(string)
				if path.Clean(s) != s {
					return errors.New("path is not clean")
				}
				for _, d := range c.allowed() {
					if s == d || (strings.HasSuffix(d, "/") && strings.HasPrefix(s, d) && len(s) > len(d)) {
						return nil
					}
				}
				return fmt.Errorf("not a %s file location", strings.TrimSuffix(c.name, ".disable"))
			}},
			{Name: "reason", Type: String, Max: 1024}}}
}

func (c cronDisable) q(p Params) (Params, error) {
	m := map[string]any{"path": p.Str("path")}
	if p.Has("reason") {
		m["reason"] = p.Str("reason")
	}
	return fileQuarantine{}.Spec().Validate(m)
}

func (c cronDisable) Locks(Params) []string { return nil }
func (c cronDisable) Touches(p Params) []Touch {
	return []Touch{pathTouch(p.Str("path"), OpQuarantine)}
}
func (c cronDisable) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	q, err := c.q(p)
	if err != nil {
		return Plan{}, err
	}
	return fileQuarantine{}.Plan(ctx, env, q)
}
func (c cronDisable) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	q, err := c.q(p)
	if err != nil {
		return Rollback{}, err
	}
	return fileQuarantine{}.Capture(ctx, env, q)
}
func (c cronDisable) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	q, err := c.q(p)
	if err != nil {
		return nil, err
	}
	return fileQuarantine{}.Apply(ctx, env, q)
}
func (c cronDisable) Verify(ctx context.Context, env *Env, p Params) error {
	q, err := c.q(p)
	if err != nil {
		return err
	}
	return fileQuarantine{}.Verify(ctx, env, q)
}
