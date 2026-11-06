package actions

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

type regTestAction struct{ name string }

func (a regTestAction) Spec() Spec                                            { return Spec{Name: a.name, Risk: RiskNone, ReadOnly: true} }
func (regTestAction) Locks(Params) []string                                   { return nil }
func (regTestAction) Touches(Params) []Touch                                  { return nil }
func (regTestAction) Plan(context.Context, *Env, Params) (Plan, error)        { return Plan{}, nil }
func (regTestAction) Capture(context.Context, *Env, Params) (Rollback, error) { return Rollback{}, nil }
func (regTestAction) Apply(context.Context, *Env, Params) (Output, error)     { return Output{}, nil }
func (regTestAction) Verify(context.Context, *Env, Params) error              { return nil }

func namedAction(name string) Action { return regTestAction{name} }

func TestRegisterAddsToCore(t *testing.T) {
	Register(func() []Action { return []Action{namedAction("regtest.hello")} })
	if _, err := Core().Get("regtest.hello"); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterUndoDuplicatePanics(t *testing.T) {
	RegisterUndo("regtest.undo", func(context.Context, *Env, deadman.Entry) error { return nil })
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate undo kind accepted")
		}
	}()
	RegisterUndo("regtest.undo", func(context.Context, *Env, deadman.Entry) error { return nil })
}

func TestUnsupportedWrapsSentinel(t *testing.T) {
	err := Unsupported("network devices")
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "network devices") {
		t.Fatalf("%v", err)
	}
}

func TestEnvNowUsesClock(t *testing.T) {
	fixed := time.Date(2027, 2, 6, 9, 0, 0, 0, time.UTC)
	e := &Env{Clock: func() time.Time { return fixed }}
	if !e.Now().Equal(fixed) {
		t.Fatal(e.Now())
	}
	if d := time.Since((&Env{}).Now()); d < 0 || d > time.Second {
		t.Fatal(d)
	}
}

func TestEnvExtNilReadsAbsent(t *testing.T) {
	e := &Env{}
	if v, ok := e.Ext["firewall"]; ok || v != nil {
		t.Fatal("nil Ext must read as absent")
	}
	e.Ext = map[string]any{"firewall": 1}
	if e.Ext["firewall"] != 1 {
		t.Fatal("Ext lost a value")
	}
}
