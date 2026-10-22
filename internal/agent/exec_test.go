package agent

import (
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/link"
)

func TestExecRefusesToStartWithoutPlanKey(t *testing.T) {
	l := Layout{Root: t.TempDir()}
	if err := l.SaveBundle(&Bundle{Controllers: []string{"127.0.0.1:1"}, ControllerPin: link.Pin{}.String(), Host: "h"}); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{Layout: l, Logger: quietLog(), Exec: &ExecConfig{Env: actions.NewEnv("h", t.TempDir())}})
	if err == nil || !strings.Contains(err.Error(), "plan-signing key") {
		t.Fatalf("got %v", err)
	}
	b := &Bundle{PlanKey: "zz"}
	if _, err := b.PlanPublicKey(); err == nil {
		t.Fatal("bad plan_key accepted")
	}
}
