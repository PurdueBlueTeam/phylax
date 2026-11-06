package controller

import (
	"context"
	"crypto/ecdsa"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// fakeStepAgent is a link-level agent that answers signed steps with signed
// results. It is not a mock of the controller code: it speaks the real wire
// protocol and signs with a real ECDSA identity.
type fakeStepAgent struct {
	t    *testing.T
	x    *ctl
	host string
	id   *link.Identity
	sess *link.Session

	mu   sync.Mutex
	busy map[string]int
	hold bool
	step func(*link.Step) (string, bool)
}

func newFakeStepAgent(t *testing.T, x *ctl, host string, hold bool, step func(*link.Step) (string, bool)) *fakeStepAgent {
	t.Helper()
	tok, err := x.c.MintToken(host, 0)
	if err != nil {
		t.Fatal(err)
	}
	id, err := link.GenerateIdentity(host)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeStepAgent{t: t, x: x, host: host, id: id, busy: map[string]int{}, hold: hold, step: step}
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := link.Dial(ctx, x.addr, link.DialOptions{Identity: id, ServerPin: x.c.Pin(), ALPN: link.ALPNAgent})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	f.sess = link.NewSession(conn, link.Options{Role: link.RoleAgent, Handler: func(_ context.Context, m link.Message) error {
		if s, ok := m.(*link.Step); ok {
			if f.hold {
				return nil
			}
			go f.answer(s)
		}
		return nil
	}})
	go f.sess.Run(ctx)
	if err := f.sess.Send(ctx, link.PrioCritical, &link.Hello{Proto: 1, Minor: link.ProtoMinor, Host: host,
		Version: "fake", Token: tok}); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); f.sess.Close() })
	waitFor(t, 10*time.Second, "fake agent connection", func() bool {
		st, ok := x.c.AgentStatus(host)
		return ok && st.Connected
	})
	return f
}

func (f *fakeStepAgent) answer(w *link.Step) {
	outcome, ok := f.step(w)
	if !ok {
		return
	}
	s := plan.StepFromWire(w)
	res, err := plan.NewResult(s, outcome)
	if err != nil {
		return
	}
	now := time.Now().UnixMilli()
	res.StartedMS, res.FinishedMS = now, now
	key, ok := f.id.Cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return
	}
	if err := res.Sign(key); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = f.sess.Send(ctx, link.PrioStep, plan.ResultToWire(res, nil))
}

// busyTimes answers busy for the first n apply steps of node.
func (f *fakeStepAgent) busyTimes(node string, n int) {
	f.mu.Lock()
	f.busy[node] = n
	f.mu.Unlock()
}

func (f *fakeStepAgent) takeBusy(node string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.busy[node] <= 0 {
		return false
	}
	f.busy[node]--
	return true
}
