package agent

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
)

// fakeController speaks the real protocol with a persistent store/receiver
// that survives server restarts (as a durable controller store would).
type fakeController struct {
	t     *testing.T
	id    *link.Identity
	token string
	host  string

	mu            sync.Mutex
	rx            *link.Receiver
	events        []event.Event
	hellos        []link.Hello
	heartbeats    []link.Heartbeat
	results       []link.StepResult
	enrolled      bool
	sendOnWelcome []link.Message // extra messages sent after welcome/ack

	addr   string
	cancel context.CancelFunc
	done   chan struct{}
}

func newFakeController(t *testing.T, host, token string, ackedStart uint64) *fakeController {
	id, err := link.GenerateIdentity("controller")
	if err != nil {
		t.Fatal(err)
	}
	c := &fakeController{t: t, id: id, host: host, token: token, rx: link.NewReceiver(ackedStart, 0)}
	c.start("127.0.0.1:0")
	t.Cleanup(c.stop)
	return c
}

func (c *fakeController) start(addr string) {
	srv, err := link.NewServer(link.ServerOptions{Identity: c.id,
		Check:    func(link.Pin) error { return nil },
		Handlers: map[string]link.Handler{link.ALPNAgent: c.handle}})
	if err != nil {
		c.t.Fatal(err)
	}
	var ln net.Listener
	for i := 0; i < 50; i++ {
		if ln, err = net.Listen("tcp", addr); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		c.t.Fatal(err)
	}
	c.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel, c.done = cancel, make(chan struct{})
	go func() { defer close(c.done); srv.Serve(ctx, ln) }()
}

func (c *fakeController) stop() {
	if c.cancel != nil {
		c.cancel()
		<-c.done
		c.cancel = nil
	}
}

func (c *fakeController) restart() {
	addr := c.addr
	c.stop()
	c.start(addr)
}

func (c *fakeController) handle(ctx context.Context, conn *link.Conn) {
	var sess *link.Session
	sess = link.NewSession(conn, link.Options{Role: link.RoleController, AckFunc: c.rx.Acked,
		Handler: func(ctx context.Context, m link.Message) error {
			switch v := m.(type) {
			case *link.Hello:
				c.mu.Lock()
				c.hellos = append(c.hellos, *v)
				if v.Host != c.host || (!c.enrolled && v.Token != c.token) {
					c.mu.Unlock()
					return io.ErrClosedPipe // wrong token: no welcome
				}
				c.enrolled = true
				extra := c.sendOnWelcome
				c.mu.Unlock()
				sess.TrySend(link.PrioCritical, &link.Welcome{Proto: 1, Enrolled: true})
				sess.TrySend(link.PrioCritical, &link.Ack{Seq: c.rx.Acked()})
				for _, e := range extra {
					sess.TrySend(link.PrioStep, e)
				}
			case *link.Events:
				fresh, err := c.rx.Fresh(v.Events)
				if err != nil {
					return err
				}
				c.mu.Lock()
				c.events = append(c.events, fresh...)
				c.mu.Unlock()
				sess.TrySend(link.PrioCritical, &link.Ack{Seq: c.rx.Commit(fresh)})
			case *link.Heartbeat:
				c.mu.Lock()
				c.heartbeats = append(c.heartbeats, *v)
				c.mu.Unlock()
			case *link.StepResult:
				c.mu.Lock()
				c.results = append(c.results, *v)
				c.mu.Unlock()
			}
			return nil
		}})
	sess.Run(ctx)
}

func (c *fakeController) snapshot() (evs []event.Event, hellos []link.Hello, hbs []link.Heartbeat) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append(evs, c.events...), append(hellos, c.hellos...), append(hbs, c.heartbeats...)
}

func eventually(t *testing.T, d time.Duration, what string, f func() bool) {
	t.Helper()
	dl := time.Now().Add(d)
	for time.Now().Before(dl) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func writeBundle(t *testing.T, l Layout, c *fakeController, token string) {
	t.Helper()
	if err := l.SaveBundle(&Bundle{Controllers: []string{c.addr}, ControllerPin: c.id.Pin.String(),
		Host: c.host, Token: token, Roles: []string{"capture"}}); err != nil {
		t.Fatal(err)
	}
}

type runningAgent struct {
	a      *Agent
	cancel context.CancelFunc
	done   chan error
}

func startAgent(t *testing.T, cfg Config) *runningAgent {
	t.Helper()
	cfg.Logger = quietLog()
	if cfg.Backoff.Min == 0 {
		cfg.Backoff = link.Backoff{Min: 20 * time.Millisecond, Max: 100 * time.Millisecond}
	}
	if cfg.Supervisor.Backoff.Min == 0 {
		cfg.Supervisor.Backoff = link.Backoff{Min: time.Millisecond, Max: 10 * time.Millisecond}
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &runningAgent{a: a, cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- a.Run(ctx) }()
	t.Cleanup(r.stop)
	return r
}

func (r *runningAgent) stop() {
	if r.cancel == nil {
		return
	}
	r.cancel()
	r.cancel = nil
	select {
	case <-r.done:
	case <-time.After(10 * time.Second):
		panic("agent did not stop")
	}
}

// funcModule adapts a function to Module.
type funcModule struct {
	name string
	fn   func(ctx context.Context, emit Emit) error
}

func (m funcModule) Name() string                            { return m.name }
func (m funcModule) Start(ctx context.Context, e Emit) error { return m.fn(ctx, e) }
