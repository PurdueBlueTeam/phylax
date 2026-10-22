package link

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

type testEnv struct {
	srvID, cliID *Identity
	addr         string
	cancel       context.CancelFunc
	done         chan struct{}
}

// startServer runs a real Server on a loopback TCP listener.
func startServer(t *testing.T, o ServerOptions) *testEnv {
	t.Helper()
	srvID, err := GenerateIdentity("controller")
	if err != nil {
		t.Fatal(err)
	}
	cliID, err := GenerateIdentity("agent")
	if err != nil {
		t.Fatal(err)
	}
	o.Identity = srvID
	if o.Check == nil {
		o.Check = PinEquals(cliID.Pin)
	}
	srv, err := NewServer(o)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &testEnv{srvID: srvID, cliID: cliID, addr: ln.Addr().String(), cancel: cancel, done: make(chan struct{})}
	go func() { defer close(e.done); srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-e.done:
		case <-time.After(30 * time.Second):
			t.Error("server did not shut down")
		}
	})
	return e
}

func (e *testEnv) dial(t *testing.T, alpn string) (*Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return Dial(ctx, e.addr, DialOptions{Identity: e.cliID, ServerPin: e.srvID.Pin, ALPN: alpn})
}

type memSource struct {
	mu  sync.Mutex
	evs []event.Event
}

func (m *memSource) add(n int, prio event.Priority) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := 0; i < n; i++ {
		last := uint64(len(m.evs))
		e := event.Event{Agent: "h1", Time: time.Unix(1700000000+int64(last), 0).UTC(), Kind: "test", Priority: prio,
			Fields: map[string]any{"i": float64(last + 1)}}
		prev := ""
		if last > 0 {
			prev = m.evs[last-1].Hash
		}
		if err := e.Seal(last, prev); err != nil {
			panic(err)
		}
		m.evs = append(m.evs, e)
	}
}

func (m *memSource) Events(after uint64, max int) ([]event.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if after >= uint64(len(m.evs)) {
		return nil, nil
	}
	end := min(int(after)+max, len(m.evs))
	return append([]event.Event(nil), m.evs[after:end]...), nil
}

func eventually(t *testing.T, d time.Duration, what string, f func() bool) {
	t.Helper()
	// d is the expected latency; a slow -race CI runner gets a generous floor.
	d = max(d, 30*time.Second)
	dl := time.Now().Add(d)
	for !f() {
		if time.Now().After(dl) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
