package link

import (
	"context"
	"testing"
	"time"
)

// rttServer starts a real server whose session echoes heartbeats the way the
// controller does: an ack carrying the heartbeat's id, after a delay. Received
// heartbeats and the server session are handed to the test.
func rttServer(t *testing.T, delay time.Duration, echo func(*Heartbeat) bool) (*testEnv, <-chan *Heartbeat, <-chan *Session) {
	t.Helper()
	got := make(chan *Heartbeat, 16)
	sessions := make(chan *Session, 1)
	e := startServer(t, ServerOptions{Handlers: map[string]Handler{ALPNAgent: func(ctx context.Context, c *Conn) {
		var s *Session
		s = NewSession(c, Options{Role: RoleController, Handler: func(ctx context.Context, m Message) error {
			hb, ok := m.(*Heartbeat)
			if !ok {
				return nil
			}
			got <- hb
			if echo != nil && !echo(hb) {
				return nil
			}
			time.Sleep(delay)
			s.TrySend(PrioCritical, &Ack{Seq: 0, HB: hb.ID}) // full queue: a newer ack follows
			return nil
		}})
		sessions <- s
		s.Run(ctx)
	}}})
	t.Cleanup(func() { time.Sleep(10 * time.Millisecond) })
	return e, got, sessions
}

// rttClient dials the server and runs a real agent-role session on it.
func rttClient(t *testing.T, e *testEnv) *Session {
	t.Helper()
	c, err := e.dial(t, ALPNAgent)
	if err != nil {
		t.Fatal(err)
	}
	s := NewSession(c, Options{Role: RoleAgent})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Run(ctx)
	return s
}

func waitHeartbeat(t *testing.T, got <-chan *Heartbeat) *Heartbeat {
	t.Helper()
	select {
	case hb := <-got:
		return hb
	case <-time.After(10 * time.Second):
		t.Fatal("heartbeat did not arrive")
		return nil
	}
}

func TestHeartbeatRTT(t *testing.T) {
	e, got, _ := rttServer(t, 20*time.Millisecond, nil)
	client := rttClient(t, e)
	if err := client.TrySend(PrioCritical, &Heartbeat{Seq: 1, HostClock: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if hb := waitHeartbeat(t, got); hb.ID != 1 {
		t.Fatalf("first heartbeat id %d", hb.ID)
	}
	eventually(t, 2*time.Second, "the echoed heartbeat to set the RTT", func() bool {
		r := client.RTT()
		return r >= 20*time.Millisecond && r < time.Second
	})
	// The next heartbeat carries the measured round trip for the controller.
	if err := client.TrySend(PrioCritical, &Heartbeat{Seq: 2, HostClock: time.Now()}); err != nil {
		t.Fatal(err)
	}
	hb := waitHeartbeat(t, got)
	if hb.ID != 2 {
		t.Fatalf("second heartbeat id %d", hb.ID)
	}
	if hb.RTTUs < 20000 {
		t.Fatalf("second heartbeat rtt_us %d, want at least 20000", hb.RTTUs)
	}
}

func TestStaleEchoIgnored(t *testing.T) {
	e, got, sessions := rttServer(t, 0, func(hb *Heartbeat) bool { return false })
	client := rttClient(t, e)
	var srv *Session
	select {
	case srv = <-sessions:
	case <-time.After(10 * time.Second):
		t.Fatal("server session did not start")
	}
	// Two heartbeats go out, so the client is waiting for the echo of ID 2.
	if err := client.TrySend(PrioCritical, &Heartbeat{Seq: 1, HostClock: time.Now()}); err != nil {
		t.Fatal(err)
	}
	waitHeartbeat(t, got)
	if err := client.TrySend(PrioCritical, &Heartbeat{Seq: 2, HostClock: time.Now()}); err != nil {
		t.Fatal(err)
	}
	waitHeartbeat(t, got)
	// A late echo of the superseded heartbeat must not be mistaken for the trip
	// time of the current one.
	srv.TrySend(PrioCritical, &Ack{Seq: 0, HB: 1})
	time.Sleep(100 * time.Millisecond)
	if r := client.RTT(); r != 0 {
		t.Fatalf("stale echo set the RTT to %s", r)
	}
}

func TestHeartbeatNewFieldsAreOptional(t *testing.T) {
	m, err := Unmarshal(TypeHeartbeat, []byte(`{"seq":1,"host_clock":"2026-11-06T00:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	if hb := m.(*Heartbeat); hb.ID != 0 || hb.RTTUs != 0 {
		t.Fatalf("%+v", hb)
	}
	am, err := Unmarshal(TypeAck, []byte(`{"seq":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if a := am.(*Ack); a.HB != 0 {
		t.Fatalf("%+v", a)
	}
	// Receivers ignore unknown fields within a protocol version.
	if _, err := Unmarshal(TypeHeartbeat, []byte(`{"seq":1,"host_clock":"2026-11-06T00:00:00Z","from_the_future":true}`)); err != nil {
		t.Fatalf("unknown field rejected: %v", err)
	}
}
