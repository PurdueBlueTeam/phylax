package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// AgentStatus is a snapshot of what the controller knows about a live agent.
type AgentStatus struct {
	Host       string
	Connected  bool
	Acked      uint64
	LastSeen   time.Time
	Silent     bool
	ClockSkew  time.Duration // agent clock minus controller clock at the last heartbeat
	SkewAt     time.Time
	SpoolDepth uint64
	Congestion string
	Modules    map[string]string
	SafeMode   bool
	Drops      uint64
	Buffered   int
}

type agentState struct {
	host string

	mu       sync.Mutex
	acked    uint64
	buf      map[uint64]event.Event // out-of-order events waiting for their predecessors
	gapFrom  map[uint64]uint64      // gap record "from" -> its Seq (the record covers from..Seq-1)
	sess     *agentConn
	lastSeen time.Time
	silent   bool
	hb       AgentStatus
}

// stateLocked returns the state for host, creating it. Caller must hold c.mu
// or be single-threaded (New).
func (c *Controller) stateLocked(host string) *agentState {
	s, ok := c.agents[host]
	if !ok {
		s = &agentState{host: host, buf: map[uint64]event.Event{}, gapFrom: map[uint64]uint64{}}
		c.agents[host] = s
	}
	return s
}

func (c *Controller) state(host string) *agentState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stateLocked(host)
}

// AgentStatus reports on one agent.
func (c *Controller) AgentStatus(host string) (AgentStatus, bool) {
	c.mu.Lock()
	s, ok := c.agents[host]
	c.mu.Unlock()
	if !ok {
		return AgentStatus{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.hb
	st.Host, st.Connected, st.Acked, st.LastSeen, st.Silent, st.Buffered = host, s.sess != nil, s.acked, s.lastSeen, s.silent, len(s.buf)
	return st, true
}

// agentConn is one live session of one agent.
type agentConn struct {
	c     *Controller
	conn  *link.Conn
	sess  *link.Session
	ready chan struct{}              // closed once hello was accepted
	stp   atomic.Pointer[agentState] // set by hello; read after Run without other synchronisation
}

func (c *Controller) handleAgent(ctx context.Context, conn *link.Conn) {
	a := &agentConn{c: c, conn: conn, ready: make(chan struct{})}
	a.sess = link.NewSession(conn, link.Options{
		Role:     link.RoleController,
		Handler:  a.handle,
		ReadIdle: time.Duration(c.cfg.ReadIdle),
	})
	t := time.AfterFunc(time.Duration(c.cfg.HelloTimeout), func() {
		select {
		case <-a.ready:
		default:
			a.sess.Close()
		}
	})
	err := a.sess.Run(ctx)
	t.Stop()
	if st := a.stp.Load(); st != nil {
		st.mu.Lock()
		if st.sess == a {
			st.sess = nil
			st.buf = map[uint64]event.Event{}
			st.gapFrom = map[uint64]uint64{}
		}
		st.mu.Unlock()
		c.log.Info("agent session ended", "host", st.host, "err", err)
	} else {
		c.log.Info("session ended before hello", "pin", conn.Peer.String(), "err", err)
	}
}

func (a *agentConn) handle(ctx context.Context, m link.Message) error {
	if h, ok := m.(*link.Hello); ok {
		select {
		case <-a.ready:
			return errors.New("duplicate hello")
		default:
		}
		return a.hello(ctx, h)
	}
	select {
	case <-a.ready:
	case <-ctx.Done():
		return ctx.Err()
	case <-a.sess.Done():
		return a.sess.Err()
	}
	st := a.stp.Load()
	st.mu.Lock()
	if st.sess != a {
		st.mu.Unlock()
		return errors.New("superseded by a newer session")
	}
	st.lastSeen = a.c.now()
	resumed := st.silent
	st.silent = false
	st.mu.Unlock()
	if resumed {
		a.c.alert(st.host, "agent.resumed", "agent is sending again")
	}
	switch v := m.(type) {
	case *link.Heartbeat:
		return a.heartbeat(v)
	case *link.Events:
		return a.events(ctx, v)
	default:
		// step_result, chunk, chunk_have: handled by later milestones.
		a.c.log.Debug("ignored message", "host", st.host, "type", m.MsgType().String())
		return nil
	}
}

func (a *agentConn) hello(ctx context.Context, h *link.Hello) error {
	c := a.c
	if h.Proto != link.ProtoVersion {
		return fmt.Errorf("unsupported protocol %d", h.Proto) // closed without welcome
	}
	pin := a.conn.Peer
	enrolled, err := c.authorize(ctx, h, pin)
	if err != nil {
		return err
	}
	st := c.state(h.Host)
	ag, err := c.st.Agent(ctx, h.Host)
	if err != nil {
		return err
	}
	st.mu.Lock()
	if old := st.sess; old != nil {
		old.sess.Close()
	}
	st.sess = a
	st.acked = ag.LastSeq
	st.buf = map[uint64]event.Event{}
	st.gapFrom = map[uint64]uint64{}
	st.lastSeen = c.now()
	if st.silent {
		st.silent = false
		defer c.alert(h.Host, "agent.resumed", "agent reconnected")
	}
	st.mu.Unlock()
	a.stp.Store(st)
	if err := a.sess.Send(ctx, link.PrioCritical, &link.Welcome{Proto: link.ProtoVersion, Enrolled: enrolled}); err != nil {
		return err
	}
	if err := a.sess.Send(ctx, link.PrioCritical, &link.Ack{Seq: ag.LastSeq}); err != nil {
		return err
	}
	close(a.ready)
	c.log.Info("agent connected", "host", h.Host, "version", h.Version, "enrolled_now", enrolled, "acked", ag.LastSeq, "agent_last_seq", h.LastSeq)
	return nil
}

// authorize decides whether pin may act as h.Host. It returns whether this
// call enrolled the key.
func (c *Controller) authorize(ctx context.Context, h *link.Hello, pin link.Pin) (bool, error) {
	c.enrMu.Lock()
	defer c.enrMu.Unlock()
	refuse := func(kind string, err error) (bool, error) {
		c.alert(h.Host, kind, fmt.Sprintf("pin %s: %v", pin, err))
		return false, err
	}
	ag, err := c.st.Agent(ctx, h.Host)
	switch {
	case err == nil:
		if string(ag.PubKey) != string(pin[:]) {
			// A new key claiming an existing host is always an alert; tokens
			// cannot override it (operator-approved re-enrollment only).
			return refuse("enroll.key_mismatch", store.ErrKeyMismatch)
		}
		return false, nil
	case !errors.Is(err, store.ErrUnknownAgent):
		return false, err
	}
	// Unknown host: needs a valid token bound to this host.
	if h.Token == "" {
		return refuse("enroll.refused", errors.New("unknown host without token"))
	}
	all, err := c.st.Agents(ctx)
	if err != nil {
		return false, err
	}
	for _, o := range all {
		if string(o.PubKey) == string(pin[:]) {
			return refuse("enroll.key_reuse", fmt.Errorf("key already enrolled as %q", o.ID))
		}
	}
	if err := c.tok.Consume(h.Token, h.Host, pin); err != nil {
		return refuse("enroll.refused", err)
	}
	if err := c.st.EnrollAgent(ctx, h.Host, pin[:]); err != nil {
		return false, err
	}
	return true, nil
}

func (a *agentConn) heartbeat(hb *link.Heartbeat) error {
	st := a.stp.Load()
	now := a.c.now()
	st.mu.Lock()
	st.hb.ClockSkew = hb.HostClock.Sub(now)
	st.hb.SkewAt = now
	st.hb.SpoolDepth, st.hb.Congestion, st.hb.Modules = hb.SpoolDepth, hb.Congestion, hb.Modules
	st.hb.SafeMode, st.hb.Drops = hb.SafeMode, hb.Drops
	acked := st.acked
	st.mu.Unlock()
	a.sess.TrySend(link.PrioCritical, &link.Ack{Seq: acked}) // keepalive; a full queue means a newer ack is coming
	return nil
}

func (a *agentConn) events(ctx context.Context, m *link.Events) error {
	c, st := a.c, a.stp.Load()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.sess != a {
		return errors.New("superseded by a newer session")
	}
	for _, e := range m.Events {
		if e.Agent != st.host {
			return fmt.Errorf("event for agent %q on session of %q", e.Agent, st.host)
		}
		if e.Seq <= st.acked {
			continue // already stored (resend after reconnect)
		}
		key := e.Seq
		if e.Kind == store.KindGap {
			from, ok := gapFrom(e)
			if !ok || from > e.Seq || from <= st.acked {
				c.alert(st.host, "store.chain_error", fmt.Sprintf("malformed gap record seq %d", e.Seq))
				return errors.New("malformed gap record")
			}
			if from-st.acked > c.cfg.ReorderWindow {
				return link.ErrWindow
			}
			st.gapFrom[from] = e.Seq
		} else if e.Seq-st.acked > c.cfg.ReorderWindow {
			return fmt.Errorf("%w: %d (acked %d)", link.ErrWindow, e.Seq, st.acked)
		}
		if _, dup := st.buf[key]; !dup {
			if len(st.buf) >= c.cfg.MaxBufferedEvents {
				return fmt.Errorf("reorder buffer full (%d events)", len(st.buf))
			}
			st.buf[key] = e
		}
	}
	return a.drain(ctx)
}

// drain stores every event that is now contiguous with the ack point, then
// acks. Caller holds st.mu.
func (a *agentConn) drain(ctx context.Context) error {
	c, st := a.c, a.stp.Load()
	progressed := false
	defer func() {
		if progressed {
			a.sess.TrySend(link.PrioCritical, &link.Ack{Seq: st.acked})
		}
	}()
	for {
		var run []event.Event
		cur := st.acked
		for len(run) < store.MaxBatch {
			if e, ok := st.buf[cur+1]; ok && e.Kind != store.KindGap {
				run = append(run, e)
				cur = e.Seq
			} else if gs, ok := st.gapFrom[cur+1]; ok {
				run = append(run, st.buf[gs])
				cur = gs
			} else {
				break
			}
		}
		if len(run) == 0 {
			return nil
		}
		ack, err := c.st.Ingest(ctx, st.host, run)
		if ack.Seq > st.acked {
			for s := st.acked + 1; s <= ack.Seq; s++ {
				delete(st.buf, s)
				delete(st.gapFrom, s)
			}
			st.acked = ack.Seq
			progressed = true
		}
		if err != nil {
			st.buf = map[uint64]event.Event{}
			st.gapFrom = map[uint64]uint64{}
			if errors.Is(err, event.ErrChain) {
				// Evidence of tampering or an agent bug: alert, end this
				// session, keep everything already stored. Never crash.
				c.alert(st.host, "store.chain_error", err.Error())
			}
			return fmt.Errorf("ingest: %w", err)
		}
		if len(run) < store.MaxBatch {
			return nil
		}
	}
}

func gapFrom(e event.Event) (uint64, bool) {
	switch v := e.Fields["from"].(type) {
	case float64:
		return uint64(v), v >= 1 && v == float64(uint64(v))
	case uint64:
		return v, v >= 1
	case int:
		return uint64(v), v >= 1
	}
	return 0, false
}

// watchSilence raises agent.silent when an enrolled agent has not been heard
// from for SilenceThreshold.
func (c *Controller) watchSilence(ctx context.Context) {
	th := time.Duration(c.cfg.SilenceThreshold)
	t := time.NewTicker(max(th/4, 10*time.Millisecond))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c.mu.Lock()
		states := make([]*agentState, 0, len(c.agents))
		for _, s := range c.agents {
			states = append(states, s)
		}
		c.mu.Unlock()
		now := c.now()
		for _, s := range states {
			s.mu.Lock()
			fire := !s.silent && now.Sub(s.lastSeen) > th
			if fire {
				s.silent = true
			}
			since := now.Sub(s.lastSeen)
			s.mu.Unlock()
			if fire {
				c.alert(s.host, "agent.silent", fmt.Sprintf("no message for %s", since.Round(time.Millisecond)))
			}
		}
	}
}
