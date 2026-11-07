package controller

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/module"
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
	// Health is the per-module health blocks of the latest heartbeat.
	Health map[string]module.Health
	// ConfigState/ConfigEpoch/ConfigVersion are what the agent last reported
	// about its signed config ("none" until it applies one).
	ConfigState   string
	ConfigEpoch   uint64
	ConfigVersion uint64
	SafeMode      bool
	Drops         uint64
	Buffered      int
	// Bench figures (bench.go): accepted hellos, the controller time of the
	// last one, the head sequence of the last heartbeat and its RTT.
	Connects    uint64
	ConnectedAt time.Time
	HeadSeq     uint64
	RTT         time.Duration
}

type agentState struct {
	host string

	mu    sync.Mutex
	acked uint64
	// verify is set in hello when the agent's head still equals its restore
	// point: the restored controller asked for the whole spool, so events at
	// or below acked go through Ingest for the restore-point check.
	verify  bool
	buf     map[uint64]event.Event // out-of-order events waiting for their predecessors
	gapFrom map[uint64]uint64      // gap record "from" -> its Seq (the record covers from..Seq-1)
	sess    *agentConn
	// sessAddr is the remote IP of the live session; lastData is the last
	// heartbeat or event it sent; lastReuseAlert is when the stolen-key alert
	// for this host last rang (agent.go).
	sessAddr       string
	lastData       time.Time
	lastReuseAlert time.Time
	lastSeen       time.Time
	silent         bool
	hb             AgentStatus
	// bench bookkeeping (bench.go): accepted hellos, when the last one was,
	// and when the last session ended (0 while one is up).
	connects    uint64
	connectedAt time.Time
	downAt      time.Time
	// config push bookkeeping (agentconfig.go)
	cfgSess   *agentConn
	cfgSent   *link.Config
	cfgPushed time.Time
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
	st.Connects, st.ConnectedAt = s.connects, s.connectedAt
	return st, true
}

// agentConn is one live session of one agent.
type agentConn struct {
	c     *Controller
	conn  *link.Conn
	sess  *link.Session
	ready chan struct{}              // closed once hello was accepted
	stp   atomic.Pointer[agentState] // set by hello; read after Run without other synchronisation
	// reconciled is set once resume has compared the agent's dead-man report
	// with the running plans; no step is dispatched to the session before.
	reconciled atomic.Bool
	minor      int                 // protocol minor announced in hello
	dm         []link.DeadmanEntry // dead-man entries the agent reported in hello
	pub        *ecdsa.PublicKey    // the peer's key (its pin was matched at enrollment); verifies step results
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
			st.downAt = c.now()
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
	case *link.StepResult:
		a.c.onStepResult(a, st.host, v)
		return nil
	case *link.Chunk:
		// The transfer receiver is W11's. Until it lands, every chunk an
		// agent sends is a bulk transfer (fetch results); a refused chunk is
		// logged and dropped, and the sender retries it when space returns.
		if ok, code := a.c.admitChunk(event.PriorityBulk); !ok {
			a.c.log.Warn("chunk refused by quota", "host", st.host, "sha256", v.SHA256, "code", code)
		}
		return nil
	default:
		a.c.log.Debug("ignored message", "host", st.host, "type", m.MsgType().String())
		return nil
	}
}

// keyReuseFresh is how recently the old session must have sent a heartbeat or
// event for a second address to be a stolen key rather than a reconnect.
const keyReuseFresh = 10 * time.Second

func (a *agentConn) hello(ctx context.Context, h *link.Hello) error {
	c := a.c
	if h.Proto != link.ProtoVersion {
		return fmt.Errorf("unsupported protocol %d", h.Proto) // closed without welcome
	}
	pin := a.conn.Peer
	if pcs := a.conn.ConnectionState().PeerCertificates; len(pcs) > 0 {
		a.pub, _ = pcs[0].PublicKey.(*ecdsa.PublicKey)
	}
	a.minor, a.dm = h.Minor, h.Deadman
	res, err := c.enr.Authorize(ctx, h, pin)
	if err != nil {
		return err
	}
	// A restored controller fences on the epoch the fleet accepted before it
	// signs; this hello is that report (restorewait.go).
	if err := c.noteRestoreReport(ctx, h); err != nil {
		return err
	}
	// The watch sees every accepted connection, not the refused ones (those
	// alert in authorize); it checks the reported binary hash and withdraws
	// the host's bundle.
	c.enrollConnected(h.Host, h.BinarySHA256)
	st := c.state(h.Host)
	ag, err := c.st.Agent(ctx, h.Host)
	if err != nil {
		return err
	}
	now := c.now()
	addr := remoteIP(a.conn.RemoteAddr())
	st.mu.Lock()
	reuse := ""
	if old := st.sess; old != nil {
		recent := !st.lastData.IsZero() && now.Sub(st.lastData) <= keyReuseFresh
		if recent && st.sessAddr != "" && addr != st.sessAddr && (st.lastReuseAlert.IsZero() || now.Sub(st.lastReuseAlert) >= time.Minute) {
			st.lastReuseAlert = now
			reuse = fmt.Sprintf("second live session from %s, first from %s", addr, st.sessAddr)
		}
		old.sess.Close()
	}
	st.sess = a
	st.sessAddr = addr
	st.acked = ag.LastSeq
	st.verify = ag.RestoredSeq > 0 && ag.LastSeq == ag.RestoredSeq
	st.buf = map[uint64]event.Event{}
	st.gapFrom = map[uint64]uint64{}
	st.lastSeen = now
	st.connects++
	st.connectedAt = now
	c.bs.connects.Add(1)
	if !st.downAt.IsZero() {
		c.bs.down.Observe(now.Sub(st.downAt))
		st.downAt = time.Time{}
	}
	if st.silent {
		st.silent = false
		defer c.alert(h.Host, "agent.resumed", "agent reconnected")
	}
	st.mu.Unlock()
	if reuse != "" {
		c.enrollAlert(h.Host, event.ReasonKeyReuse, reuse)
	}
	a.stp.Store(st)
	welcome := &link.Welcome{Proto: link.ProtoVersion, Minor: link.ProtoMinor, Enrolled: res.Enrolled || res.Reenrolled}
	if wc, err := c.AgentConfigFor(ctx, h.Host); err != nil {
		// The agent keeps running its last good config; say why it got none.
		c.alert(h.Host, "config.generate_failed", err.Error())
	} else if wc != nil {
		welcome.Config = wc
		st.mu.Lock()
		st.cfgSess, st.cfgSent, st.cfgPushed = a, wc, c.now()
		st.mu.Unlock()
	}
	if err := a.sess.Send(ctx, link.PrioCritical, welcome); err != nil {
		return err
	}
	if err := c.enr.Announce(ctx, h.Host, pin, res); err != nil {
		c.log.Error("agent.announce", "host", h.Host, "err", err)
	}
	firstAck := ag.LastSeq
	if st.verify {
		// Ask for everything the spool still holds: a restored controller has
		// no events, and the run through the recorded point is verified.
		firstAck = 0
	}
	if err := a.sess.Send(ctx, link.PrioCritical, &link.Ack{Seq: firstAck}); err != nil {
		return err
	}
	close(a.ready)
	go c.resume(h.Host)
	c.log.Info("agent connected", "host", h.Host, "version", h.Version, "enrolled_now", res.Enrolled || res.Reenrolled, "acked", ag.LastSeq, "agent_last_seq", h.LastSeq)
	return nil
}

// remoteIP returns the IP part of a connection's remote address.
func remoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if a, ok := addr.(*net.TCPAddr); ok {
		return a.IP.String()
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}

func (a *agentConn) heartbeat(hb *link.Heartbeat) error {
	st := a.stp.Load()
	now := a.c.now()
	st.mu.Lock()
	st.lastData = now
	st.hb.ClockSkew = hb.HostClock.Sub(now)
	st.hb.SkewAt = now
	st.hb.SpoolDepth, st.hb.Congestion, st.hb.Modules = hb.SpoolDepth, hb.Congestion, hb.Modules
	st.hb.Health = hb.Health
	st.hb.SafeMode, st.hb.Drops = hb.SafeMode, hb.Drops
	st.hb.HeadSeq, st.hb.RTT = hb.Seq, time.Duration(hb.RTTUs)*time.Microsecond
	acked := st.acked
	if st.verify {
		// Nothing at or below the restore point is stored until the resend
		// reaches it, so do not acknowledge past the first ack (0) yet.
		acked = 0
	}
	st.mu.Unlock()
	a.sess.TrySend(link.PrioCritical, &link.Ack{Seq: acked, HB: hb.ID}) // keepalive and RTT echo; a full queue means a newer ack is coming
	a.c.noteConfigStatus(st, hb)
	return nil
}

func (a *agentConn) events(ctx context.Context, m *link.Events) error {
	c, st := a.c, a.stp.Load()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.sess != a {
		return errors.New("superseded by a newer session")
	}
	st.lastData = c.now()
	evs := m.Events
	if st.verify {
		// A resend after a restore starts at the oldest event the spool still
		// holds. Everything at or below the restore point goes back through
		// Ingest, which backfills it only when the run reaches the point with
		// the recorded hash; a resend that starts above the point leaves the
		// missing range to ResumeAfterRestore.
		i := 0
		for i < len(evs) && evs[i].Seq <= st.acked {
			i++
		}
		if i > 0 {
			if err := a.verifyResend(ctx, evs[:i]); err != nil {
				return err
			}
			if evs[i-1].Seq == st.acked {
				st.verify = false // the run reached the restore point and its hash
			}
			evs = evs[i:]
		}
		if len(evs) > 0 && evs[0].Seq > st.acked+1 && evs[0].Kind != store.KindGap {
			if err := c.st.ResumeAfterRestore(ctx, st.host, evs[0]); err != nil {
				c.alert(st.host, "store.chain_error", err.Error())
				return fmt.Errorf("ingest: %w", err)
			}
			st.acked = evs[0].Seq - 1
		}
	}
	for _, e := range evs {
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

// verifyResend passes a resend's events at or below the restore point to the
// store, in order, in MaxBatch-sized calls. The store carries the pending run
// across calls and stores it only when it reaches the snapshot's sequence with
// its hash; ErrRestoreMismatch then ends the session like any other chain
// error.
func (a *agentConn) verifyResend(ctx context.Context, evs []event.Event) error {
	c, st := a.c, a.stp.Load()
	for len(evs) > 0 {
		n := min(len(evs), store.MaxBatch)
		if _, err := c.st.Ingest(ctx, st.host, evs[:n]); err != nil {
			st.buf = map[uint64]event.Event{}
			st.gapFrom = map[uint64]uint64{}
			if errors.Is(err, event.ErrChain) {
				c.alert(st.host, "store.chain_error", err.Error())
			}
			return fmt.Errorf("ingest: %w", err)
		}
		evs = evs[n:]
	}
	return nil
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
			st.verify = false // the chain has moved past the restore point
			progressed = true
		}
		now := c.now()
		for _, e := range run {
			if e.Seq > ack.Seq {
				continue
			}
			if e.Kind == store.KindGap {
				c.bs.gap(e)
			} else {
				c.bs.stored(e, now, -st.hb.ClockSkew)
			}
		}
		c.captureObserve(ctx, run, ack.Seq) // controller-scope rules over network events (capture_ingest.go)
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

// RevokeAgent revokes host's current key and closes its live session.
func (c *Controller) RevokeAgent(ctx context.Context, host string) error {
	if err := c.enr.Revoke(ctx, host); err != nil {
		return err
	}
	c.disconnectAgent(host)
	return nil
}

// disconnectAgent closes host's live session, if any. The key is already
// revoked or about to be; the session table is the controller's side.
func (c *Controller) disconnectAgent(host string) {
	c.mu.Lock()
	s := c.agents[host]
	c.mu.Unlock()
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sess != nil {
		s.sess.sess.Close()
	}
}
