package winevt

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// ---- fake event log (the OS boundary) ----

func mkXML(channel string, rid uint64, id int) []byte {
	return []byte(fmt.Sprintf(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>`+
		`<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>%d</EventID><EventRecordID>%d</EventRecordID>`+
		`<TimeCreated SystemTime="2026-03-14T18:22:05.0000000Z"/><Channel>%s</Channel><Computer>H</Computer></System>`+
		`<EventData><Data Name="TargetUserName">u%d</Data><Data Name="LogonType">3</Data></EventData></Event>`, id, rid, channel, rid))
}

// fakeLog is an append-only per-channel log with the real semantics the
// pipeline depends on: bookmarks are positions, resume is "after bookmark".
type fakeLog struct {
	mu     sync.Mutex
	events map[string][][]byte // channel -> events; record id = index+1
	batch  int
	opens  map[string][]string // channel -> bookmark argument of each open
}

func newFakeLog(batch int) *fakeLog {
	return &fakeLog{events: map[string][][]byte{}, batch: batch, opens: map[string][]string{}}
}

func (l *fakeLog) add(ch string, id int, n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := 0; i < n; i++ {
		l.events[ch] = append(l.events[ch], mkXML(ch, uint64(len(l.events[ch])+1), id))
	}
}

func (l *fakeLog) open(_ context.Context, ch Channel, bookmark string, fromOldest bool) (Source, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.opens[ch.Name] = append(l.opens[ch.Name], bookmark)
	pos := 0
	switch {
	case bookmark != "":
		n, err := strconv.Atoi(strings.TrimPrefix(bookmark, "rid:"))
		if err != nil {
			return nil, ErrBookmarkStale
		}
		pos = n
	case !fromOldest:
		pos = len(l.events[ch.Name])
	}
	return &fakeSource{l: l, ch: ch.Name, pos: pos}, nil
}

type fakeSource struct {
	l   *fakeLog
	ch  string
	pos int
}

func (s *fakeSource) Close() error { return nil }
func (s *fakeSource) Next(ctx context.Context) (Batch, error) {
	for {
		if err := ctx.Err(); err != nil {
			return Batch{}, err
		}
		s.l.mu.Lock()
		evs := s.l.events[s.ch]
		if s.pos < len(evs) {
			end := min(s.pos+s.l.batch, len(evs))
			b := Batch{Events: evs[s.pos:end], Bookmark: "rid:" + strconv.Itoa(end)}
			s.pos = end
			s.l.mu.Unlock()
			return b, nil
		}
		s.l.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Millisecond):
		}
	}
}

// ---- collector ----

type sink struct {
	mu   sync.Mutex
	evs  []event.Event
	hook func(event.Event) error
}

func (s *sink) emit(e event.Event) error {
	if s.hook != nil {
		if err := s.hook(e); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.evs = append(s.evs, e)
	s.mu.Unlock()
	return nil
}

func (s *sink) snapshot() []event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]event.Event(nil), s.evs...)
}

func (s *sink) kinds(kind string) []event.Event {
	var out []event.Event
	for _, e := range s.snapshot() {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func noProbe([]string) (SysmonInfo, error) { return SysmonInfo{}, nil }

func never(time.Duration) <-chan time.Time { return nil }

func baseCfg(t *testing.T, l *fakeLog, chans ...Channel) Config {
	return Config{
		Channels: chans, BookmarkPath: filepath.Join(t.TempDir(), "bm.json"), Open: l.open, Probe: noProbe,
		QueueWait: 50 * time.Millisecond, GapFlushInterval: 5 * time.Millisecond, BookmarkSaveInterval: time.Millisecond,
		After: never, FromOldest: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func run(t *testing.T, m *Module, s *sink) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Start(ctx, s.emit) }()
	return func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Start returned %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("Start did not return after cancel")
		}
	}
}

// ---- tests ----

func TestModuleEmitsMappedEvents(t *testing.T) {
	l := newFakeLog(4)
	l.add(ChSecurity, 4624, 10)
	m, err := New(baseCfg(t, l, Channel{Name: ChSecurity}))
	if err != nil {
		t.Fatal(err)
	}
	s := &sink{}
	stop := run(t, m, s)
	waitFor(t, "10 events", func() bool { return len(s.kinds(KindAuthSuccess)) == 10 })
	stop()
	e := s.kinds(KindAuthSuccess)[3]
	if e.Fields["account"] != "u4" || e.Fields["record_id"] != uint64(4) || e.Fields["logon_type"] != 3 {
		t.Fatalf("%+v", e.Fields)
	}
	if st := m.Stats()[ChSecurity]; st.Emitted != 10 || st.Received != 10 || st.State != "ok" || st.LastRecordID != 10 {
		t.Fatalf("%+v", st)
	}
}

func TestRestartResumesWithoutLossOrDuplication(t *testing.T) {
	l := newFakeLog(5)
	l.add(ChSecurity, 4624, 60)
	cfg := baseCfg(t, l, Channel{Name: ChSecurity})
	cfg.QueueSize = 3 // keeps the reader close behind the consumer
	// Dropping on a full queue is by design (it is recorded as a telemetry
	// gap), but this test asserts zero loss, so a descheduled consumer on a
	// slow -race runner must not be able to trip the drop deadline.
	cfg.QueueWait = time.Minute

	// Run 1 is cancelled from inside emit after 17 events (mid-batch).
	m1, _ := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	first := &sink{}
	first.hook = func(event.Event) error {
		time.Sleep(time.Millisecond)
		if len(first.snapshot()) == 16 { // this emit is the 17th
			cancel()
		}
		return nil
	}
	if err := m1.Start(ctx, first.emit); err != nil {
		t.Fatal(err)
	}
	n1 := len(first.kinds(KindAuthSuccess))
	if n1 < 17 || n1 >= 60 {
		t.Fatalf("run 1 emitted %d", n1)
	}

	// Run 2 (a new Module reading the same bookmark file) finishes the log.
	l.add(ChSecurity, 4624, 10) // plus events logged while the agent was down
	m2, _ := New(cfg)
	second := &sink{}
	stop := run(t, m2, second)
	waitFor(t, "run 2", func() bool { return len(first.kinds(KindAuthSuccess))+len(second.kinds(KindAuthSuccess)) >= 70 })
	stop() // drains the queue; any duplicate would be emitted before Start returns
	if d := m1.Stats()[ChSecurity].QueueDropped + m2.Stats()[ChSecurity].QueueDropped; d != 0 {
		t.Fatalf("%d events dropped to queue backpressure", d)
	}

	seen := map[uint64]int{}
	for _, s := range []*sink{first, second} {
		for _, e := range s.kinds(KindAuthSuccess) {
			seen[e.Fields["record_id"].(uint64)]++
		}
	}
	if len(seen) != 70 {
		t.Fatalf("saw %d distinct records, want 70", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("record %d delivered %d times", id, n)
		}
	}
	if got := l.opens[ChSecurity]; len(got) != 2 || got[0] != "" || got[1] == "" {
		t.Fatalf("opens = %q", got)
	}
}

func TestFirstRunWithoutBookmarkStartsAtFutureEvents(t *testing.T) {
	l := newFakeLog(5)
	l.add(ChSecurity, 4624, 20) // history that must not be replayed
	cfg := baseCfg(t, l, Channel{Name: ChSecurity})
	cfg.FromOldest = false
	m, _ := New(cfg)
	s := &sink{}
	stop := run(t, m, s)
	waitFor(t, "open", func() bool { return m.Stats()[ChSecurity].State == "ok" })
	l.add(ChSecurity, 4624, 3)
	waitFor(t, "3 new", func() bool { return len(s.kinds(KindAuthSuccess)) == 3 })
	stop()
}

func TestFilteringAndMalformedXML(t *testing.T) {
	l := newFakeLog(100)
	l.add(ChSecurity, 4624, 3)
	l.add(ChSecurity, 9999, 4) // not in the include list
	l.mu.Lock()
	l.events[ChSecurity] = append(l.events[ChSecurity], []byte("<Event><System><EventID>46"), []byte("not xml at all"))
	l.mu.Unlock()
	l.add(ChSecurity, 4625, 1)
	m, _ := New(baseCfg(t, l, Channel{Name: ChSecurity, Include: []int{4624, 4625}}))
	s := &sink{}
	stop := run(t, m, s)
	waitFor(t, "events", func() bool { return len(s.kinds(KindAuthSuccess)) == 3 && len(s.kinds(KindAuthFail)) == 1 })
	waitFor(t, "parse gap", func() bool { return len(s.kinds("telemetry_gap")) >= 1 })
	stop()
	st := m.Stats()[ChSecurity]
	if st.Filtered != 4 || st.ParseErrors != 2 || st.Emitted != 4 {
		t.Fatalf("%+v", st)
	}
	g := s.kinds("telemetry_gap")[0]
	if g.Fields["reason"] != "parse_error" || g.Fields["count"] != uint64(2) || g.Fields["source"] != "winevt:Security" {
		t.Fatalf("%+v", g.Fields)
	}
}

func TestBackpressureRecordsTelemetryGap(t *testing.T) {
	l := newFakeLog(200)
	l.add(ChSecurity, 4624, 100)
	cfg := baseCfg(t, l, Channel{Name: ChSecurity})
	cfg.QueueSize = 4
	cfg.QueueWait = 5 * time.Millisecond
	m, _ := New(cfg)
	release := make(chan struct{})
	s := &sink{}
	s.hook = func(event.Event) error { <-release; return nil } // a slow consumer
	stop := run(t, m, s)
	waitFor(t, "queue drops", func() bool { return m.Stats()[ChSecurity].QueueDropped > 50 })
	close(release)
	waitFor(t, "gap event", func() bool {
		for _, g := range s.kinds("telemetry_gap") {
			if g.Fields["reason"] == "queue_full" {
				return true
			}
		}
		return false
	})
	waitFor(t, "drain", func() bool {
		return len(s.kinds(KindAuthSuccess)) > 0 && m.Stats()[ChSecurity].Emitted+m.Stats()[ChSecurity].QueueDropped == 100
	})
	stop()
	st := m.Stats()[ChSecurity]
	var gapCount uint64
	var g event.Event
	for _, x := range s.kinds("telemetry_gap") {
		if x.Fields["reason"] == "queue_full" {
			gapCount += x.Fields["count"].(uint64)
			g = x
		}
	}
	if gapCount != st.QueueDropped || st.Emitted+st.QueueDropped != 100 {
		t.Fatalf("gap %d dropped %d emitted %d", gapCount, st.QueueDropped, st.Emitted)
	}
	if g.Fields["from_record"] == nil || g.Fields["to_record"] == nil {
		t.Fatalf("gap lacks record range: %+v", g.Fields)
	}
}

func TestEmitRefusalIsCountedAsGap(t *testing.T) {
	l := newFakeLog(10)
	l.add(ChSecurity, 4624, 10)
	m, _ := New(baseCfg(t, l, Channel{Name: ChSecurity}))
	s := &sink{}
	s.hook = func(e event.Event) error {
		if e.Kind == KindAuthSuccess && e.Fields["record_id"].(uint64)%2 == 0 {
			return fmt.Errorf("spool full")
		}
		return nil
	}
	stop := run(t, m, s)
	waitFor(t, "gap", func() bool {
		for _, g := range s.kinds("telemetry_gap") {
			if g.Fields["reason"] == "emit_refused" && g.Fields["count"] == uint64(5) {
				return true
			}
		}
		return false
	})
	stop()
	if st := m.Stats()[ChSecurity]; st.EmitDropped != 5 || st.Emitted != 5 {
		t.Fatalf("%+v", st)
	}
}

func TestStaleBookmarkResubscribesFromOldest(t *testing.T) {
	l := newFakeLog(10)
	l.add(ChSecurity, 4624, 5)
	cfg := baseCfg(t, l, Channel{Name: ChSecurity})
	// A bookmark the log cannot honour (e.g. the log was cleared).
	if err := os.WriteFile(cfg.BookmarkPath, []byte(`{"version":1,"bookmarks":{"Security":"garbage"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m, _ := New(cfg)
	s := &sink{}
	stop := run(t, m, s)
	waitFor(t, "recovery", func() bool { return len(s.kinds(KindAuthSuccess)) == 5 })
	stop()
	var found bool
	for _, g := range s.kinds("telemetry_gap") {
		found = found || g.Fields["reason"] == "bookmark_stale"
	}
	if !found {
		t.Fatal("no bookmark_stale gap")
	}
	if got := l.opens[ChSecurity]; len(got) != 2 || got[0] != "garbage" || got[1] != "" {
		t.Fatalf("opens = %q", got)
	}
	if st := m.Stats()[ChSecurity]; st.Resets != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestMissingChannelRetriesAndSucceeds(t *testing.T) {
	l := newFakeLog(10)
	var mu sync.Mutex
	attempts := 0
	cfg := baseCfg(t, l, Channel{Name: ChSecurity, Include: []int{4624}})
	cfg.After = func(time.Duration) <-chan time.Time { return time.After(time.Millisecond) }
	cfg.Open = func(ctx context.Context, ch Channel, bm string, o bool) (Source, error) {
		mu.Lock()
		attempts++
		a := attempts
		mu.Unlock()
		if a <= 3 {
			return nil, fmt.Errorf("%w: Sysmon not installed yet", ErrChannelNotFound)
		}
		return l.open(ctx, ch, bm, o)
	}
	cfg.Probe = func([]string) (SysmonInfo, error) { return SysmonInfo{}, nil }
	m, _ := New(cfg)
	s := &sink{}
	stop := run(t, m, s)
	waitFor(t, "channel ok", func() bool { return m.Stats()[ChSecurity].State == "ok" })
	l.add(ChSecurity, 4624, 2)
	waitFor(t, "events", func() bool { return len(s.kinds(KindAuthSuccess)) == 2 })
	stop()
	n := 0
	for _, g := range s.kinds("telemetry_gap") {
		if g.Fields["reason"] == "channel_unavailable" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("channel_unavailable gaps = %d, want exactly 1 per outage", n)
	}
}

func TestSysmonSensorStateAnd4688Fallback(t *testing.T) {
	l := newFakeLog(10)
	var mu sync.Mutex
	info := SysmonInfo{}
	cfg := baseCfg(t, l, Channel{Name: ChSecurity, Include: []int{4688}})
	cfg.Probe = func([]string) (SysmonInfo, error) { mu.Lock(); defer mu.Unlock(); return info, nil }
	tick := make(chan time.Time)
	cfg.After = func(time.Duration) <-chan time.Time { return tick }
	m, _ := New(cfg)
	s := &sink{}
	stop := run(t, m, s)
	waitFor(t, "first sensor_state", func() bool { return len(s.kinds("sensor_state")) == 1 })
	if e := s.kinds("sensor_state")[0]; e.Fields["fallback"] != "4688" || e.Fields["present"] != false {
		t.Fatalf("%+v", e.Fields)
	}
	if !m.use4688() {
		t.Fatal("fallback must be on without Sysmon")
	}
	// Sysmon appears (renamed): the fallback turns off and the change is reported.
	mu.Lock()
	info = SysmonInfo{Present: true, Running: true, DriverRunning: true, ServiceName: "WinHelper", DriverName: "WinDrv", Renamed: true}
	mu.Unlock()
	tick <- time.Now()
	waitFor(t, "second sensor_state", func() bool { return len(s.kinds("sensor_state")) == 2 })
	e := s.kinds("sensor_state")[1]
	if e.Fields["fallback"] != "" || e.Fields["renamed"] != true || e.Fields["service_name"] != "WinHelper" ||
		e.Fields["expected_config_hash"] != SysmonConfigSHA256() {
		t.Fatalf("%+v", e.Fields)
	}
	if m.use4688() || !m.Sysmon().Healthy() {
		t.Fatal("fallback must be off while Sysmon runs")
	}
	// An unchanged probe emits nothing new.
	tick <- time.Now()
	time.Sleep(20 * time.Millisecond)
	if n := len(s.kinds("sensor_state")); n != 2 {
		t.Fatalf("sensor_state emitted %d times", n)
	}
	// 4688 records are now suppressed (Sysmon 1 is the source of truth).
	l.mu.Lock()
	l.events[ChSecurity] = append(l.events[ChSecurity], mk4688(1))
	l.mu.Unlock()
	waitFor(t, "record seen", func() bool { return m.Stats()[ChSecurity].Received == 1 })
	time.Sleep(20 * time.Millisecond)
	if n := len(s.kinds(KindProcessStart)); n != 0 {
		t.Fatalf("4688 produced %d process_start events while Sysmon is healthy", n)
	}
	// Sysmon stops: the fallback comes back.
	mu.Lock()
	info.Running = false
	mu.Unlock()
	tick <- time.Now()
	waitFor(t, "fallback back", m.use4688)
	l.mu.Lock()
	l.events[ChSecurity] = append(l.events[ChSecurity], mk4688(2))
	l.mu.Unlock()
	waitFor(t, "4688 process_start", func() bool { return len(s.kinds(KindProcessStart)) == 1 })
	stop()
}

func mk4688(rid uint64) []byte {
	return []byte(fmt.Sprintf(`<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID>`+
		`<EventRecordID>%d</EventRecordID><Channel>Security</Channel><Computer>H</Computer></System><EventData>`+
		`<Data Name="NewProcessName">C:\x\a.exe</Data><Data Name="NewProcessId">0x10</Data><Data Name="ProcessId">0x4</Data>`+
		`<Data Name="SubjectUserName">bob</Data><Data Name="SubjectDomainName">D</Data></EventData></Event>`, rid))
}

func TestCorruptBookmarkFileReportsGapAndContinues(t *testing.T) {
	l := newFakeLog(10)
	l.add(ChSecurity, 4624, 3)
	cfg := baseCfg(t, l, Channel{Name: ChSecurity})
	_ = os.WriteFile(cfg.BookmarkPath, []byte("\x00\x01 not json"), 0o600)
	m, _ := New(cfg)
	s := &sink{}
	stop := run(t, m, s)
	waitFor(t, "events", func() bool { return len(s.kinds(KindAuthSuccess)) == 3 })
	stop()
	var found bool
	for _, g := range s.kinds("telemetry_gap") {
		found = found || g.Fields["reason"] == "bookmark_file_corrupt"
	}
	if !found {
		t.Fatal("corrupt bookmark file not reported")
	}
}

func TestSourceErrorRetriesWithoutKillingOtherChannels(t *testing.T) {
	l := newFakeLog(10)
	l.add(ChSecurity, 4624, 4)
	cfg := baseCfg(t, l, Channel{Name: ChSecurity}, Channel{Name: ChSystem, Include: []int{7045}})
	cfg.After = func(time.Duration) <-chan time.Time { return time.After(time.Millisecond) }
	var n int
	var mu sync.Mutex
	cfg.Open = func(ctx context.Context, ch Channel, bm string, o bool) (Source, error) {
		if ch.Name == ChSystem {
			mu.Lock()
			n++
			mu.Unlock()
			return nil, fmt.Errorf("access denied")
		}
		return l.open(ctx, ch, bm, o)
	}
	cfg.Probe = func([]string) (SysmonInfo, error) { time.Sleep(time.Millisecond); return SysmonInfo{}, nil }
	m, _ := New(cfg)
	s := &sink{}
	stop := run(t, m, s)
	waitFor(t, "security", func() bool { return len(s.kinds(KindAuthSuccess)) == 4 })
	waitFor(t, "retries", func() bool { mu.Lock(); defer mu.Unlock(); return n >= 3 })
	stop()
	if st := m.Stats()[ChSystem]; st.State != "error" || st.LastError != "access denied" {
		t.Fatalf("%+v", st)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("BookmarkPath required")
	}
	p := filepath.Join(t.TempDir(), "b")
	if _, err := New(Config{BookmarkPath: p, Channels: []Channel{{Name: "Nope/Unknown"}}}); err == nil {
		t.Fatal("unknown channel without ids must fail")
	}
	if _, err := New(Config{BookmarkPath: p, Channels: []Channel{{Name: ChSecurity}, {Name: ChSecurity}}}); err == nil {
		t.Fatal("duplicate channel must fail")
	}
	m, err := New(Config{BookmarkPath: p})
	if err != nil || m.Name() != "winevt" || len(m.chans) != 7 {
		t.Fatal(err)
	}
}
