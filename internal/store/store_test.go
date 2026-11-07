package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

var t0 = time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC)

// chain builds sealed events for one agent.
type chain struct {
	agent string
	seq   uint64
	hash  string
}

func (c *chain) next(kind string, fields map[string]any) event.Event {
	e := event.Event{Agent: c.agent, Time: t0.Add(time.Duration(c.seq) * time.Second), Kind: kind, Fields: fields}
	if err := e.Seal(c.seq, c.hash); err != nil {
		panic(err)
	}
	c.seq, c.hash = e.Seq, e.Hash
	return e
}

func (c *chain) many(n int, kind string) []event.Event {
	out := make([]event.Event, n)
	for i := range out {
		out[i] = c.next(kind, map[string]any{"i": i, "name": "x"})
	}
	return out
}

// shed simulates a spool shedding count events then appending a gap record.
func (c *chain) shed(count uint64, class string) event.Event {
	from := c.seq + 1
	to := c.seq + count
	e := event.Event{Agent: c.agent, Time: t0.Add(time.Hour), Kind: KindGap,
		Fields: map[string]any{"from": from, "to": to, "count": count, "class": class}}
	if err := e.Seal(to, c.hash); err != nil {
		panic(err)
	}
	c.seq, c.hash = e.Seq, e.Hash
	return e
}

func open(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "phylax.db")
	s, err := Open(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, p
}

func enroll(t *testing.T, s *Store, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if err := s.EnrollAgent(context.Background(), id, []byte("key-"+id)); err != nil {
			t.Fatal(err)
		}
	}
}

func wantReason(t *testing.T, err, reason error) {
	t.Helper()
	var ce *ChainError
	if !errors.As(err, &ce) || !errors.Is(err, reason) || !errors.Is(err, event.ErrChain) {
		t.Fatalf("want chain error %v, got %v", reason, err)
	}
}

func TestMigrationsAndTables(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	v, _ := s.SchemaVersion(ctx)
	if v != len(migrations) {
		t.Fatalf("version %d", v)
	}
	for _, tb := range []string{"agents", "events", "alerts", "plans", "plan_steps", "checks", "incidents", "chains", "hops", "devices", "credentials"} {
		var n int
		if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+tb).Scan(&n); err != nil {
			t.Errorf("table %s: %v", tb, err)
		}
	}
	// credentials hold metadata only: no column may look like a secret.
	rows, _ := s.r.QueryContext(ctx, `SELECT name FROM pragma_table_info('credentials')`)
	defer rows.Close()
	for rows.Next() {
		var n string
		rows.Scan(&n)
		switch n {
		case "secret", "password", "value", "hash":
			t.Errorf("credentials has secret-looking column %q", n)
		}
	}
	var mode string
	s.r.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode)
	if mode != "wal" {
		t.Errorf("journal mode %s", mode)
	}
}

func TestEnroll(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	enroll(t, s, "web")
	enroll(t, s, "web") // same key, no-op
	if err := s.EnrollAgent(ctx, "web", []byte("other")); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("got %v", err)
	}
	if _, err := s.Ingest(ctx, "ghost", nil); !errors.Is(err, ErrUnknownAgent) {
		t.Fatalf("got %v", err)
	}
}

func TestChainAcceptAndReject(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	enroll(t, s, "a")
	c := &chain{agent: "a"}
	evs := c.many(5, "proc")
	ack, err := s.Ingest(ctx, "a", evs[:3])
	if err != nil || ack.Seq != 3 || ack.Accepted != 3 || ack.Hash != evs[2].Hash {
		t.Fatalf("ack %+v err %v", ack, err)
	}

	// out of order: skip seq 4
	_, err = s.Ingest(ctx, "a", evs[4:5])
	wantReason(t, err, ErrOutOfOrder)

	// mismatched prev hash
	bad := evs[3]
	bad.PrevHash = "deadbeef"
	_, err = s.Ingest(ctx, "a", []event.Event{bad})
	wantReason(t, err, ErrPrevMismatch)

	// bad hash (tampered body)
	bad = evs[3]
	bad.Kind = "tampered"
	_, err = s.Ingest(ctx, "a", []event.Event{bad})
	wantReason(t, err, ErrBadHash)

	// wrong agent
	bad = evs[3]
	bad.Agent = "b"
	_, err = s.Ingest(ctx, "a", []event.Event{bad})
	wantReason(t, err, ErrBadEvent)

	// nothing was stored by the rejects
	if a, _ := s.Agent(ctx, "a"); a.LastSeq != 3 {
		t.Fatalf("ack moved: %d", a.LastSeq)
	}

	// prefix commit: good 4, then corrupt 5
	bad5 := evs[4]
	bad5.Hash = "00"
	ack, err = s.Ingest(ctx, "a", []event.Event{evs[3], bad5})
	wantReason(t, err, ErrBadHash)
	if ack.Seq != 4 || ack.Accepted != 1 {
		t.Fatalf("prefix ack %+v", ack)
	}
	if _, err := s.Ingest(ctx, "a", evs[4:]); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Count(ctx, "a"); n != 5 {
		t.Fatalf("count %d", n)
	}
}

func TestBatchBound(t *testing.T) {
	s, _ := open(t)
	enroll(t, s, "a")
	c := &chain{agent: "a"}
	evs := c.many(MaxBatch+1, "k")
	if _, err := s.Ingest(context.Background(), "a", evs); !errors.Is(err, ErrBatchTooBig) {
		t.Fatalf("got %v", err)
	}
	if ack, err := s.Ingest(context.Background(), "a", evs[:MaxBatch]); err != nil || ack.Seq != MaxBatch {
		t.Fatalf("%+v %v", ack, err)
	}
}

func TestIdempotentResend(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	enroll(t, s, "a")
	c := &chain{agent: "a"}
	evs := c.many(10, "k")
	if _, err := s.Ingest(ctx, "a", evs[:6]); err != nil {
		t.Fatal(err)
	}
	// reconnect: agent resends from its last unacked point, overlapping.
	ack, err := s.Ingest(ctx, "a", evs[2:])
	if err != nil || ack.Duplicates != 4 || ack.Accepted != 4 || ack.Seq != 10 {
		t.Fatalf("%+v %v", ack, err)
	}
	// full replay is all duplicates
	ack, err = s.Ingest(ctx, "a", evs)
	if err != nil || ack.Duplicates != 10 || ack.Accepted != 0 {
		t.Fatalf("%+v %v", ack, err)
	}
	if n, _ := s.Count(ctx, "a"); n != 10 {
		t.Fatalf("count %d", n)
	}
	// An attacker re-signs seq 3 with different content: acknowledged events
	// cannot be rewritten.
	forged := evs[2]
	forged.Fields = map[string]any{"i": 99}
	forged.Hash, _ = forged.ComputeHash()
	_, err = s.Ingest(ctx, "a", []event.Event{forged})
	wantReason(t, err, ErrRewrite)
	got, _ := s.Event(ctx, "a", 3)
	if got.Hash != evs[2].Hash {
		t.Fatal("stored event changed")
	}
}

func TestGapRecord(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	enroll(t, s, "a")
	c := &chain{agent: "a"}
	evs := c.many(3, "k")
	gap := c.shed(50, "flows")
	after := c.many(2, "k")
	all := append(append(evs, gap), after...)
	ack, err := s.Ingest(ctx, "a", all)
	if err != nil || ack.Seq != 3+50+1+2 || ack.Accepted != 6 {
		t.Fatalf("%+v %v", ack, err)
	}
	gs, _ := s.Gaps(ctx, "a")
	if len(gs) != 1 || gs[0].From != 4 || gs[0].To != 53 || gs[0].Class != "flows" || gs[0].Count != 50 || gs[0].Reason != "shed" {
		t.Fatalf("%+v", gs)
	}
	// stored fields survive a round trip and still hash correctly
	got, err := s.Event(ctx, "a", 54)
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := got.ComputeHash(); h != got.Hash {
		t.Fatal("stored event no longer verifies")
	}

	// malformed gaps are rejected: wrong range bridge.
	s2, _ := open(t)
	enroll(t, s2, "a")
	c2 := &chain{agent: "a"}
	c2.many(2, "k")
	bad := c2.shed(5, "x")
	bad.Fields["from"] = uint64(1) // claims to cover already-acked seqs
	bad.Hash, _ = bad.ComputeHash()
	s2.Ingest(ctx, "a", (&chain{agent: "a"}).many(2, "k"))
	_, err = s2.Ingest(ctx, "a", []event.Event{bad})
	wantReason(t, err, ErrBadGap)
}

func TestRestartPersistence(t *testing.T) {
	ctx := context.Background()
	p := filepath.Join(t.TempDir(), "p.db")
	s, err := Open(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	enroll(t, s, "a")
	c := &chain{agent: "a"}
	evs := c.many(20, "k")
	if _, err := s.Ingest(ctx, "a", evs[:15]); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = Open(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, err := s.Agent(ctx, "a")
	if err != nil || a.LastSeq != 15 || a.LastHash != evs[14].Hash {
		t.Fatalf("%+v %v", a, err)
	}
	ack, err := s.Ingest(ctx, "a", evs[10:])
	if err != nil || ack.Seq != 20 || ack.Duplicates != 5 {
		t.Fatalf("%+v %v", ack, err)
	}
}

func TestQueries(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	enroll(t, s, "a", "b")
	ca, cb := &chain{agent: "a"}, &chain{agent: "b"}
	var ea, eb []event.Event
	for i := 0; i < 6; i++ {
		k := []string{"hb", "proc"}[i%2]
		ea = append(ea, ca.next(k, map[string]any{"n": i, "big": uint64(1) << 60}))
		eb = append(eb, cb.next("hb", nil))
	}
	if _, err := s.Ingest(ctx, "a", ea); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest(ctx, "b", eb); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Events(ctx, Query{Agent: "a", Kind: "proc"})
	if len(got) != 3 || got[0].Seq != 2 {
		t.Fatalf("%v", got)
	}
	for _, e := range got { // round-tripped events still verify
		if h, _ := e.ComputeHash(); h != e.Hash {
			t.Fatalf("seq %d no longer hashes", e.Seq)
		}
	}
	got, _ = s.Events(ctx, Query{Kind: "hb", From: t0.Add(2 * time.Second), To: t0.Add(5 * time.Second)})
	// a's hb events are at +0s,+2s,+4s -> +2s,+4s fall in [2s,5s); b's at +2s,+3s,+4s
	if len(got) != 5 {
		t.Fatalf("time range got %d", len(got))
	}
	got, _ = s.Events(ctx, Query{Agent: "b", Limit: 2, Desc: true})
	if len(got) != 2 || got[0].Seq != 6 {
		t.Fatalf("%v", got)
	}
	got, _ = s.Events(ctx, Query{Agent: "b", AfterSeq: 4})
	if len(got) != 2 {
		t.Fatalf("%d", len(got))
	}
	l, err := s.Latest(ctx, "a", "hb")
	if err != nil || l.Seq != 5 {
		t.Fatalf("%+v %v", l, err)
	}
	if _, err := s.Latest(ctx, "a", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	m, _ := s.LatestPerKind(ctx, "a")
	if len(m) != 2 || m["hb"].Seq != 5 || m["proc"].Seq != 6 {
		t.Fatalf("%v", m)
	}
}

func TestContextCancelled(t *testing.T) {
	s, _ := open(t)
	enroll(t, s, "a")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &chain{agent: "a"}
	if _, err := s.Ingest(ctx, "a", c.many(3, "k")); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if a, _ := s.Agent(context.Background(), "a"); a.LastSeq != 0 {
		t.Fatal("cancelled ingest stored data")
	}
}

func TestBackupRestoreFullSnapshot(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	enroll(t, s, "a")
	c := &chain{agent: "a"}
	evs := c.many(30, "k")
	if _, err := s.Ingest(ctx, "a", evs[:20]); err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := s.Backup(ctx, snap, BackupOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Backup(ctx, snap, BackupOptions{}); err == nil {
		t.Fatal("backup overwrote existing file")
	}
	// the live controller keeps going, then is "lost".
	if _, err := s.Ingest(ctx, "a", evs[20:25]); err != nil {
		t.Fatal(err)
	}
	s.Close()

	rp := filepath.Join(t.TempDir(), "restored.db")
	r, err := Restore(ctx, snap, rp, "controller restored")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if ep, _ := r.Epoch(ctx); ep != 2 {
		t.Fatalf("epoch %d", ep)
	}
	eps, _ := r.Epochs(ctx)
	if len(eps) != 2 || eps[1].Reason != "controller restored" {
		t.Fatalf("%+v", eps)
	}
	a, _ := r.Agent(ctx, "a")
	if a.LastSeq != 20 || a.RestoredSeq != 20 || a.RestoredHash != evs[19].Hash || a.Epoch != 2 {
		t.Fatalf("%+v", a)
	}
	// resend of everything the spool holds (the lost 21-25 included) passes.
	ack, err := r.Ingest(ctx, "a", evs)
	if err != nil || ack.Seq != 30 || ack.Duplicates != 20 || ack.Accepted != 10 {
		t.Fatalf("%+v %v", ack, err)
	}
	if a, _ := r.Agent(ctx, "a"); a.Epoch != 2 {
		t.Fatal("epoch not stamped")
	}
}

func TestRestoreStateOnlyResendMustPassThroughRecordedPoint(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	enroll(t, s, "a", "b")
	ca, cb := &chain{agent: "a"}, &chain{agent: "b"}
	ea, eb := ca.many(20, "k"), cb.many(20, "k")
	s.Ingest(ctx, "a", ea[:12])
	s.Ingest(ctx, "b", eb[:12])
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := s.Backup(ctx, snap, BackupOptions{StateOnly: true}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	r, err := Restore(ctx, snap, filepath.Join(t.TempDir(), "r.db"), "disk died")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if n, _ := r.Count(ctx, ""); n != 0 {
		t.Fatalf("state-only snapshot kept %d events", n)
	}

	// Agent a: honest resend of its whole spool: backfilled, then extended.
	ack, err := r.Ingest(ctx, "a", ea)
	if err != nil || ack.Backfilled != 12 || ack.Accepted != 8 || ack.Seq != 20 {
		t.Fatalf("%+v %v", ack, err)
	}
	if n, _ := r.Count(ctx, "a"); n != 20 {
		t.Fatalf("count %d", n)
	}

	// Agent b: a different history that does not pass through (12, hash).
	forged := &chain{agent: "b"}
	var fe []event.Event
	for i := 0; i < 20; i++ {
		fe = append(fe, forged.next("evil", nil))
	}
	ack, err = r.Ingest(ctx, "b", fe)
	wantReason(t, err, ErrRestoreMismatch)
	if ack.Seq != 12 {
		t.Fatalf("ack moved to %d", ack.Seq)
	}
	// ...and the honest one still works afterwards.
	if _, err := r.Ingest(ctx, "b", eb); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreResendBackfillsAcrossBatches(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	enroll(t, s, "a")
	c := &chain{agent: "a"}
	evs := c.many(2500, "k")
	for off := 0; off < len(evs); off += MaxBatch {
		end := min(off+MaxBatch, len(evs))
		if _, err := s.Ingest(ctx, "a", evs[off:end]); err != nil {
			t.Fatal(err)
		}
	}
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := s.Backup(ctx, snap, BackupOptions{StateOnly: true}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	r, err := Restore(ctx, snap, filepath.Join(t.TempDir(), "r.db"), "disk died")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	// The resend spans several calls below the restore point: nothing is
	// stored until the last one reaches it, then the whole run is backfilled.
	for off := 0; off < len(evs); off += 700 {
		end := min(off+700, len(evs))
		ack, err := r.Ingest(ctx, "a", evs[off:end])
		if err != nil {
			t.Fatalf("batch at %d: %v", off, err)
		}
		if end < len(evs) {
			if n, _ := r.Count(ctx, "a"); n != 0 {
				t.Fatalf("stored %d events before the restore point", n)
			}
		} else if ack.Backfilled != len(evs) || ack.Seq != uint64(len(evs)) {
			t.Fatalf("ack %+v; want all %d backfilled", ack, len(evs))
		}
	}
	if n, err := r.Count(ctx, "a"); err != nil || n != int64(len(evs)) {
		t.Fatalf("stored %d events (%v), want %d", n, err, len(evs))
	}
	if g, err := r.Gaps(ctx, "a"); err != nil || len(g) != 0 {
		t.Fatalf("gaps after a complete resend: %+v %v", g, err)
	}
}

// A resend can start below the restore point when the store already holds the
// event before it. Its first prev hash is checked against that stored event;
// a stale link is refused and the honest run still backfills.
func TestRestoreResendStartsAfterStoredEvent(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	enroll(t, s, "a")
	c := &chain{agent: "a"}
	evs := c.many(20, "k")
	if _, err := s.Ingest(ctx, "a", evs); err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := s.Backup(ctx, snap, BackupOptions{}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	r, err := Restore(ctx, snap, filepath.Join(t.TempDir(), "r.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// Simulate a store that kept the events below the run but not the run.
	if _, err := r.w.ExecContext(ctx, `DELETE FROM events WHERE agent='a' AND seq>=10`); err != nil {
		t.Fatal(err)
	}

	bad := evs[9]
	bad.PrevHash = "00"
	_, err = r.Ingest(ctx, "a", []event.Event{bad})
	wantReason(t, err, ErrPrevMismatch)

	ack, err := r.Ingest(ctx, "a", evs[9:])
	if err != nil || ack.Backfilled != 11 || ack.Seq != 20 {
		t.Fatalf("%+v %v", ack, err)
	}
	if n, err := r.Count(ctx, "a"); err != nil || n != 20 {
		t.Fatalf("stored %d events (%v), want 20", n, err)
	}
}

func TestResumeAfterRestoreRecordsGap(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	enroll(t, s, "a")
	c := &chain{agent: "a"}
	evs := c.many(30, "k")
	s.Ingest(ctx, "a", evs[:10])
	snap := filepath.Join(t.TempDir(), "snap.db")
	s.Backup(ctx, snap, BackupOptions{})
	s.Close()
	r, err := Restore(ctx, snap, filepath.Join(t.TempDir(), "r.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// spool only retains seq 21..30: events 11..20 are gone.
	if _, err := r.Ingest(ctx, "a", evs[20:]); err == nil {
		t.Fatal("accepted a jump")
	}
	if err := r.ResumeAfterRestore(ctx, "a", evs[20]); err != nil {
		t.Fatal(err)
	}
	ack, err := r.Ingest(ctx, "a", evs[20:])
	if err != nil || ack.Seq != 30 {
		t.Fatalf("%+v %v", ack, err)
	}
	gs, _ := r.Gaps(ctx, "a")
	if len(gs) != 1 || gs[0].From != 11 || gs[0].To != 20 || gs[0].Reason != "controller restored" {
		t.Fatalf("%+v", gs)
	}
	// not allowed once the head has moved past the restore point
	if err := r.ResumeAfterRestore(ctx, "a", evs[25]); err == nil {
		t.Fatal("resume allowed with moved head")
	}
}

func TestConcurrentIngest(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	const agents, per, batch = 24, 300, 50
	var wg sync.WaitGroup
	errs := make(chan error, agents)
	for i := 0; i < agents; i++ {
		id := fmt.Sprintf("host%02d", i)
		enroll(t, s, id)
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &chain{agent: id}
			evs := c.many(per, "k")
			for off := 0; off < per; off += batch {
				if _, err := s.Ingest(ctx, id, evs[off:off+batch]); err != nil {
					errs <- err
					return
				}
				// concurrent readers
				if _, err := s.Events(ctx, Query{Agent: id, Limit: 10}); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	for i := 0; i < agents; i++ {
		a, _ := s.Agent(ctx, fmt.Sprintf("host%02d", i))
		if a.LastSeq != per {
			t.Fatalf("%s at %d", a.ID, a.LastSeq)
		}
	}
	if n, _ := s.Count(ctx, ""); n != agents*per {
		t.Fatalf("count %d", n)
	}
}

func BenchmarkIngest(b *testing.B) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(b.TempDir(), "b.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	s.EnrollAgent(ctx, "a", []byte("k"))
	c := &chain{agent: "a"}
	const batch = 500
	b.ResetTimer()
	for done := 0; done < b.N; {
		n := min(batch, b.N-done)
		b.StopTimer()
		evs := c.many(n, "proc")
		b.StartTimer()
		if _, err := s.Ingest(ctx, "a", evs); err != nil {
			b.Fatal(err)
		}
		done += n
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "events/s")
}

func TestPlansAndStepSeq(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Plan(ctx, "nope"); !errors.Is(err, ErrNoPlan) {
		t.Fatalf("got %v", err)
	}
	if err := s.UpsertPlan(ctx, PlanRow{ID: "p", Name: "n", State: "draft", Epoch: 1, Body: `{"a":1}`}); err != nil {
		t.Fatal(err)
	}
	first, _ := s.Plan(ctx, "p")
	if err := s.UpsertPlan(ctx, PlanRow{ID: "p", Name: "n", State: "running", Epoch: 1}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Plan(ctx, "p")
	if got.State != "running" || !got.Created.Equal(first.Created) && got.Created.Before(first.Created) {
		t.Fatalf("%+v", got)
	}
	if err := s.UpsertPlanStep(ctx, PlanStepRow{PlanID: "p", Step: "a", Host: "h", Action: "x", State: "approved"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertPlanStep(ctx, PlanStepRow{PlanID: "p", Step: "a", Host: "h", Action: "x", State: "verified", Result: `{"r":1}`}); err != nil {
		t.Fatal(err)
	}
	steps, _ := s.PlanSteps(ctx, "p")
	if len(steps) != 1 || steps[0].State != "verified" || steps[0].Result != `{"r":1}` {
		t.Fatalf("%+v", steps)
	}
	for want := uint64(1); want <= 3; want++ {
		if n, err := s.NextStepSeq(ctx, "h1"); err != nil || n != want {
			t.Fatalf("seq %d: %d %v", want, n, err)
		}
	}
	if n, _ := s.NextStepSeq(ctx, "h2"); n != 1 {
		t.Fatalf("independent per host: %d", n)
	}
	path := s.Path()
	s.Close()
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if n, _ := s.NextStepSeq(ctx, "h1"); n != 4 {
		t.Fatalf("sequence not durable: %d", n)
	}
	if n, err := s.InterruptPlans(ctx, "running", "draft"); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	if p, _ := s.Plan(ctx, "p"); p.State != "interrupted" {
		t.Fatal(p.State)
	}
}

func TestAuditPageAndCheckHistory(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	for i := 0; i < 7; i++ {
		actor := "a"
		if i%2 == 1 {
			actor = "b"
		}
		if err := s.AppendAudit(ctx, AuditRow{Time: now, Actor: actor, Action: "act", Detail: "d"}); err != nil {
			t.Fatal(err)
		}
	}
	p1, next, err := s.AuditPage(ctx, AuditFilter{Limit: 3})
	if err != nil || len(p1) != 3 || next == 0 {
		t.Fatalf("page 1: %d next %d %v", len(p1), next, err)
	}
	p2, next2, _ := s.AuditPage(ctx, AuditFilter{Limit: 3, Before: next})
	if len(p2) != 3 || p2[0].ID >= p1[2].ID || next2 == 0 {
		t.Fatalf("page 2: %+v", p2)
	}
	p3, next3, _ := s.AuditPage(ctx, AuditFilter{Limit: 3, Before: next2})
	if len(p3) != 1 || next3 != 0 {
		t.Fatalf("page 3: %+v next %d", p3, next3)
	}
	onlyB, _, _ := s.AuditPage(ctx, AuditFilter{Actor: "b"})
	if len(onlyB) != 3 {
		t.Fatalf("actor filter: %d", len(onlyB))
	}

	checkKeep = 25
	defer func() { checkKeep = 2000 }()
	for i := 0; i < checkKeep+10; i++ {
		if err := s.RecordCheck(ctx, CheckResult{CheckID: "web:http", Service: "web", Kind: "http", Vantage: "controller", Time: now.Add(time.Duration(i) * time.Second), OK: i%2 == 0}); err != nil {
			t.Fatal(err)
		}
	}
	h, err := s.CheckHistory(ctx, "web:http", 5000)
	if err != nil || len(h) != checkKeep || !h[0].Time.After(h[1].Time) {
		t.Fatalf("history kept %d (%v), want %d newest first", len(h), err, checkKeep)
	}
}
