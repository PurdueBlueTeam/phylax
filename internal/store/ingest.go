package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// KindGap is the kind of the gap record a spool appends when it sheds events.
// Fields: from, to (inclusive sequence range shed), count, class. The record's
// Seq is to+1 and its PrevHash is the hash of the last event before the range
// (the "hash bridge"), so the chain stays verifiable across the shed range.
const KindGap = "spool.gap"

// Reasons a chain check can fail. A *ChainError wraps one of these and also
// matches event.ErrChain.
var (
	ErrOutOfOrder      = errors.New("out of order")
	ErrPrevMismatch    = errors.New("prev hash mismatch")
	ErrBadHash         = errors.New("bad hash")
	ErrRewrite         = errors.New("acknowledged event differs from resent event")
	ErrRestoreMismatch = errors.New("resend does not pass through the restore point")
	ErrBadGap          = errors.New("malformed gap record")
	ErrBadEvent        = errors.New("malformed event")
)

// ChainError is the typed rejection returned by Ingest.
type ChainError struct {
	Agent  string
	Seq    uint64
	Reason error
	Detail string
}

func (e *ChainError) Error() string {
	s := fmt.Sprintf("store: agent %q seq %d: %v", e.Agent, e.Seq, e.Reason)
	if e.Detail != "" {
		s += " (" + e.Detail + ")"
	}
	return s
}
func (e *ChainError) Unwrap() []error { return []error{event.ErrChain, e.Reason} }

// Ack is the controller's acknowledgment for an agent: everything up to and
// including Seq (whose chain hash is Hash) is durably stored.
type Ack struct {
	Agent      string
	Seq        uint64
	Hash       string
	Accepted   int // new events appended to the chain
	Duplicates int // already-stored events matched on resend
	Backfilled int // events at or below the restore point stored from a resend
}

// Ingest verifies and stores a batch of events from one agent, in order. The
// batch is processed as a prefix: on a rejection the valid events before it
// are committed, and the returned Ack reflects them together with the error.
// A resend of events already stored is idempotent; one that differs from what
// was acknowledged is ErrRewrite. Other (non-chain) errors roll everything back.
func (s *Store) Ingest(ctx context.Context, agent string, evs []event.Event) (Ack, error) {
	if len(evs) > MaxBatch {
		return Ack{}, fmt.Errorf("%w: %d > %d", ErrBatchTooBig, len(evs), MaxBatch)
	}
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return Ack{}, err
	}
	defer tx.Rollback()

	a, err := scanAgent(tx.QueryRowContext(ctx, `SELECT `+agentCols+` FROM agents WHERE id=?`, agent))
	if errors.Is(err, sql.ErrNoRows) {
		return Ack{}, ErrUnknownAgent
	} else if err != nil {
		return Ack{}, err
	}
	start := Ack{Agent: agent, Seq: a.LastSeq, Hash: a.LastHash}
	ack := start
	curSeq, curHash := a.LastSeq, a.LastHash

	ins, err := tx.PrepareContext(ctx, `INSERT INTO events(agent, seq, time_ns, kind, prio, fields, prev, hash) VALUES (?,?,?,?,?,?,?,?)`)
	if err != nil {
		return start, err
	}
	defer ins.Close()

	var chainErr error
	var pending []*event.Event // unstored events below the restore point, not yet tied to it
	var last *event.Event      // previous event in this batch, for link checks
	var newly []event.Event    // events this transaction stored, for the ingest hook
	for i := range evs {
		if err := ctx.Err(); err != nil {
			return start, err
		}
		ev := &evs[i]
		cerr := func(reason error, detail string) error {
			return &ChainError{Agent: agent, Seq: ev.Seq, Reason: reason, Detail: detail}
		}
		if ev.Agent != agent || ev.Kind == "" || ev.Seq == 0 {
			chainErr = cerr(ErrBadEvent, "agent/kind/seq")
			break
		}
		if last != nil && last.Seq+1 == ev.Seq && ev.PrevHash != last.Hash && ev.Kind != KindGap {
			chainErr = cerr(ErrPrevMismatch, "does not follow previous event in batch")
			break
		}

		if ev.Seq <= curSeq {
			// Resend of something at or below the ack point.
			var stored string
			err := tx.QueryRowContext(ctx, `SELECT hash FROM events WHERE agent=? AND seq=?`, agent, ev.Seq).Scan(&stored)
			switch {
			case err == nil:
				if stored != ev.Hash {
					chainErr = cerr(ErrRewrite, "")
					break
				}
				ack.Duplicates++
			case errors.Is(err, sql.ErrNoRows):
				if ev.Seq > a.RestoredSeq {
					chainErr = cerr(ErrOutOfOrder, "seq lies inside a recorded gap")
					break
				}
				// Below or at the restore point and not stored (state-only
				// snapshot). Nothing is stored until the run of events
				// reaches the restore point and its hash equals the one the
				// snapshot recorded; the prev links (checked above) then tie
				// every pending event to that hash.
				h, herr := ev.ComputeHash()
				if herr != nil {
					return start, herr
				}
				if h != ev.Hash {
					chainErr = cerr(ErrBadHash, "")
					break
				}
				if len(pending) > 0 && pending[len(pending)-1].Seq+1 != ev.Seq {
					pending = pending[:0]
				}
				pending = append(pending, ev)
				if ev.Seq == a.RestoredSeq {
					if ev.Hash != a.RestoredHash {
						chainErr = cerr(ErrRestoreMismatch, "hash at restored seq differs from snapshot")
						break
					}
					for _, p := range pending {
						if p.Kind == KindGap {
							continue // shed ranges are recorded in gaps already
						}
						if err := insertEvent(ctx, ins, p); err != nil {
							return start, err
						}
						newly = append(newly, *p)
						ack.Backfilled++
					}
					pending = pending[:0]
				}
			default:
				return start, err
			}
			if chainErr != nil {
				break
			}
			last = ev
			continue
		}

		// A new event extending the chain.
		if ev.Kind == KindGap {
			from, to, ok := gapRange(ev)
			if !ok || from != curSeq+1 || to < from || ev.Seq != to+1 {
				chainErr = cerr(ErrBadGap, "range does not bridge the chain")
				break
			}
		} else if ev.Seq != curSeq+1 {
			chainErr = cerr(ErrOutOfOrder, fmt.Sprintf("expected %d", curSeq+1))
			break
		}
		if ev.PrevHash != curHash {
			chainErr = cerr(ErrPrevMismatch, "")
			break
		}
		h, herr := ev.ComputeHash()
		if herr != nil {
			return start, herr
		}
		if h != ev.Hash {
			chainErr = cerr(ErrBadHash, "")
			break
		}
		if err := insertEvent(ctx, ins, ev); err != nil {
			return start, err
		}
		if ev.Kind == KindGap {
			from, to, _ := gapRange(ev)
			class, _ := ev.Fields["class"].(string)
			cnt, _ := fieldUint(ev.Fields["count"])
			if _, err := tx.ExecContext(ctx, `INSERT INTO gaps(agent, from_seq, to_seq, reason, class, count, time_ns) VALUES (?,?,?,?,?,?,?)`,
				agent, from, to, "shed", class, cnt, ev.Time.UnixNano()); err != nil {
				return start, err
			}
		}
		newly = append(newly, *ev)
		curSeq, curHash = ev.Seq, ev.Hash
		ack.Accepted++
		last = ev
	}

	itx := &IngestTx{ctx: ctx, tx: tx}
	if h := s.hook.Load(); h != nil && len(newly) > 0 {
		if err := (*h)(ctx, itx, newly); err != nil {
			return start, fmt.Errorf("store: ingest hook: %w", err)
		}
	}
	if curSeq != a.LastSeq {
		if _, err := tx.ExecContext(ctx, `UPDATE agents SET last_seq=?, last_hash=?, epoch=(SELECT CAST(value AS INTEGER) FROM meta WHERE key='epoch') WHERE id=?`,
			curSeq, curHash, agent); err != nil {
			return start, err
		}
	}
	if err := tx.Commit(); err != nil {
		return start, err
	}
	for _, f := range itx.after {
		f()
	}
	ack.Seq, ack.Hash = curSeq, curHash
	return ack, chainErr
}

func insertEvent(ctx context.Context, st *sql.Stmt, ev *event.Event) error {
	fields, err := json.Marshal(ev.Fields)
	if err != nil {
		return fmt.Errorf("store: encode fields: %w", err)
	}
	_, err = st.ExecContext(ctx, ev.Agent, ev.Seq, ev.Time.UnixNano(), ev.Kind, int(ev.Priority), string(fields), ev.PrevHash, ev.Hash)
	return err
}

func fieldUint(v any) (uint64, bool) {
	switch n := v.(type) {
	case float64:
		if n >= 0 && n == float64(uint64(n)) {
			return uint64(n), true
		}
	case json.Number:
		u, err := n.Int64()
		return uint64(u), err == nil && u >= 0
	case uint64:
		return n, true
	case int:
		return uint64(n), n >= 0
	case int64:
		return uint64(n), n >= 0
	case uint:
		return uint64(n), true
	case uint32:
		return uint64(n), true
	}
	return 0, false
}

func gapRange(ev *event.Event) (from, to uint64, ok bool) {
	f, ok1 := fieldUint(ev.Fields["from"])
	t, ok2 := fieldUint(ev.Fields["to"])
	return f, t, ok1 && ok2
}

// Gap is a recorded hole in an agent's history.
type Gap struct {
	Agent    string
	From, To uint64
	Reason   string // "shed" for spool gap records, or a controller reason
	Class    string
	Count    uint64
	Time     time.Time
}

// Gaps lists an agent's recorded gaps in order.
func (s *Store) Gaps(ctx context.Context, agent string) ([]Gap, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT agent, from_seq, to_seq, reason, class, count, time_ns FROM gaps WHERE agent=? ORDER BY from_seq, id`, agent)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Gap
	for rows.Next() {
		var g Gap
		var ns int64
		if err := rows.Scan(&g.Agent, &g.From, &g.To, &g.Reason, &g.Class, &g.Count, &ns); err != nil {
			return nil, err
		}
		g.Time = time.Unix(0, ns).UTC()
		out = append(out, g)
	}
	return out, rows.Err()
}

// ResumeAfterRestore handles the case where, after a restore, an agent's spool
// no longer holds the events between the controller's head and its earliest
// retained event. first is that earliest event (the agent's resend starts
// there). The missing range is recorded as a gap with reason "controller
// restored" and the head moves to first's predecessor so first can be
// ingested. Only allowed while the agent's head still equals its restore
// point and first lies beyond it; the earliest event's self-hash is checked.
func (s *Store) ResumeAfterRestore(ctx context.Context, agent string, first event.Event) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	a, err := scanAgent(tx.QueryRowContext(ctx, `SELECT `+agentCols+` FROM agents WHERE id=?`, agent))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnknownAgent
	} else if err != nil {
		return err
	}
	ce := func(r error, d string) error { return &ChainError{Agent: agent, Seq: first.Seq, Reason: r, Detail: d} }
	if first.Agent != agent || a.RestoredSeq == 0 || a.LastSeq != a.RestoredSeq || first.Seq <= a.LastSeq+1 {
		return ce(ErrOutOfOrder, "no restore gap to resume across")
	}
	if h, err := first.ComputeHash(); err != nil {
		return err
	} else if h != first.Hash {
		return ce(ErrBadHash, "")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO gaps(agent, from_seq, to_seq, reason, time_ns) VALUES (?,?,?,?,?)`,
		agent, a.LastSeq+1, first.Seq-1, "controller restored", time.Now().UnixNano()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE agents SET last_seq=?, last_hash=? WHERE id=?`, first.Seq-1, first.PrevHash, agent); err != nil {
		return err
	}
	return tx.Commit()
}
