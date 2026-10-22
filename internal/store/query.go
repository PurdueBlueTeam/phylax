package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// Query selects stored events. Zero fields are unconstrained. Results are
// ordered by (time, agent, seq) ascending, or descending when Desc is set.
type Query struct {
	Agent    string
	Kind     string
	From, To time.Time // From inclusive, To exclusive
	AfterSeq uint64    // with Agent: only seq > AfterSeq (order is then by seq)
	Limit    int       // default DefaultQueryMax, capped at MaxQueryLimit
	Desc     bool
}

const eventCols = `agent, seq, time_ns, kind, prio, fields, prev, hash`

func scanEvent(r scanner) (event.Event, error) {
	var e event.Event
	var ns int64
	var prio int
	var fields string
	if err := r.Scan(&e.Agent, &e.Seq, &ns, &e.Kind, &prio, &fields, &e.PrevHash, &e.Hash); err != nil {
		return e, err
	}
	e.Time = time.Unix(0, ns).UTC()
	e.Priority = event.Priority(prio)
	if fields != "null" && fields != "" {
		dec := json.NewDecoder(bytes.NewReader([]byte(fields)))
		dec.UseNumber() // keep numbers byte-exact so the hash still verifies
		if err := dec.Decode(&e.Fields); err != nil {
			return e, err
		}
	}
	return e, nil
}

// Events runs a query.
func (s *Store) Events(ctx context.Context, q Query) ([]event.Event, error) {
	var where []string
	var args []any
	if q.Agent != "" {
		where = append(where, "agent=?")
		args = append(args, q.Agent)
	}
	if q.Kind != "" {
		where = append(where, "kind=?")
		args = append(args, q.Kind)
	}
	if !q.From.IsZero() {
		where = append(where, "time_ns>=?")
		args = append(args, q.From.UnixNano())
	}
	if !q.To.IsZero() {
		where = append(where, "time_ns<?")
		args = append(args, q.To.UnixNano())
	}
	if q.AfterSeq > 0 {
		where = append(where, "seq>?")
		args = append(args, q.AfterSeq)
	}
	limit := q.Limit
	if limit <= 0 {
		limit = DefaultQueryMax
	}
	if limit > MaxQueryLimit {
		limit = MaxQueryLimit
	}
	dir := "ASC"
	if q.Desc {
		dir = "DESC"
	}
	sqlq := `SELECT ` + eventCols + ` FROM events`
	if len(where) > 0 {
		sqlq += ` WHERE ` + strings.Join(where, " AND ")
	}
	order := "time_ns " + dir + ", agent " + dir + ", seq " + dir
	if q.Agent != "" && q.From.IsZero() && q.To.IsZero() {
		order = "seq " + dir
	}
	sqlq += ` ORDER BY ` + order + ` LIMIT ?`
	args = append(args, limit)
	return s.collect(ctx, sqlq, args...)
}

func (s *Store) collect(ctx context.Context, q string, args ...any) ([]event.Event, error) {
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []event.Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ErrNotFound is returned when a lookup matches nothing.
var ErrNotFound = errors.New("store: not found")

// Event returns one stored event.
func (s *Store) Event(ctx context.Context, agent string, seq uint64) (event.Event, error) {
	e, err := scanEvent(s.r.QueryRowContext(ctx, `SELECT `+eventCols+` FROM events WHERE agent=? AND seq=?`, agent, seq))
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}

// Latest returns the newest event (highest seq) of a kind from an agent.
func (s *Store) Latest(ctx context.Context, agent, kind string) (event.Event, error) {
	e, err := scanEvent(s.r.QueryRowContext(ctx,
		`SELECT `+eventCols+` FROM events WHERE agent=? AND kind=? ORDER BY seq DESC LIMIT 1`, agent, kind))
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}

// LatestPerKind returns the newest event of every kind from an agent (for
// example heartbeat, health and inventory snapshots).
func (s *Store) LatestPerKind(ctx context.Context, agent string) (map[string]event.Event, error) {
	evs, err := s.collect(ctx, `SELECT `+eventCols+` FROM events e WHERE agent=? AND seq=(
		SELECT MAX(seq) FROM events WHERE agent=e.agent AND kind=e.kind)`, agent)
	if err != nil {
		return nil, err
	}
	m := make(map[string]event.Event, len(evs))
	for _, e := range evs {
		m[e.Kind] = e
	}
	return m, nil
}

// Count returns the number of stored events for an agent ("" for all).
func (s *Store) Count(ctx context.Context, agent string) (int64, error) {
	var n int64
	var err error
	if agent == "" {
		err = s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&n)
	} else {
		err = s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE agent=?`, agent).Scan(&n)
	}
	return n, err
}
