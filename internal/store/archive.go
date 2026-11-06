package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ArchiveAgent moves host's chain (events, gaps and alert rows) to the id
// "<host>~<n>" (n = 1 + the highest existing suffix), inserts that id with the
// old key, chain head and epoch, then resets host to pubkey with last_seq 0 and
// an empty chain. One transaction, on the writer connection.
func (s *Store) ArchiveAgent(ctx context.Context, host string, pubkey []byte) (string, error) {
	if host == "" || len(pubkey) == 0 {
		return "", errors.New("store: archive needs an id and a key")
	}
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	prefix := host + "~"
	rows, err := tx.QueryContext(ctx, `SELECT id FROM agents`)
	if err != nil {
		return "", err
	}
	highest := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return "", err
		}
		if rest, ok := strings.CutPrefix(id, prefix); ok {
			if n, err := strconv.Atoi(rest); err == nil && n > highest {
				highest = n
			}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", err
	}
	rows.Close()
	archived := fmt.Sprintf("%s%d", prefix, highest+1)

	res, err := tx.ExecContext(ctx, `INSERT INTO agents(id, pubkey, enrolled_at, last_seq, last_hash, epoch, restored_seq, restored_hash)
		SELECT ?, pubkey, enrolled_at, last_seq, last_hash, epoch, restored_seq, restored_hash FROM agents WHERE id=?`, archived, host)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrUnknownAgent
	}
	for _, q := range []string{
		`UPDATE events SET agent=? WHERE agent=?`,
		`UPDATE gaps SET agent=? WHERE agent=?`,
		`UPDATE alerts SET agent=? WHERE agent=?`,
	} {
		if _, err := tx.ExecContext(ctx, q, archived, host); err != nil {
			return "", err
		}
	}
	var epoch uint64
	err = tx.QueryRowContext(ctx, `SELECT CAST(value AS INTEGER) FROM meta WHERE key='epoch'`).Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		epoch = 1
	} else if err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE agents SET pubkey=?, enrolled_at=?, last_seq=0, last_hash='',
		epoch=?, restored_seq=0, restored_hash='' WHERE id=?`,
		pubkey, time.Now().UnixNano(), epoch, host); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return archived, nil
}
