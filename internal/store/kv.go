package store

import (
	"context"
	"database/sql"
	"errors"
)

// Small durable key/value records in the meta table, for controller state that
// is not worth a table of its own (the honeytoken registry). Keys are
// namespaced by the caller ("honeytokens", never "epoch" or "stepseq:*").

// ErrNoMeta is returned by MetaGet for a missing key.
var ErrNoMeta = errors.New("store: no such meta key")

// MetaGet returns the value stored under key.
func (s *Store) MetaGet(ctx context.Context, key string) (string, error) {
	var v string
	err := s.r.QueryRowContext(ctx, `SELECT value FROM meta WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNoMeta
	}
	return v, err
}

// MetaSet durably stores value under key. The reserved keys the store itself
// owns cannot be overwritten through this call.
func (s *Store) MetaSet(ctx context.Context, key, value string) error {
	if key == "" || key == "epoch" || len(key) > 7 && key[:7] == "stepseq" {
		return errors.New("store: reserved meta key")
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO meta(key, value) VALUES (?,?)
ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}
