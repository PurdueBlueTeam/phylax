package spool

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const metaName = "meta.json"

// meta is the small index file: the chain head and the last cumulative ack.
// The head matters only when every segment has been deleted; the ack only
// saves resending, so a stale meta is always safe.
type meta struct {
	Version  int    `json:"v"`
	Ack      uint64 `json:"ack"`
	AckHash  string `json:"ack_hash"`
	HeadSeq  uint64 `json:"head_seq"`
	HeadHash string `json:"head_hash"`
}

func readMeta(dir string) meta {
	var m meta
	b, err := os.ReadFile(filepath.Join(dir, metaName))
	if err != nil || json.Unmarshal(b, &m) != nil || m.Version != 1 {
		return meta{}
	}
	return m
}

// writeMeta replaces meta.json atomically: temp file, fsync, rename, dir fsync.
func writeMeta(dir string, m meta) error {
	m.Version = 1
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, metaName+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, metaName)); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(dir)
}
