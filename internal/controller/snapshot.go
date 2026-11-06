package controller

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

const (
	// maxSnapshotBytes bounds the encrypted snapshot and its unpacked content.
	maxSnapshotBytes = 64 << 20
	// snapshotsKept is how many snapshot files one directory keeps.
	snapshotsKept = 8
	// snapshotPrefix names every snapshot file.
	snapshotPrefix = "phylax-snapshot-"
	// snapshotDebounce is the shortest gap between two event-triggered
	// snapshots; a tick is not debounced.
	snapshotDebounce = 30 * time.Second
	// snapshotScryptWork is the scrypt work factor of a snapshot (about 100 ms).
	snapshotScryptWork = 15
)

// snapshotEntry is one regular file in a snapshot.
type snapshotEntry struct {
	name string // tar entry name, a base name
	path string // source file
}

// snapshotSourceFiles lists the controller state files a snapshot holds, in a
// fixed order. Missing files are skipped; the store backup is added by the
// writer.
func (c *Controller) snapshotSourceFiles() []snapshotEntry {
	idPath := c.cfg.IdentityPath
	if idPath == "" {
		idPath = filepath.Join(c.cfg.DataDir, "identity.pem")
	}
	files := []snapshotEntry{
		{"identity.pem", idPath},
		{"plan.key", filepath.Join(c.cfg.DataDir, "plan.key")},
		{"tokens.json", filepath.Join(c.cfg.DataDir, "tokens.json")},
		{"revoked.json", filepath.Join(c.cfg.DataDir, "revoked.json")},
		{"known_hosts.json", filepath.Join(c.cfg.DataDir, "known_hosts.json")},
	}
	if c.cfg.VaultPath != "" {
		files = append(files, snapshotEntry{filepath.Base(c.cfg.VaultPath), c.cfg.VaultPath})
	}
	out := files[:0]
	for _, f := range files {
		if _, err := os.Stat(f.path); err == nil {
			out = append(out, f)
		}
	}
	return out
}

// WriteSnapshot writes one age (scrypt) encrypted tar of the controller's
// state to <dir>/phylax-snapshot-<UTC yyyymmddThhmmssZ>.age. The database is a
// StateOnly backup (no event rows); the other files are the controller keys,
// the token, revocation and host-key files and the vault when configured. The
// newest 8 files in dir are kept.
func (c *Controller) WriteSnapshot(ctx context.Context, dir string, pass []byte) (string, error) {
	if len(pass) == 0 {
		return "", errors.New("controller: snapshot needs a passphrase")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("controller: snapshot dir: %w", err)
	}
	tmp, err := os.MkdirTemp("", "phylax-snapshot-")
	if err != nil {
		return "", fmt.Errorf("controller: snapshot temp: %w", err)
	}
	defer os.RemoveAll(tmp)
	db := filepath.Join(tmp, "phylax.db")
	if err := c.st.Backup(ctx, db, store.BackupOptions{StateOnly: true}); err != nil {
		return "", err
	}
	files := append([]snapshotEntry{{"phylax.db", db}}, c.snapshotSourceFiles()...)
	name := snapshotPrefix + c.now().UTC().Format("20060102T150405Z") + ".age"
	path := filepath.Join(dir, name)
	err = atomicfile.Write(path, 0o600, func(w io.Writer) error {
		return writeSnapshotTar(w, files, pass)
	})
	if err != nil {
		return "", err
	}
	if err := pruneSnapshots(dir); err != nil {
		return path, err
	}
	return path, nil
}

// writeSnapshotTar encrypts and writes the fixed file list.
func writeSnapshotTar(w io.Writer, files []snapshotEntry, pass []byte) error {
	r, err := age.NewScryptRecipient(string(pass))
	if err != nil {
		return err
	}
	r.SetWorkFactor(snapshotScryptWork) // shortcut: about 100 ms per snapshot, raise when snapshots become rare
	aw, err := age.Encrypt(w, r)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(aw)
	for _, f := range files {
		if err := addSnapshotFile(tw, f.name, f.path); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return aw.Close()
}

func addSnapshotFile(tw *tar.Writer, name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("controller: snapshot: %s is not a regular file", path)
	}
	h, err := tar.FileInfoHeader(fi, "")
	if err != nil {
		return err
	}
	h.Name = name
	h.Mode = 0o600
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	n, err := io.CopyN(tw, f, fi.Size())
	if err != nil {
		return err
	}
	if n != fi.Size() {
		return fmt.Errorf("controller: snapshot: short read of %s", path)
	}
	return nil
}

// pruneSnapshots keeps the newest snapshotsKept files in dir.
func pruneSnapshots(dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, snapshotPrefix+"*.age"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	for len(files) > snapshotsKept {
		if err := os.Remove(files[0]); err != nil {
			return err
		}
		files = files[1:]
	}
	return nil
}

// RunSnapshots writes a snapshot to every configured directory on the
// interval and again after enrollment and plan completion, debounced to one
// per 30 s. It does nothing while no passphrase is held ("locked": snapshots
// need the operator passphrase) and records that in SnapshotStatus.
func (c *Controller) RunSnapshots(ctx context.Context, pass func() []byte) {
	if len(c.cfg.SnapshotDirs) == 0 {
		return
	}
	every := time.Duration(c.cfg.SnapshotInterval)
	if every <= 0 {
		every = 15 * time.Minute
	}
	t := c.clk.NewTicker(every)
	defer t.Stop()
	var last time.Time
	var pending timer
	for {
		var due <-chan time.Time
		if pending != nil {
			due = pending.C()
		}
		select {
		case <-ctx.Done():
			if pending != nil {
				pending.Stop()
			}
			return
		case <-t.C():
			c.writeSnapshots(ctx, pass)
			last = c.now()
		case <-c.snapSoonC:
			if d := snapshotDebounce - c.now().Sub(last); d > 0 {
				if pending == nil {
					pending = c.clk.NewTimer(d)
				}
				continue
			}
			c.writeSnapshots(ctx, pass)
			last = c.now()
			drainSnapSoon(c.snapSoonC)
		case <-due:
			pending = nil
			c.writeSnapshots(ctx, pass)
			last = c.now()
			drainSnapSoon(c.snapSoonC)
		}
	}
}

// drainSnapSoon drops event triggers that arrived during a write, so a burst
// produces one snapshot per debounce window.
func drainSnapSoon(ch chan struct{}) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// writeSnapshots writes to every configured directory and records the result.
func (c *Controller) writeSnapshots(ctx context.Context, pass func() []byte) {
	var p []byte
	if pass != nil {
		p = pass()
	}
	locked, _ := c.Locked()
	if locked || len(p) == 0 {
		c.setSnapshotStatus("skipped: locked")
		return
	}
	for _, dir := range c.cfg.SnapshotDirs {
		path, err := c.WriteSnapshot(ctx, dir, p)
		if err != nil {
			c.log.Error("snapshot failed", "dir", dir, "err", err)
			c.setSnapshotStatus("error: " + err.Error())
			continue
		}
		c.log.Info("snapshot written", "path", path)
		c.setSnapshotStatus("wrote " + path)
	}
}

func (c *Controller) setSnapshotStatus(s string) {
	c.snapMu.Lock()
	c.snapStatus = s
	c.snapMu.Unlock()
}

// SnapshotStatus is the last snapshot writer result, for example "skipped:
// locked" or "wrote <path>".
func (c *Controller) SnapshotStatus() string {
	c.snapMu.Lock()
	defer c.snapMu.Unlock()
	return c.snapStatus
}

// snapshotSoon asks the snapshot writer for one extra snapshot, coalesced with
// any other trigger in the same debounce window.
func (c *Controller) snapshotSoon() {
	select {
	case c.snapSoonC <- struct{}{}:
	default:
	}
}

// RestoreSnapshot decrypts file with pass, refuses a data dir that already has
// phylax.db unless force, unpacks the files and installs the database through
// store.Restore (which starts a new epoch).
func RestoreSnapshot(ctx context.Context, file string, pass []byte, dataDir, reason string, force bool) error {
	dbPath := filepath.Join(dataDir, "phylax.db")
	if !force {
		if _, err := os.Stat(dbPath); err == nil {
			return fmt.Errorf("controller: restore: %s already exists (use force to replace it)", dbPath)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	entries, err := readSnapshot(file, pass)
	if err != nil {
		return err
	}
	db, ok := entries["phylax.db"]
	if !ok {
		return errors.New("controller: snapshot has no phylax.db")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("controller: restore: %w", err)
	}
	for name, data := range entries {
		if name == "phylax.db" {
			continue
		}
		if err := atomicfile.WriteFile(filepath.Join(dataDir, name), data, 0o600); err != nil {
			return err
		}
	}
	tmp := dbPath + ".snapshot.tmp"
	if err := os.WriteFile(tmp, db, 0o600); err != nil {
		return fmt.Errorf("controller: restore: %w", err)
	}
	defer os.Remove(tmp)
	s, err := store.Restore(ctx, tmp, dbPath, reason)
	if err != nil {
		return err
	}
	return s.Close()
}

// readSnapshot decrypts and unpacks a snapshot, bounded to maxSnapshotBytes.
// Entry names must be base names: nothing may be written outside dataDir.
func readSnapshot(file string, pass []byte) (map[string][]byte, error) {
	if len(pass) == 0 {
		return nil, errors.New("controller: restore needs a passphrase")
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return nil, err
	} else if fi.Size() > maxSnapshotBytes {
		return nil, fmt.Errorf("controller: snapshot is larger than %d bytes", maxSnapshotBytes)
	}
	id, err := age.NewScryptIdentity(string(pass))
	if err != nil {
		return nil, err
	}
	id.SetMaxWorkFactor(22)
	r, err := age.Decrypt(io.LimitReader(f, maxSnapshotBytes), id)
	if err != nil {
		return nil, fmt.Errorf("controller: snapshot decrypt: %w", err)
	}
	entries := map[string][]byte{}
	var total int64
	tr := tar.NewReader(io.LimitReader(r, maxSnapshotBytes))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("controller: snapshot tar: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("controller: snapshot entry %q is not a regular file", h.Name)
		}
		if !safeSnapshotName(h.Name) {
			return nil, fmt.Errorf("controller: snapshot entry %q is not a base name", h.Name)
		}
		if _, dup := entries[h.Name]; dup {
			return nil, fmt.Errorf("controller: snapshot entry %q appears twice", h.Name)
		}
		if h.Size < 0 || total+h.Size > maxSnapshotBytes {
			return nil, fmt.Errorf("controller: snapshot is larger than %d bytes", maxSnapshotBytes)
		}
		b, err := io.ReadAll(io.LimitReader(tr, h.Size))
		if err != nil {
			return nil, err
		}
		if int64(len(b)) != h.Size {
			return nil, fmt.Errorf("controller: snapshot entry %q is short", h.Name)
		}
		entries[h.Name] = b
		total += int64(len(b))
	}
	return entries, nil
}

// safeSnapshotName reports whether name is a plain base name.
func safeSnapshotName(name string) bool {
	return name != "" && name != "." && name != ".." &&
		!strings.ContainsAny(name, `/\`) && !filepath.IsAbs(name)
}
