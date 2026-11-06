package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// WatchEnrollment starts the watch for the bundles in dir. It hashes the files
// named in served (the binaries the web root serves) and, until window has
// elapsed:
//   - a hello from a watched host whose BinarySHA256 is empty or matches none
//     of the served hashes raises an enroll.hash_mismatch alert (once per
//     host);
//   - the first accepted connection of a watched host removes dir/<host>.json
//     (the bundle token is consumed anyway);
//   - at the end of the window every watched host that never connected raises
//     enroll.no_show, and every remaining dir/<host>.json is removed
//     (bundles are served only during enrollment).
//
// enroll.refused already raises an alert in authorize for a refused token or
// an unknown host. A served path that cannot be read is an error: an empty
// served set would accept every hash silently.
//
// shortcut: the served set is hashed once at start, a binary replaced on disk
// afterwards is not re-hashed, upgrade when W12 serves from the bootstrap
// handler.
func (c *Controller) WatchEnrollment(dir string, hosts []string, served []string, window time.Duration) error {
	if len(served) == 0 {
		return errors.New("controller: enrollment watch needs at least one served binary")
	}
	if window <= 0 {
		return errors.New("controller: enrollment watch needs a positive window")
	}
	hashes := make([]string, 0, len(served))
	for _, p := range served {
		h, err := fileSHA256(p)
		if err != nil {
			return fmt.Errorf("controller: enrollment watch: %w", err)
		}
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)
	w := &enrollWatch{
		dir:     dir,
		hashes:  hashes,
		hosts:   sortedUnique(hosts),
		window:  window,
		started: c.now(),
		waiting: map[string]bool{},
		alerted: map[string]bool{},
	}
	for _, h := range w.hosts {
		w.waiting[h] = true
	}
	timer := c.opt.EnrollTimer
	if timer == nil {
		timer = func(d time.Duration, f func()) func() {
			t := time.AfterFunc(d, f)
			return func() { t.Stop() }
		}
	}
	w.stop = timer(window, func() { c.endEnrollment(w) })

	c.enrWatchMu.Lock()
	old := c.enrWatch
	c.enrWatch = w
	c.enrWatchMu.Unlock()
	if old != nil && old.stop != nil {
		old.stop() // a later watch replaces an earlier one
	}
	return nil
}

// enrollWatch is the state of one WatchEnrollment call.
type enrollWatch struct {
	dir     string
	hashes  []string // sha256 hex of the served binaries, sorted
	hosts   []string // watched hosts, sorted and deduplicated
	window  time.Duration
	started time.Time // when the watch began (the bundle-time fallback)
	stop    func()    // stops the window timer

	mu      sync.Mutex
	waiting map[string]bool // hosts that have not connected yet
	alerted map[string]bool // hosts that already raised a hash mismatch
	over    bool            // the window has ended; late hellos are ignored
}

func (w *enrollWatch) serves(hash string) bool {
	return slices.Contains(w.hashes, hash)
}

// enrollConnected is called by the hello handler once a host's hello is
// accepted. It checks the reported binary hash and, on the first connection,
// removes the host's served bundle.
func (c *Controller) enrollConnected(host, hash string) {
	c.enrWatchMu.Lock()
	w := c.enrWatch
	c.enrWatchMu.Unlock()
	if w == nil {
		return
	}
	var detail, served string
	first := false
	w.mu.Lock()
	if !w.over && slices.Contains(w.hosts, host) {
		if w.waiting[host] {
			delete(w.waiting, host)
			first = true
		}
		if !w.alerted[host] {
			served = strings.Join(w.hashes, " ")
			switch {
			case hash == "":
				detail = "no binary hash reported"
			case !w.serves(hash):
				detail = fmt.Sprintf("host %s reported binary sha256 %s, served %s", host, hash, served)
			}
			if detail != "" {
				w.alerted[host] = true
			}
		}
	}
	w.mu.Unlock()
	if detail != "" {
		c.alertTyped(host, detail, event.KindEnrollHashMismatch, event.EnrollHashMismatch{
			Host: host, Served: served, Reported: hash})
	}
	if first {
		c.removeBundle(w.dir, host)
	}
}

// endEnrollment closes the window: hosts that never connected are reported and
// every remaining bundle is withdrawn.
func (c *Controller) endEnrollment(w *enrollWatch) {
	w.mu.Lock()
	if w.over {
		w.mu.Unlock()
		return
	}
	w.over = true
	missed := make([]string, 0, len(w.waiting))
	for h := range w.waiting {
		missed = append(missed, h)
	}
	w.waiting = nil
	w.mu.Unlock()
	sort.Strings(missed)
	for _, h := range missed {
		c.alertTyped(h, "no connection within the enrollment window", event.KindEnrollNoShow,
			event.EnrollNoShow{Host: h, WindowSec: int(w.window / time.Second), Since: bundleSince(w.dir, h, w.started)})
	}
	for _, h := range w.hosts {
		c.removeBundle(w.dir, h)
	}
}

// bundleSince is when the host's bundle was written, for the enroll.no_show
// payload. A bundle already gone falls back to the start of the watch.
func bundleSince(dir, host string, fallback time.Time) string {
	if fi, err := os.Stat(filepath.Join(dir, host+".json")); err == nil {
		fallback = fi.ModTime()
	}
	return fallback.UTC().Format(time.RFC3339)
}

// removeBundle deletes one served bundle; a consumed or already removed bundle
// is not an error.
func (c *Controller) removeBundle(dir, host string) {
	if err := os.Remove(filepath.Join(dir, host+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		c.log.Error("cannot remove enrollment bundle", "host", host, "err", err)
	}
}

// fileSHA256 hashes a file without reading it into memory (the agent binary is
// tens of MB).
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sortedUnique(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
