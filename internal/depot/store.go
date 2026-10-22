package depot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
)

// MaxToolSize bounds any single tool binary.
const MaxToolSize = 256 << 20

// Store is a content-addressed directory: blobs/<sha256>. It is the controller
// cache tier for depot binaries and the source for deployment.
type Store struct{ Dir string }

func (s Store) blobPath(sum string) (string, error) {
	if b, err := hex.DecodeString(sum); err != nil || len(b) != sha256.Size {
		return "", fmt.Errorf("depot: bad sha256 %q", sum)
	}
	return filepath.Join(s.Dir, "blobs", sum), nil
}

// ManifestPath is where the signed manifest lives in the store.
func (s Store) ManifestPath() string { return filepath.Join(s.Dir, "depot.json") }

// Has reports whether the blob is present (not that it is intact; Open checks).
func (s Store) Has(sum string) bool {
	p, err := s.blobPath(sum)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// Put reads r (bounded by max, and by want.Size when known), checks the hash
// and stores it. A mismatch stores nothing.
func (s Store) Put(r io.Reader, wantSum string, max int64) (string, int64, error) {
	if max <= 0 || max > MaxToolSize {
		max = MaxToolSize
	}
	h := sha256.New()
	var n int64
	dst, err := s.blobPath(wantSum)
	if err != nil {
		return "", 0, err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", 0, err
	}
	errBad := errors.New("hash mismatch")
	err = atomicfile.Write(dst, 0o600, func(w io.Writer) error {
		var err error
		n, err = io.Copy(io.MultiWriter(w, h), io.LimitReader(r, max+1))
		if err != nil {
			return err
		}
		if n > max {
			return fmt.Errorf("blob exceeds %d bytes", max)
		}
		if hex.EncodeToString(h.Sum(nil)) != wantSum {
			return errBad
		}
		return nil
	})
	if errors.Is(err, errBad) {
		return "", 0, fmt.Errorf("depot: content hash mismatch (want %s)", wantSum)
	}
	if err != nil {
		return "", 0, err
	}
	return wantSum, n, nil
}

// PutFile hashes a local file and stores it under its own hash.
func (s Store) PutFile(path string) (sum string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, MaxToolSize+1)); err != nil {
		return "", 0, err
	}
	sum = hex.EncodeToString(h.Sum(nil))
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	return s.Put(f, sum, MaxToolSize)
}

// Open opens a blob and verifies it while reading it fully into memory is not
// needed: callers use ReadVerified for that. Open only returns the file.
func (s Store) Open(sum string) (*os.File, error) {
	p, err := s.blobPath(sum)
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}

// ReadVerified reads the blob and checks its hash, so a corrupted cache is
// never used.
func (s Store) ReadVerified(sum string) ([]byte, error) {
	f, err := s.Open(sum)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxToolSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > MaxToolSize {
		return nil, errors.New("depot: blob too large")
	}
	got := sha256.Sum256(b)
	if hex.EncodeToString(got[:]) != sum {
		return nil, fmt.Errorf("depot: cached blob %s is corrupt", sum)
	}
	return b, nil
}

// Fetcher retrieves a tool's bytes from the network. The only production
// implementation is used on the controller, through the cache path (logged,
// stored); agents never fetch. Tests use local fixtures.
type Fetcher interface {
	Fetch(ctx context.Context, e Entry) (io.ReadCloser, error)
}

// FetchMissing fetches every fetch-at-init entry (vendor downloads we may not
// redistribute) of the platform that is absent from the
// store and verifies it against the pinned hash. Failures are collected and
// do not stop the others (a failed fetch degrades one tool, not the depot).
func (s Store) FetchMissing(ctx context.Context, m *Manifest, f Fetcher, goos, goarch string) (fetched []string, errs []error) {
	for _, e := range m.For(goos, goarch) {
		if !e.FetchAtInit {
			if !s.Has(e.SHA256) {
				errs = append(errs, fmt.Errorf("%s: a release asset, missing from the store (copy it from the signed release)", e.Name))
			}
			continue
		}
		if e.SHA256 == "" {
			errs = append(errs, fmt.Errorf("%s: no pinned hash yet", e.Name))
			continue
		}
		if s.Has(e.SHA256) {
			continue
		}
		if e.URL == "" {
			errs = append(errs, fmt.Errorf("%s: not in the store and no URL", e.Name))
			continue
		}
		rc, err := f.Fetch(ctx, e)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Name, err))
			continue
		}
		max := e.Size
		if max <= 0 {
			max = MaxToolSize
		}
		_, n, err := s.Put(rc, e.SHA256, max)
		rc.Close()
		if err == nil && e.Size > 0 && n != e.Size {
			os.Remove(filepath.Join(s.Dir, "blobs", e.SHA256))
			err = fmt.Errorf("size %d, manifest says %d", n, e.Size)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Name, err))
			continue
		}
		fetched = append(fetched, e.Name)
	}
	return fetched, errs
}
