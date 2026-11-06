package enroll

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
)

// revokedKeys is the persisted set of hosts whose current key may no longer
// act. The sorted JSON array is replaced atomically.
type revokedKeys struct {
	path string

	mu    sync.Mutex
	hosts map[string]bool
}

func openRevoked(path string) (*revokedKeys, error) {
	r := &revokedKeys{path: path, hosts: map[string]bool{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	var hosts []string
	if err := json.Unmarshal(b, &hosts); err != nil {
		return nil, fmt.Errorf("enroll: revoked file %s: %w", path, err)
	}
	for _, h := range hosts {
		r.hosts[h] = true
	}
	return r, nil
}

func (r *revokedKeys) has(host string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hosts[host]
}

func (r *revokedKeys) set(host string, on bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	was := r.hosts[host]
	if on {
		r.hosts[host] = true
	} else {
		delete(r.hosts, host)
	}
	if err := r.saveLocked(); err != nil {
		if was {
			r.hosts[host] = true
		} else {
			delete(r.hosts, host)
		}
		return err
	}
	return nil
}

func (r *revokedKeys) saveLocked() error {
	hosts := make([]string, 0, len(r.hosts))
	for h := range r.hosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	b, err := json.Marshal(hosts)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return err
	}
	return atomicfile.WriteFile(r.path, b, 0o600)
}
